package output

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/rifqifitriady/ZAAFVesper/pkg/config"
)

// Transport delivers one batch of records. Send must be all-or-nothing from
// the caller's point of view: on error the whole batch is spooled again
// (delivery is at least once).
type Transport interface {
	Name() string
	Send(ctx context.Context, recs []Record) error
	Close() error
}

// Limits of files read for outputs.
const (
	maxCAFileBytes    = 1 << 20
	maxTokenFileBytes = 4096
	sendTimeout       = 15 * time.Second
	maxResponseBytes  = 4096
)

// TLSConfig builds a client TLS configuration that trusts only the CA
// certificates in caFile (pinning: the system roots are not used), or the
// system roots when caFile is empty and allowSystem is true. The file is read
// with config.SecureRead (as root: root-owned, not group/world writable, no
// symbolic link); as root the file and every directory above it must also
// pass config.CheckOwnership, so nobody else can swap the entry (for
// example for a hard link to the system's CA bundle).
func TLSConfig(caFile, serverName string, allowSystem, asRoot bool) (*tls.Config, error) {
	c := &tls.Config{MinVersion: tls.VersionTLS12, ServerName: serverName}
	if caFile == "" {
		if !allowSystem {
			return nil, errors.New("a CA file is required (the system roots are not trusted for this output)")
		}
		return c, nil
	}
	if asRoot {
		if err := config.CheckOwnership(caFile); err != nil {
			return nil, fmt.Errorf("CA file %s is not safe to read as root:\n%w", caFile, err)
		}
	}
	pem, err := config.SecureRead(caFile, maxCAFileBytes)
	if err != nil {
		return nil, fmt.Errorf("CA file: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pem) {
		return nil, fmt.Errorf("CA file %s: no PEM certificate found", caFile)
	}
	c.RootCAs = pool
	return c, nil
}

// ReadToken reads a bearer or HEC token from a file with config.SecureRead.
// As root the file and every directory above it must pass
// config.CheckOwnership first, so the entry cannot change between the read
// and the mode check below. The file must be readable by its owner only
// (mode 0600 or 0400): a token readable by others is refused. The token must
// be printable ASCII without spaces. Errors never contain the token.
func ReadToken(path string, asRoot bool) (string, error) {
	if asRoot {
		if err := config.CheckOwnership(path); err != nil {
			return "", fmt.Errorf("token file %s is not safe to read as root:\n%w", path, err)
		}
	}
	data, err := config.SecureRead(path, maxTokenFileBytes)
	if err != nil {
		return "", fmt.Errorf("token file: %w", err)
	}
	fi, err := os.Lstat(path)
	if err != nil {
		return "", fmt.Errorf("token file: %w", err)
	}
	if fi.Mode().Perm()&0o077 != 0 {
		return "", fmt.Errorf("token file %s: mode %o lets other users read it; use chmod 600", path, fi.Mode().Perm())
	}
	tok := strings.TrimSpace(string(data))
	if tok == "" {
		return "", fmt.Errorf("token file %s is empty", path)
	}
	for i := 0; i < len(tok); i++ {
		if tok[i] <= ' ' || tok[i] >= 0x7f {
			return "", fmt.Errorf("token file %s: the token must be printable ASCII without spaces (one line)", path)
		}
	}
	return tok, nil
}

// ---- syslog RFC 5424 over TLS (RFC 5425) ----

// Syslog facilities by name.
var facilities = map[string]int{"kern": 0, "user": 1, "daemon": 3, "auth": 4, "authpriv": 10,
	"local0": 16, "local1": 17, "local2": 18, "local3": 19, "local4": 20, "local5": 21, "local6": 22, "local7": 23}

// Facility parses a facility name.
func Facility(name string) (int, error) {
	f, ok := facilities[name]
	if !ok {
		return 0, fmt.Errorf("unknown syslog facility %q (use kern, user, daemon, auth, authpriv or local0-local7)", name)
	}
	return f, nil
}

// sdID is the structured-data element ID. 32473 is the example enterprise
// number of RFC 5612 (ZAAFVesper has no registered one).
const sdID = "zaafvesper@32473"

// SyslogConfig configures the syslog transport.
type SyslogConfig struct {
	Addr     string // host:port
	TLS      *tls.Config
	Facility int
	Host     string // HOSTNAME field (Host() applied)
	PID      int
}

// Syslog sends one RFC 5424 message per record over one TLS connection,
// framed by octet counting (RFC 5425 / RFC 6587). The connection is
// re-established after any error.
type Syslog struct {
	cfg  SyslogConfig
	mu   sync.Mutex
	conn net.Conn
}

// NewSyslog returns the transport; it connects on the first Send.
func NewSyslog(cfg SyslogConfig) (*Syslog, error) {
	if _, _, err := net.SplitHostPort(cfg.Addr); err != nil {
		return nil, fmt.Errorf("syslog address %q: %w", cfg.Addr, err)
	}
	if cfg.TLS == nil {
		return nil, errors.New("syslog: TLS is required")
	}
	cfg.Host = Host(cfg.Host)
	return &Syslog{cfg: cfg}, nil
}

func (s *Syslog) Name() string { return "syslog" }

// Send writes the batch; any error closes the connection.
func (s *Syslog) Send(ctx context.Context, recs []Record) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.conn != nil && !alive(s.conn) {
		_ = s.conn.Close()
		s.conn = nil
	}
	if s.conn == nil {
		c, err := s.dial(ctx)
		if err != nil {
			return err
		}
		s.conn = c
	}
	var buf bytes.Buffer
	for i := range recs {
		msg := s.format(&recs[i])
		buf.WriteString(strconv.Itoa(len(msg)))
		buf.WriteByte(' ')
		buf.Write(msg)
	}
	_ = s.conn.SetWriteDeadline(time.Now().Add(sendTimeout))
	if _, err := s.conn.Write(buf.Bytes()); err != nil {
		_ = s.conn.Close()
		s.conn = nil
		return fmt.Errorf("syslog %s: %w", s.cfg.Addr, err)
	}
	return nil
}

// alive probes an idle syslog connection before a batch is written. The
// receiver never sends anything, so a 1 ms read that ends in EOF or an error
// other than the timeout means it closed or reset the connection; writing
// would then be accepted by the local kernel and lost. Syslog over TCP has no
// acknowledgement, so a receiver that goes away during the write can still
// lose that batch.
func alive(c net.Conn) bool {
	_ = c.SetReadDeadline(time.Now().Add(time.Millisecond))
	var b [1]byte
	_, err := c.Read(b[:])
	_ = c.SetReadDeadline(time.Time{})
	var ne net.Error
	return err != nil && errors.As(err, &ne) && ne.Timeout()
}

func (s *Syslog) dial(ctx context.Context) (net.Conn, error) {
	ctx, cancel := context.WithTimeout(ctx, sendTimeout)
	defer cancel()
	d := &tls.Dialer{NetDialer: &net.Dialer{}, Config: s.serverConfig()}
	c, err := d.DialContext(ctx, "tcp", s.cfg.Addr)
	if err != nil {
		return nil, fmt.Errorf("syslog %s: %w", s.cfg.Addr, err)
	}
	return c, nil
}

// serverConfig fills ServerName from the address when it is not set.
func (s *Syslog) serverConfig() *tls.Config {
	c := s.cfg.TLS.Clone()
	if c.ServerName == "" {
		host, _, _ := net.SplitHostPort(s.cfg.Addr)
		c.ServerName = host
	}
	return c
}

// severities maps rule severity to syslog severity.
var severities = map[string]int{"critical": 2, "high": 3, "medium": 4, "low": 5, "info": 6}

// format builds one RFC 5424 message: header, one SD element with the
// record's kind, rule id and severity (escaped per RFC 5424 6.3.3), and the
// record body (sanitised JSON) as MSG.
func (s *Syslog) format(r *Record) []byte {
	sev, ok := severities[r.Severity]
	if !ok {
		sev = 6
	}
	msgid := "event"
	if r.Kind == KindAlert {
		msgid = "alert"
	}
	var b bytes.Buffer
	fmt.Fprintf(&b, "<%d>1 %s %s zaafvesper %d %s [%s kind=\"%s\"", s.cfg.Facility*8+sev,
		r.Time.UTC().Format("2006-01-02T15:04:05.000000Z"), s.cfg.Host, s.cfg.PID, msgid, sdID, r.Kind)
	if r.RuleID != "" {
		fmt.Fprintf(&b, " rule_id=\"%s\"", sdEscape(r.RuleID))
	}
	if r.Severity != "" {
		fmt.Fprintf(&b, " severity=\"%s\"", sdEscape(r.Severity))
	}
	b.WriteString("] ")
	b.Write(r.Body)
	return b.Bytes()
}

// sdEscape escapes '"', '\' and ']' in an SD-PARAM value.
func sdEscape(v string) string {
	r := strings.NewReplacer(`\`, `\\`, `"`, `\"`, `]`, `\]`)
	return r.Replace(v)
}

// Close closes the connection.
func (s *Syslog) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.conn == nil {
		return nil
	}
	err := s.conn.Close()
	s.conn = nil
	return err
}

// ---- HTTPS webhook and Splunk HEC ----

// Webhook formats.
const (
	FormatJSON = "json" // JSON array of {type, host, time, data}
	FormatHEC  = "hec"  // Splunk HTTP Event Collector
)

// WebhookConfig configures the webhook transport.
type WebhookConfig struct {
	URL    string
	Format string // FormatJSON or FormatHEC
	Token  string // bearer (json) or HEC token; never logged
	TLS    *tls.Config
	Host   string
	// UserAgent is sent as User-Agent.
	UserAgent string
	// Transport overrides the HTTP round tripper (tests).
	Transport http.RoundTripper
}

// Webhook POSTs batches over HTTPS. Redirects are not followed (the token
// must not travel to another host), environment proxies are not used, and
// only the status code of a failure is reported.
type Webhook struct {
	cfg    WebhookConfig
	client *http.Client
	where  string // scheme://host/path for messages (no query, no userinfo)
}

// ValidateURL accepts only https URLs without user information.
func ValidateURL(raw string) (*url.URL, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return nil, errors.New("webhook URL does not parse")
	}
	switch {
	case u.Scheme != "https":
		return nil, errors.New("webhook URL must use https")
	case u.User != nil:
		return nil, errors.New("webhook URL must not carry user information; use --webhook-token-file")
	case u.Host == "":
		return nil, errors.New("webhook URL has no host")
	}
	return u, nil
}

// NewWebhook returns the transport.
func NewWebhook(cfg WebhookConfig) (*Webhook, error) {
	u, err := ValidateURL(cfg.URL)
	if err != nil {
		return nil, err
	}
	if cfg.Format == "" {
		cfg.Format = FormatJSON
	}
	if cfg.Format != FormatJSON && cfg.Format != FormatHEC {
		return nil, fmt.Errorf("webhook format %q: use json or hec", cfg.Format)
	}
	if cfg.Token == "" {
		return nil, errors.New("webhook: a token is required")
	}
	if cfg.TLS == nil {
		return nil, errors.New("webhook: TLS configuration missing")
	}
	cfg.Host = Host(cfg.Host)
	rt := cfg.Transport
	if rt == nil {
		rt = &http.Transport{
			Proxy:                 nil,
			TLSClientConfig:       cfg.TLS.Clone(),
			ForceAttemptHTTP2:     true,
			MaxIdleConns:          2,
			IdleConnTimeout:       90 * time.Second,
			TLSHandshakeTimeout:   10 * time.Second,
			ResponseHeaderTimeout: sendTimeout,
			DialContext:           (&net.Dialer{Timeout: 10 * time.Second}).DialContext,
		}
	}
	client := &http.Client{Transport: rt, Timeout: sendTimeout,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	return &Webhook{cfg: cfg, client: client, where: u.Scheme + "://" + u.Host + u.EscapedPath()}, nil
}

func (w *Webhook) Name() string {
	if w.cfg.Format == FormatHEC {
		return "hec"
	}
	return "webhook"
}

// String never prints the token.
func (w *Webhook) String() string { return w.Name() + " " + w.where }

// Body builds the request body of a batch.
func (w *Webhook) Body(recs []Record) []byte {
	var b bytes.Buffer
	if w.cfg.Format == FormatHEC {
		for i := range recs {
			r := &recs[i]
			fmt.Fprintf(&b, `{"time":%s,"host":%q,"source":"zaafvesper","sourcetype":"zaafvesper:%s","event":`,
				strconv.FormatFloat(float64(r.Time.UnixMilli())/1000, 'f', 3, 64), w.cfg.Host, r.Kind)
			b.Write(r.Body)
			b.WriteString("}\n")
		}
		return b.Bytes()
	}
	b.WriteByte('[')
	for i := range recs {
		r := &recs[i]
		if i > 0 {
			b.WriteByte(',')
		}
		fmt.Fprintf(&b, `{"type":%q,"host":%q,"time":%q,"data":`, r.Kind, w.cfg.Host, r.Time.UTC().Format(time.RFC3339Nano))
		b.Write(r.Body)
		b.WriteByte('}')
	}
	b.WriteByte(']')
	return b.Bytes()
}

// Send POSTs the batch; a non-2xx status is an error (reported by code).
func (w *Webhook) Send(ctx context.Context, recs []Record) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, w.cfg.URL, bytes.NewReader(w.Body(recs)))
	if err != nil {
		return fmt.Errorf("%s: building the request failed", w.where)
	}
	req.Header.Set("Content-Type", "application/json")
	if w.cfg.UserAgent != "" {
		req.Header.Set("User-Agent", w.cfg.UserAgent)
	}
	if w.cfg.Format == FormatHEC {
		req.Header.Set("Authorization", "Splunk "+w.cfg.Token)
	} else {
		req.Header.Set("Authorization", "Bearer "+w.cfg.Token)
	}
	resp, err := w.client.Do(req)
	if err != nil {
		// url.Error carries the URL (with its query); report the safe part.
		var ue *url.Error
		if errors.As(err, &ue) {
			err = ue.Err
		}
		return fmt.Errorf("%s: %v", w.where, err)
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, maxResponseBytes))
	_ = resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return fmt.Errorf("%s: HTTP status %d", w.where, resp.StatusCode)
	}
	return nil
}

// Close releases idle connections.
func (w *Webhook) Close() error {
	w.client.CloseIdleConnections()
	return nil
}
