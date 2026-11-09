//go:build unix

package output

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/rifqifitriady/ZAAFVesper/pkg/event"
	"github.com/rifqifitriady/ZAAFVesper/pkg/rules"
)

// testPKI is a CA and a server certificate for 127.0.0.1 / localhost.
type testPKI struct {
	caFile string
	server tls.Certificate
}

func newPKI(t *testing.T) testPKI {
	t.Helper()
	caKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	caTmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test CA"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: true,
		KeyUsage: x509.KeyUsageCertSign, BasicConstraintsValid: true}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	ca, _ := x509.ParseCertificate(caDER)
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "localhost"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		DNSNames: []string{"localhost"}, IPAddresses: []net.IP{net.IPv4(127, 0, 0, 1)},
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, KeyUsage: x509.KeyUsageDigitalSignature}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca, &key.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	caFile := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(caFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER}), 0o600); err != nil {
		t.Fatal(err)
	}
	return testPKI{caFile: caFile, server: tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}}
}

func testAlert(output string) *rules.Alert {
	return &rules.Alert{RuleID: "rule-1", RuleName: "Test rule", Severity: "high", Output: output,
		Time:   time.Date(2026, 11, 9, 10, 0, 0, 0, time.UTC),
		Labels: map[string]string{"tactic.id": "TA0002", "technique.id": "T1059.004"},
		Events: []*event.Event{{Seq: 7, Time: time.Date(2026, 11, 9, 10, 0, 0, 0, time.UTC), Name: event.NetworkConnect,
			Source: "netpoll", Platform: event.PlatformMacOS,
			Proc: &event.Proc{PID: 42, PPID: 1, Exe: "/bin/bash", Name: "bash", Cmdline: "bash -i", Username: "rifqi",
				Env: map[string]string{"SECRET": "hunter2"}},
			Net: &event.Net{Proto: "tcp", Direction: "outbound", SrcIP: "10.0.0.5", SrcPort: 50000, DstIP: "203.0.113.9", DstPort: 4444}}}}
}

func TestEncoderSanitisesAndRedacts(t *testing.T) {
	r, err := Encoder{}.Alert(testAlert("evil ‮\u0007name\x1b[31m"))
	if err != nil {
		t.Fatal(err)
	}
	if !json.Valid(r.Body) {
		t.Fatalf("invalid JSON: %s", r.Body)
	}
	body := string(r.Body)
	if strings.ContainsRune(body, '‮') || strings.Contains(body, "hunter2") {
		t.Fatalf("not sanitised or not redacted: %s", body)
	}
	// A huge event is reduced to its identity, under the cap.
	big := &event.Event{Name: event.CreateProcess, Proc: &event.Proc{PID: 1, Exe: "/bin/x", Args: make([]string, 5000)}}
	for i := range big.Proc.Args {
		big.Proc.Args[i] = strings.Repeat("a", 100)
	}
	er, err := Encoder{MaxBytes: 4096}.Event(big)
	if err != nil {
		t.Fatal(err)
	}
	if len(er.Body) > 4096 || !strings.Contains(string(er.Body), `"truncated":true`) || !json.Valid(er.Body) {
		t.Fatalf("event not capped: %d bytes", len(er.Body))
	}
}

// syslogServer accepts one TLS connection and returns the octet-counted
// messages it reads.
func syslogServer(t *testing.T, cert tls.Certificate) (string, <-chan string) {
	t.Helper()
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{cert}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	msgs := make(chan string, 16)
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				br := bufio.NewReader(c)
				for {
					lenStr, err := br.ReadString(' ')
					if err != nil {
						return
					}
					n, err := strconv.Atoi(strings.TrimSpace(lenStr))
					if err != nil {
						return
					}
					buf := make([]byte, n)
					if _, err := io.ReadFull(br, buf); err != nil {
						return
					}
					msgs <- string(buf)
				}
			}(c)
		}
	}()
	return ln.Addr().String(), msgs
}

func TestSyslogTLSPinnedCA(t *testing.T) {
	pki := newPKI(t)
	addr, msgs := syslogServer(t, pki.server)
	conf, err := TLSConfig(pki.caFile, "", false, false)
	if err != nil {
		t.Fatal(err)
	}
	s, err := NewSyslog(SyslogConfig{Addr: addr, TLS: conf, Facility: 20, Host: "mac book\n", PID: 99})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	a := testAlert("x")
	a.RuleID = `id"with]and\`
	r, _ := Encoder{}.Alert(a)
	if err := s.Send(context.Background(), []Record{r}); err != nil {
		t.Fatal(err)
	}
	m := <-msgs
	want := `<163>1 2026-11-09T10:00:00.000000Z macbook zaafvesper 99 alert [zaafvesper@32473 kind="alert" rule_id="id\"with\]and\\" severity="high"] {`
	if !strings.HasPrefix(m, want) {
		t.Fatalf("message:\n%s\nwant prefix:\n%s", m, want)
	}
	if !json.Valid([]byte(m[strings.Index(m, "] {")+2:])) {
		t.Fatal("MSG is not JSON")
	}
	// Another CA: the handshake fails (the system roots are never used).
	other := newPKI(t)
	conf2, _ := TLSConfig(other.caFile, "", false, false)
	s2, _ := NewSyslog(SyslogConfig{Addr: addr, TLS: conf2, Facility: 20, Host: "h"})
	if err := s2.Send(context.Background(), []Record{r}); err == nil {
		t.Fatal("a server certificate from another CA was accepted")
	}
	if _, err := TLSConfig("", "", false, false); err == nil {
		t.Fatal("syslog without a CA file accepted")
	}
}

func TestWebhookAndHEC(t *testing.T) {
	var mu sync.Mutex
	var auth []string
	var bodies [][]byte
	status := http.StatusOK
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		mu.Lock()
		auth = append(auth, r.Header.Get("Authorization"))
		bodies = append(bodies, b)
		st := status
		mu.Unlock()
		if st == http.StatusFound {
			http.Redirect(w, r, "https://elsewhere.invalid/", st)
			return
		}
		w.WriteHeader(st)
	}))
	defer srv.Close()
	conf := &tls.Config{RootCAs: x509.NewCertPool(), MinVersion: tls.VersionTLS12}
	conf.RootCAs.AddCert(srv.Certificate())
	r1, _ := Encoder{}.Alert(testAlert("one"))
	r2, _ := Encoder{}.Alert(testAlert("two"))

	w, err := NewWebhook(WebhookConfig{URL: srv.URL + "/ingest?k=v", Token: "tok-123", TLS: conf, Host: "h1"})
	if err != nil {
		t.Fatal(err)
	}
	if err := w.Send(context.Background(), []Record{r1, r2}); err != nil {
		t.Fatal(err)
	}
	var arr []map[string]json.RawMessage
	if err := json.Unmarshal(bodies[0], &arr); err != nil || len(arr) != 2 || auth[0] != "Bearer tok-123" {
		t.Fatalf("json body %s err %v auth %q", bodies[0], err, auth[0])
	}
	h, err := NewWebhook(WebhookConfig{URL: srv.URL + "/services/collector/event", Format: FormatHEC, Token: "hec-tok", TLS: conf, Host: "h1"})
	if err != nil {
		t.Fatal(err)
	}
	if err := h.Send(context.Background(), []Record{r1, r2}); err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(string(bodies[1])), "\n")
	if len(lines) != 2 || auth[1] != "Splunk hec-tok" {
		t.Fatalf("hec body %q auth %q", bodies[1], auth[1])
	}
	for _, l := range lines {
		var ev struct {
			Time       float64         `json:"time"`
			Sourcetype string          `json:"sourcetype"`
			Event      json.RawMessage `json:"event"`
		}
		if err := json.Unmarshal([]byte(l), &ev); err != nil || ev.Sourcetype != "zaafvesper:alert" || ev.Time != 1794218400 {
			t.Fatalf("hec line %s: %v %+v", l, err, ev)
		}
	}
	// Failures report the status only, never the token; redirects are not followed.
	for _, st := range []int{http.StatusInternalServerError, http.StatusFound} {
		mu.Lock()
		status = st
		mu.Unlock()
		err := w.Send(context.Background(), []Record{r1})
		if err == nil || strings.Contains(err.Error(), "tok-123") || strings.Contains(err.Error(), "k=v") ||
			!strings.Contains(err.Error(), strconv.Itoa(st)) {
			t.Fatalf("status %d: err %v", st, err)
		}
	}
	for _, bad := range []string{"http://x/y", "https://user:pw@x/", "ftp://x"} {
		if _, err := NewWebhook(WebhookConfig{URL: bad, Token: "t", TLS: conf}); err == nil {
			t.Fatalf("%s accepted", bad)
		}
	}
	if !strings.Contains(w.String(), "/ingest") || strings.Contains(w.String(), "tok") || strings.Contains(w.String(), "k=v") {
		t.Fatalf("String() = %q", w.String())
	}
}

func TestReadToken(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "tok")
	if err := os.WriteFile(p, []byte("abc.DEF-123\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if tok, err := ReadToken(p, false); err != nil || tok != "abc.DEF-123" {
		t.Fatalf("%q %v", tok, err)
	}
	if err := os.Chmod(p, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadToken(p, false); err == nil || strings.Contains(err.Error(), "abc") {
		t.Fatalf("world-readable token accepted or leaked: %v", err)
	}
	_ = os.WriteFile(p, []byte("two words\r\nX-Injected: 1"), 0o600)
	_ = os.Chmod(p, 0o600)
	if _, err := ReadToken(p, false); err == nil || strings.Contains(err.Error(), "two") {
		t.Fatalf("bad token accepted or leaked: %v", err)
	}
	link := filepath.Join(dir, "link")
	_ = os.Symlink(p, link)
	if _, err := ReadToken(link, false); err == nil {
		t.Fatal("token through a symbolic link accepted")
	}
}

func rec(kind string, n int) Record {
	return Record{Kind: kind, Time: time.Unix(int64(n), 0).UTC(), Body: json.RawMessage(`{"n":` + strconv.Itoa(n) + `,"pad":"` + strings.Repeat("x", 200) + `"}`)}
}

func TestSpoolPolicyAndSafety(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "spool", "syslog")
	s, err := OpenSpool(dir, 8192, false)
	if err != nil {
		t.Fatal(err)
	}
	if fi, _ := os.Stat(dir); fi.Mode().Perm() != 0o700 {
		t.Fatalf("mode %o", fi.Mode().Perm())
	}
	// Events stop at half the cap, alerts at the cap.
	var events, alerts []Record
	for i := 0; i < 40; i++ {
		events = append(events, rec(KindEvent, i))
		alerts = append(alerts, rec(KindAlert, 1000+i))
	}
	refE, _ := s.Append(events)
	refA, _ := s.Append(alerts)
	st := s.Stats()
	if refE == 0 || refA == 0 || st["spool_bytes"] > 8192 || st["spool_bytes"] < 6000 {
		t.Fatalf("refused events %d alerts %d, stats %v", refE, refA, st)
	}
	// Read back oldest first, all records, then remove.
	total := 0
	for !s.Empty() {
		seq, recs, err := s.Oldest()
		if err != nil {
			t.Fatal(err)
		}
		total += len(recs)
		if err := s.Remove(seq); err != nil {
			t.Fatal(err)
		}
	}
	if total != 80-refE-refA {
		t.Fatalf("read back %d records, wrote %d", total, 80-refE-refA)
	}
	// Survives a restart; foreign files are ignored.
	_, _ = s.Append([]Record{rec(KindAlert, 1)})
	s.Close()
	_ = os.WriteFile(filepath.Join(dir, "notes.txt"), []byte("x"), 0o600)
	s2, err := OpenSpool(dir, 8192, false)
	if err != nil {
		t.Fatal(err)
	}
	if s2.Stats()["spool_files"] != 1 {
		t.Fatalf("files %v", s2.Stats())
	}
	// A spool file replaced by a symbolic link is not followed.
	seq := s2.files[0].seq
	name := filepath.Join(dir, s2.files[0].name())
	_ = os.Remove(name)
	_ = os.Symlink("/etc/hosts", name)
	if _, recs, err := s2.Oldest(); err == nil || len(recs) != 0 {
		t.Fatalf("followed a symbolic link: %v %d", err, len(recs))
	}
	_ = seq
	s2.Close()
	// A group/world-accessible spool directory is refused.
	_ = os.Chmod(dir, 0o755)
	if _, err := OpenSpool(dir, 8192, false); err == nil {
		t.Fatal("0755 spool accepted")
	}
}

// flaky is a transport that fails while down is set.
type flaky struct {
	mu   sync.Mutex
	down bool
	got  []string
}

func (f *flaky) Name() string { return "flaky" }
func (f *flaky) Close() error { return nil }
func (f *flaky) Send(_ context.Context, recs []Record) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.down {
		return errors.New("connection refused")
	}
	for _, r := range recs {
		f.got = append(f.got, string(r.Body))
	}
	return nil
}

func TestForwarderSpoolsWhileDownAndDrains(t *testing.T) {
	sp, err := OpenSpool(filepath.Join(t.TempDir(), "sp"), 1<<20, false)
	if err != nil {
		t.Fatal(err)
	}
	tr := &flaky{down: true}
	var mu sync.Mutex
	conds := map[string]int{}
	f := NewForwarder(ForwarderConfig{Transport: tr, Spool: sp, Events: true, FlushEvery: 20 * time.Millisecond,
		OnDegraded: func(c, d string) {
			if strings.Contains(d, "tok") {
				t.Error("token in detail")
			}
			mu.Lock()
			conds[c]++
			mu.Unlock()
		}})
	for i := 0; i < 5; i++ {
		_ = f.Send(testAlert("a" + strconv.Itoa(i)))
	}
	f.SendEvent(&event.Event{Name: event.CreateProcess, Proc: &event.Proc{PID: 5, Exe: "/bin/ls"}})
	deadline := time.Now().Add(3 * time.Second)
	for f.Stats()["spooled"] < 6 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if f.Stats()["spooled"] < 6 {
		t.Fatalf("not spooled: %v", f.Stats())
	}
	tr.mu.Lock()
	tr.down = false
	tr.mu.Unlock()
	deadline = time.Now().Add(5 * time.Second) // first backoff is 1 s
	for time.Now().Before(deadline) {
		tr.mu.Lock()
		n := len(tr.got)
		tr.mu.Unlock()
		if n >= 6 {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	tr.mu.Lock()
	got := append([]string(nil), tr.got...)
	tr.mu.Unlock()
	if len(got) != 6 || !strings.Contains(got[0], `"output":"a0"`) || !strings.Contains(got[4], `"output":"a4"`) {
		t.Fatalf("delivered %d: %v", len(got), got)
	}
	if !sp.Empty() {
		t.Fatal("spool not drained")
	}
	mu.Lock()
	if conds[CondDown] == 0 {
		t.Fatalf("down not reported: %v", conds)
	}
	mu.Unlock()
	if err := f.Close(time.Second); err != nil {
		t.Fatal(err)
	}
}

func TestForwarderQueueFull(t *testing.T) {
	tr := &blocking{release: make(chan struct{})}
	sp, _ := OpenSpool(filepath.Join(t.TempDir(), "sp"), 1<<20, false)
	f := NewForwarder(ForwarderConfig{Transport: tr, Spool: sp, Events: true, Queue: 4, Batch: 1, FlushEvery: time.Hour})
	_ = f.Send(testAlert("first")) // the loop blocks sending this one
	time.Sleep(50 * time.Millisecond)
	for i := 0; i < 20; i++ {
		f.SendEvent(&event.Event{Name: event.CreateProcess})
		_ = f.Send(testAlert("x"))
	}
	st := f.Stats()
	if st["queue_dropped_events"] == 0 || st["spooled"] == 0 {
		t.Fatalf("stats %v", st)
	}
	close(tr.release)
	_ = f.Close(2 * time.Second)
}

type blocking struct{ release chan struct{} }

func (b *blocking) Name() string { return "blocking" }
func (b *blocking) Close() error { return nil }
func (b *blocking) Send(ctx context.Context, _ []Record) error {
	select {
	case <-b.release:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// Output files are appended across restarts; links and loose modes are
// refused (security review finding 4).
func TestOpenAppendPrivate(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "events.ndjson")
	f, size, err := OpenAppendPrivate(p, false)
	if err != nil || size != 0 {
		t.Fatal(err, size)
	}
	_, _ = f.WriteString("one\n")
	f.Close()
	f, size, err = OpenAppendPrivate(p, false) // the restart case
	if err != nil || size != 4 {
		t.Fatalf("reopen: %v size %d", err, size)
	}
	_, _ = f.WriteString("two\n")
	f.Close()
	if b, _ := os.ReadFile(p); string(b) != "one\ntwo\n" {
		t.Fatalf("content %q", b)
	}
	link := filepath.Join(dir, "link")
	_ = os.Symlink(p, link)
	if _, _, err := OpenAppendPrivate(link, false); err == nil {
		t.Fatal("symbolic link accepted")
	}
	hard := filepath.Join(dir, "hard")
	_ = os.Link(p, hard)
	if _, _, err := OpenAppendPrivate(hard, false); err == nil {
		t.Fatal("hard link accepted")
	}
	loose := filepath.Join(dir, "loose")
	_ = os.WriteFile(loose, nil, 0o644)
	if _, _, err := OpenAppendPrivate(loose, false); err == nil {
		t.Fatal("0644 file accepted")
	}
}

// The forwarder queue is bounded in bytes as well as records (finding 5).
func TestForwarderQueueBytes(t *testing.T) {
	tr := &blocking{release: make(chan struct{})}
	f := NewForwarder(ForwarderConfig{Transport: tr, Events: true, Queue: 1000, QueueBytes: 4096, Batch: 1, FlushEvery: time.Hour})
	big := &event.Event{Name: event.CreateProcess, Proc: &event.Proc{PID: 1, Cmdline: strings.Repeat("a", 1500)}}
	for i := 0; i < 50; i++ {
		f.SendEvent(big)
	}
	if f.Stats()["queue_dropped_events"] < 40 || f.queuedBytes.Load() > 4096 {
		t.Fatalf("stats %v queued %d", f.Stats(), f.queuedBytes.Load())
	}
	close(tr.release)
	_ = f.Close(2 * time.Second)
}

// The syslog receiver on 127.0.0.1 goes away: alerts are spooled, and once
// a receiver listens on the same address again they are delivered from the
// spool over a new TLS connection.
func TestSyslogDownThenUpDeliversSpool(t *testing.T) {
	pki := newPKI(t)
	tlsConf := &tls.Config{Certificates: []tls.Certificate{pki.server}}
	ln, err := tls.Listen("tcp", "127.0.0.1:0", tlsConf)
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	msgs := make(chan string, 64)
	var connsMu sync.Mutex
	var conns []net.Conn
	serve := func(l net.Listener) {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			connsMu.Lock()
			conns = append(conns, c)
			connsMu.Unlock()
			go func(c net.Conn) {
				br := bufio.NewReader(c)
				for {
					l, err := br.ReadString(' ')
					if err != nil {
						return
					}
					n, _ := strconv.Atoi(strings.TrimSpace(l))
					buf := make([]byte, n)
					if _, err := io.ReadFull(br, buf); err != nil {
						return
					}
					msgs <- string(buf)
				}
			}(c)
		}
	}
	go serve(ln)
	conf, _ := TLSConfig(pki.caFile, "", false, false)
	tr, _ := NewSyslog(SyslogConfig{Addr: addr, TLS: conf, Facility: 20, Host: "h"})
	sp, _ := OpenSpool(filepath.Join(t.TempDir(), "sp"), 1<<20, false)
	f := NewForwarder(ForwarderConfig{Transport: tr, Spool: sp, FlushEvery: 20 * time.Millisecond})
	defer f.Close(time.Second)
	_ = f.Send(testAlert("before"))
	select {
	case <-msgs:
	case <-time.After(3 * time.Second):
		t.Fatal("first alert not delivered")
	}
	// The receiver goes away (listener and connection).
	ln.Close()
	connsMu.Lock()
	for _, c := range conns {
		c.Close()
	}
	connsMu.Unlock()
	time.Sleep(50 * time.Millisecond)
	_ = f.Send(testAlert("while-down-1"))
	_ = f.Send(testAlert("while-down-2"))
	deadline := time.Now().Add(3 * time.Second)
	for f.Stats()["spooled"] < 2 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if f.Stats()["spooled"] < 2 {
		t.Fatalf("not spooled while down: %v", f.Stats())
	}
	// Back up on the same address.
	ln2, err := tls.Listen("tcp", addr, tlsConf)
	if err != nil {
		t.Fatal(err)
	}
	defer ln2.Close()
	go serve(ln2)
	got := map[string]bool{}
	timeout := time.After(6 * time.Second) // backoff starts at 1 s
	for len(got) < 2 {
		select {
		case m := <-msgs:
			for _, w := range []string{"while-down-1", "while-down-2"} {
				if strings.Contains(m, `"output":"`+w+`"`) {
					got[w] = true
				}
			}
		case <-timeout:
			t.Fatalf("spooled alerts not delivered after the receiver came back: %v, stats %v", got, f.Stats())
		}
	}
	// The forwarder removes a spooled alert after the receiver has it, so
	// the spool empties a moment after the last message arrives.
	emptyBy := time.Now().Add(2 * time.Second)
	for !sp.Empty() && time.Now().Before(emptyBy) {
		time.Sleep(10 * time.Millisecond)
	}
	if !sp.Empty() {
		t.Fatal("spool not empty 2 s after delivery")
	}
}

func TestSpoolDirSymlinkRefused(t *testing.T) {
	dir := t.TempDir()
	real := filepath.Join(dir, "real")
	if err := os.Mkdir(real, 0o700); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link")
	_ = os.Symlink(real, link)
	if _, err := OpenSpool(link, 1<<20, false); err == nil {
		t.Fatal("a symbolic link as the spool directory was accepted")
	}
}

// A record still queued when the forwarder closes is delivered in a last
// bounded attempt while the endpoint is up, not left in the spool (found by
// the live-macos validation: an alert raised just before shutdown waited in
// the spool for the next start).
func TestForwarderFinalFlushOnClose(t *testing.T) {
	sp, _ := OpenSpool(filepath.Join(t.TempDir(), "sp"), 1<<20, false)
	tr := &flaky{}
	f := NewForwarder(ForwarderConfig{Transport: tr, Spool: sp, FlushEvery: time.Hour})
	_ = f.Send(testAlert("last words"))
	time.Sleep(20 * time.Millisecond) // the record is in the loop's batch or queue
	if err := f.Close(5 * time.Second); err != nil {
		t.Fatal(err)
	}
	tr.mu.Lock()
	n := len(tr.got)
	tr.mu.Unlock()
	if n != 1 || f.Stats()["spooled"] != 0 {
		t.Fatalf("delivered %d, stats %v", n, f.Stats())
	}
	// While the endpoint is down the record is spooled at Close instead.
	sp2, _ := OpenSpool(filepath.Join(t.TempDir(), "sp2"), 1<<20, false)
	down := &flaky{down: true}
	f2 := NewForwarder(ForwarderConfig{Transport: down, Spool: sp2, FlushEvery: 20 * time.Millisecond})
	_ = f2.Send(testAlert("one"))
	deadline := time.Now().Add(3 * time.Second)
	for f2.Stats()["failed_batches"] == 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	_ = f2.Send(testAlert("two"))
	start := time.Now()
	_ = f2.Close(5 * time.Second)
	if f2.Stats()["spooled"] != 2 || time.Since(start) > 2*time.Second {
		t.Fatalf("down at close: stats %v after %v", f2.Stats(), time.Since(start))
	}
}

// An endpoint that accepts the request and never answers cannot hold up
// Close: the final flush is bounded (finalFlushTimeout) and the record is
// spooled for the next start (security review note on v0.3 C).
func TestFinalFlushBoundedByHangingEndpoint(t *testing.T) {
	release := make(chan struct{})
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-release:
		case <-r.Context().Done():
		}
	}))
	defer srv.Close()
	defer close(release)
	conf := &tls.Config{RootCAs: x509.NewCertPool(), MinVersion: tls.VersionTLS12}
	conf.RootCAs.AddCert(srv.Certificate())
	w, err := NewWebhook(WebhookConfig{URL: srv.URL + "/hook", Token: "t", TLS: conf, Host: "h"})
	if err != nil {
		t.Fatal(err)
	}
	sp, _ := OpenSpool(filepath.Join(t.TempDir(), "sp"), 1<<20, false)
	f := NewForwarder(ForwarderConfig{Transport: w, Spool: sp, FlushEvery: time.Hour})
	_ = f.Send(testAlert("hanging"))
	time.Sleep(20 * time.Millisecond)
	start := time.Now()
	_ = f.Close(5 * time.Second)
	if el := time.Since(start); el > finalFlushTimeout+time.Second {
		t.Fatalf("Close took %v with a hanging endpoint", el)
	}
	if st := f.Stats(); st["spooled"] != 1 || st["sent"] != 0 {
		t.Fatalf("stats %v", st)
	}
}

// A Close timeout shorter than finalFlushTimeout shortens the final flush
// too, so Close never returns while a Send still runs on the transport.
func TestFinalFlushFollowsCloseTimeout(t *testing.T) {
	tr := &blocking{release: make(chan struct{})}
	defer close(tr.release)
	sp, _ := OpenSpool(filepath.Join(t.TempDir(), "sp"), 1<<20, false)
	f := NewForwarder(ForwarderConfig{Transport: tr, Spool: sp, FlushEvery: time.Hour})
	_ = f.Send(testAlert("short close"))
	time.Sleep(20 * time.Millisecond)
	start := time.Now()
	if err := f.Close(1500 * time.Millisecond); err != nil {
		t.Fatalf("Close: %v (the loop must finish within the timeout)", err)
	}
	if el := time.Since(start); el > 1500*time.Millisecond {
		t.Fatalf("Close took %v", el)
	}
	if f.Stats()["spooled"] != 1 {
		t.Fatalf("stats %v", f.Stats())
	}
}
