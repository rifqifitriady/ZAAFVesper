package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"time"

	"github.com/rifqifitriady/ZAAFVesper/pkg/alert"
	"github.com/rifqifitriady/ZAAFVesper/pkg/event"
	"github.com/rifqifitriady/ZAAFVesper/pkg/output"
	"github.com/rifqifitriady/ZAAFVesper/pkg/ps"
	"github.com/rifqifitriady/ZAAFVesper/pkg/rules"
	"github.com/rifqifitriady/ZAAFVesper/pkg/source/netpoll"
)

// Wiring of workstream W2: socket polling (netpoll), SIEM outputs (syslog
// over TLS, HTTPS webhook, Splunk HEC) with their disk spool, and the
// ZAAFElegia outputs (Sigma NDJSON events, OCSF alerts).

// Defaults of the W2 outputs.
const (
	defaultSpoolDir        = "/var/db/zaafvesper/spool"
	defaultElegiaMaxBytes  = 1 << 30
	syslogMaxRecordBytes   = 8 << 10 // RFC 5425 receivers commonly accept 8 KiB
	webhookMaxRecordBytes  = alert.DefaultMaxAlertBytes
	outputCloseTimeout     = 5 * time.Second
	condElegiaDropped      = "elegia_out_dropped"
	condElegiaCapped       = "elegia_out_capped"
	condOCSFCapped         = "alerts_ocsf_capped"
	defaultSyslogFacility  = "local4"
	defaultWebhookFormat   = output.FormatJSON
	netpollChannelCapacity = 1024
)

// netOutOptions are the W2 flags of run.
type netOutOptions struct {
	noNet       bool
	netInterval time.Duration
	netLoopback bool

	syslogAddr, syslogCA, syslogServerName, syslogFacility string
	webhookURL, webhookTokenFile, webhookCA, webhookFormat string
	siemEvents                                             bool
	spoolDir                                               string
	spoolMaxBytes                                          int64

	elegiaOut      string
	elegiaMaxBytes int64
	alertsOCSF     string
	ocsfMaxBytes   int64
}

func (n *netOutOptions) register(fs *flag.FlagSet) {
	fs.BoolVar(&n.noNet, "no-net", false, "do not poll sockets for network events")
	fs.DurationVar(&n.netInterval, "net-interval", netpoll.DefaultInterval, "socket polling interval (minimum 100ms); connections shorter than this can be missed")
	fs.BoolVar(&n.netLoopback, "net-loopback", false, "also report loopback connections and listeners")
	fs.StringVar(&n.syslogAddr, "syslog", "", "send alerts to this syslog receiver (host:port) as RFC 5424 over TLS")
	fs.StringVar(&n.syslogCA, "syslog-ca", "", "PEM CA bundle the syslog server certificate must chain to (only these CAs are trusted; required with --syslog)")
	fs.StringVar(&n.syslogServerName, "syslog-server-name", "", "TLS server name to verify (default: the host of --syslog)")
	fs.StringVar(&n.syslogFacility, "syslog-facility", defaultSyslogFacility, "syslog facility (kern, user, daemon, auth, authpriv, local0-local7)")
	fs.StringVar(&n.webhookURL, "webhook", "", "POST alerts as JSON batches to this https URL")
	fs.StringVar(&n.webhookTokenFile, "webhook-token-file", "", "file holding the webhook bearer (or HEC) token; root-owned, mode 0600 (required with --webhook)")
	fs.StringVar(&n.webhookCA, "webhook-ca", "", "PEM CA bundle for the webhook server (default: the system roots)")
	fs.StringVar(&n.webhookFormat, "webhook-format", defaultWebhookFormat, "json (array of records) or hec (Splunk HTTP Event Collector)")
	fs.BoolVar(&n.siemEvents, "siem-events", false, "also send every event to the SIEM outputs (alerts are always sent)")
	fs.StringVar(&n.spoolDir, "spool-dir", defaultSpoolDir, "directory (0700, root-owned) holding SIEM records while an endpoint is down")
	fs.Int64Var(&n.spoolMaxBytes, "spool-max-bytes", output.DefaultSpoolMaxBytes, "cap of each SIEM output's spool in bytes (events stop at half)")
	fs.StringVar(&n.elegiaOut, "elegia-out", "", "stream every event as NDJSON with Sigma field names to this file (0600, appended across restarts), or - for stdout (console alerts then go to stderr)")
	fs.Int64Var(&n.elegiaMaxBytes, "elegia-max-bytes", defaultElegiaMaxBytes, "cap of the --elegia-out file in bytes (not applied to stdout)")
	fs.StringVar(&n.alertsOCSF, "alerts-ocsf", "", "write alerts as OCSF Detection Findings (class 2004) to this NDJSON file (0600, appended across restarts)")
	fs.Int64Var(&n.ocsfMaxBytes, "ocsf-max-bytes", alert.DefaultMaxFileBytes, "cap of the --alerts-ocsf file in bytes")
}

// check rejects incomplete or contradictory W2 flags.
func (n *netOutOptions) check() error {
	switch {
	case n.netInterval < netpoll.MinInterval:
		return fmt.Errorf("--net-interval must be at least %v", netpoll.MinInterval)
	case n.syslogAddr != "" && n.syslogCA == "":
		return errors.New("--syslog needs --syslog-ca (the receiver's certificate must chain to a CA you name)")
	case n.syslogAddr == "" && (n.syslogCA != "" || n.syslogServerName != ""):
		return errors.New("--syslog-ca and --syslog-server-name need --syslog")
	case n.webhookURL != "" && n.webhookTokenFile == "":
		return errors.New("--webhook needs --webhook-token-file")
	case n.webhookURL == "" && (n.webhookTokenFile != "" || n.webhookCA != ""):
		return errors.New("--webhook-token-file and --webhook-ca need --webhook")
	case n.webhookFormat != output.FormatJSON && n.webhookFormat != output.FormatHEC:
		return fmt.Errorf("--webhook-format %q: use json or hec", n.webhookFormat)
	case n.siemEvents && n.syslogAddr == "" && n.webhookURL == "":
		return errors.New("--siem-events needs --syslog or --webhook")
	case n.spoolMaxBytes <= 0 || n.elegiaMaxBytes <= 0 || n.ocsfMaxBytes <= 0:
		return errors.New("--spool-max-bytes, --elegia-max-bytes and --ocsf-max-bytes must be positive")
	case n.alertsOCSF == "-":
		return errors.New("--alerts-ocsf takes a file path")
	case n.alertsOCSF != "" && n.elegiaOut != "" && filepath.Clean(n.alertsOCSF) == filepath.Clean(n.elegiaOut):
		return errors.New("--alerts-ocsf and --elegia-out must be different files")
	}
	if n.webhookURL != "" {
		if _, err := output.ValidateURL(n.webhookURL); err != nil {
			return fmt.Errorf("--webhook: %w", err)
		}
	}
	if n.syslogAddr != "" {
		if _, err := output.Facility(n.syslogFacility); err != nil {
			return fmt.Errorf("--syslog-facility: %w", err)
		}
	}
	return nil
}

// consoleWriter is where console alerts go: stderr when --elegia-out - owns
// stdout.
func (n *netOutOptions) consoleWriter(stdout, stderr io.Writer) io.Writer {
	if n.elegiaOut == "-" {
		return stderr
	}
	return stdout
}

// handleNetwork runs a netpoll event through the pipeline WITHOUT the
// process table's Enricher (security note N7: only eslogger writes the
// table; netpoll filled the event's process read-only itself).
func (p *pipeline) handleNetwork(e *event.Event) { p.handle(e, true) }

// wantsNetwork reports whether any enabled rule can match a network event
// (nil: a rule not limited by evt.name).
func wantsNetwork(required []string) bool {
	if required == nil {
		return true
	}
	for _, n := range required {
		if n == event.NetworkConnect || n == event.NetworkAccept {
			return true
		}
	}
	return false
}

// wireNetOut builds the W2 components into s: SIEM forwarders (alert sinks,
// plus event taps with --siem-events), the ZAAFElegia writers and netpoll.
func (s *sensor) wireNetOut(o runOptions, engine *rules.Engine, snap *ps.Snapshotter, stdout, stderr io.Writer) error {
	n := &o.netout
	p := s.p
	if s.extra == nil {
		s.extra = map[string]func() map[string]uint64{}
	}
	logf := func(format string, args ...any) { say(stderr, "output: %s", fmt.Sprintf(format, args...)) }
	host, _ := os.Hostname()

	addForwarder := func(name string, tr output.Transport, maxRecord int) error {
		sp, err := output.OpenSpool(filepath.Join(n.spoolDir, name), n.spoolMaxBytes, o.asRoot)
		if err != nil {
			_ = tr.Close()
			return err
		}
		f := output.NewForwarder(output.ForwarderConfig{
			Transport: tr, Spool: sp, Events: n.siemEvents,
			Encoder:    output.Encoder{KeepEnv: o.keepEnv, MaxBytes: maxRecord},
			OnDegraded: p.degraded, Log: logf,
		})
		p.sinks = append(p.sinks, f)
		if n.siemEvents {
			p.taps = append(p.taps, f.SendEvent)
		}
		s.closers = append(s.closers, func() error { return f.Close(outputCloseTimeout) })
		s.extra["output "+name] = f.Stats
		what := "alerts"
		if n.siemEvents {
			what = "alerts and events"
		}
		say(stderr, "output: %s to %s (spool %s, cap %d bytes)", what, tr.Name(), filepath.Join(n.spoolDir, name), n.spoolMaxBytes)
		return nil
	}

	if n.syslogAddr != "" {
		tc, err := output.TLSConfig(n.syslogCA, n.syslogServerName, false, o.asRoot)
		if err != nil {
			return fmt.Errorf("--syslog-ca: %w", err)
		}
		fac, _ := output.Facility(n.syslogFacility)
		tr, err := output.NewSyslog(output.SyslogConfig{Addr: n.syslogAddr, TLS: tc, Facility: fac, Host: host, PID: os.Getpid()})
		if err != nil {
			return err
		}
		if err := addForwarder("syslog", tr, syslogMaxRecordBytes); err != nil {
			return err
		}
	}
	if n.webhookURL != "" {
		tok, err := output.ReadToken(n.webhookTokenFile, o.asRoot)
		if err != nil {
			return fmt.Errorf("--webhook-token-file: %w", err)
		}
		tc, err := output.TLSConfig(n.webhookCA, "", true, o.asRoot)
		if err != nil {
			return fmt.Errorf("--webhook-ca: %w", err)
		}
		tr, err := output.NewWebhook(output.WebhookConfig{URL: n.webhookURL, Format: n.webhookFormat, Token: tok, TLS: tc,
			Host: host, UserAgent: "zaafvesper/" + version})
		if err != nil {
			return err
		}
		if err := addForwarder(tr.Name(), tr, webhookMaxRecordBytes); err != nil {
			return err
		}
	}

	if n.elegiaOut != "" {
		var w io.Writer = stdout
		maxBytes, written := int64(0), int64(0)
		where := "stdout"
		if n.elegiaOut != "-" {
			// Appended across restarts (a LaunchDaemon restart must not
			// fail because the file exists); the cap covers the whole file.
			f, size, err := output.OpenAppendPrivate(n.elegiaOut, o.asRoot)
			if err != nil {
				return fmt.Errorf("--elegia-out: %w", err)
			}
			w, maxBytes, written, where = f, n.elegiaMaxBytes, size, f.Name()
		}
		lw := output.NewLineWriter(w, output.LineWriterConfig{Name: "elegia-out", MaxBytes: maxBytes, Written: written,
			OnDrop:   func(d string) { p.degraded(condElegiaDropped, d) },
			OnCapped: func(d string) { p.degraded(condElegiaCapped, d) }})
		es := &output.ElegiaSink{W: lw, DefaultProduct: hostPlatform()}
		p.taps = append(p.taps, es.Event)
		s.closers = append(s.closers, func() error { return lw.Close(outputCloseTimeout) })
		s.extra["elegia out"] = lw.Stats
		say(stderr, "output: every event as Sigma-named NDJSON to %s", where)
	}
	if n.alertsOCSF != "" {
		f, size, err := output.OpenAppendPrivate(n.alertsOCSF, o.asRoot)
		if err != nil {
			return fmt.Errorf("--alerts-ocsf: %w", err)
		}
		lw := output.NewLineWriter(f, output.LineWriterConfig{Name: "alerts-ocsf", MaxBytes: n.ocsfMaxBytes, Written: size,
			OnDrop:   func(d string) { p.degraded(condOCSFCapped, d) },
			OnCapped: func(d string) { p.degraded(condOCSFCapped, d) }})
		p.sinks = append(p.sinks, &output.OCSFSink{W: lw, Version: version, DefaultProduct: hostPlatform()})
		s.closers = append(s.closers, func() error { return lw.Close(outputCloseTimeout) })
		s.extra["alerts ocsf"] = lw.Stats
		say(stderr, "output: alerts as OCSF Detection Findings to %s (cap %d bytes)", f.Name(), n.ocsfMaxBytes)
	}

	exporting := n.elegiaOut != "" || n.siemEvents
	switch {
	case n.noNet:
		say(stderr, "network: socket polling disabled by --no-net")
	case runtime.GOOS != "darwin":
		// Windows and Linux get network events from Sysmon.
	case !wantsNetwork(engine.RequiredEvents()) && !exporting:
		say(stderr, "network: no enabled rule uses network events; socket polling is off")
	default:
		np := netpoll.New(netpoll.Config{Interval: n.netInterval, Lookup: snap.Lookup, SelfPID: int32(os.Getpid()),
			IncludeLoopback: n.netLoopback})
		np.OnDegraded(p.degraded)
		s.net = np
		// Poll a process right after it executes (its sockets are often
		// opened just after exec).
		p.taps = append(p.taps, func(e *event.Event) {
			if e.Name == event.CreateProcess && e.Source != netpoll.Name && e.Proc != nil {
				np.Nudge(e.Proc.PID)
			}
		})
		s.extra["network"] = np.Stats
		say(stderr, "network: polling sockets every %v and after each exec (connections shorter than that can be missed; no DNS on macOS)", n.netInterval)
	}
	return nil
}

// netChannel returns the channel netpoll writes to (nil when it is off, so
// the run loop never selects it) and starts it.
func (s *sensor) startNet(ctx context.Context, stderr io.Writer) chan *event.Event {
	if s.net == nil {
		return nil
	}
	ch := make(chan *event.Event, netpollChannelCapacity)
	go func() {
		if err := s.net.Run(ctx, nil, ch); err != nil {
			say(stderr, "network: socket polling stopped: %v", err)
		}
	}()
	return ch
}
