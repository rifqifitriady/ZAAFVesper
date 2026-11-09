package main

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"encoding/json"
	"encoding/pem"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/rifqifitriady/ZAAFVesper/pkg/event"
)

func TestNetOutFlagChecks(t *testing.T) {
	ok := netOutOptions{netInterval: time.Second, syslogFacility: "local4", webhookFormat: "json",
		spoolMaxBytes: 1, elegiaMaxBytes: 1, ocsfMaxBytes: 1}
	if err := ok.check(); err != nil {
		t.Fatal(err)
	}
	for name, mut := range map[string]func(*netOutOptions){
		"interval":        func(n *netOutOptions) { n.netInterval = 10 * time.Millisecond },
		"syslog no CA":    func(n *netOutOptions) { n.syslogAddr = "h:6514" },
		"CA no syslog":    func(n *netOutOptions) { n.syslogCA = "/x" },
		"webhook no tok":  func(n *netOutOptions) { n.webhookURL = "https://h/x" },
		"webhook http":    func(n *netOutOptions) { n.webhookURL, n.webhookTokenFile = "http://h/x", "/t" },
		"webhook creds":   func(n *netOutOptions) { n.webhookURL, n.webhookTokenFile = "https://u:p@h/x", "/t" },
		"format":          func(n *netOutOptions) { n.webhookFormat = "xml" },
		"events no siem":  func(n *netOutOptions) { n.siemEvents = true },
		"ocsf stdout":     func(n *netOutOptions) { n.alertsOCSF = "-" },
		"same file":       func(n *netOutOptions) { n.alertsOCSF, n.elegiaOut = "/tmp/a", "/tmp/a" },
		"bad facility":    func(n *netOutOptions) { n.syslogAddr, n.syslogCA, n.syslogFacility = "h:1", "/c", "mail2" },
		"zero spool size": func(n *netOutOptions) { n.spoolMaxBytes = 0 },
	} {
		n := ok
		mut(&n)
		if err := n.check(); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	var out, errb bytes.Buffer
	if (&netOutOptions{elegiaOut: "-"}).consoleWriter(&out, &errb) != &errb {
		t.Fatal("console still on stdout with --elegia-out -")
	}
}

// TestRunWiresNetworkAndOutputs builds the live sensor with every W2
// output pointed at servers this test starts on 127.0.0.1, feeds a polled
// reverse-shell socket, and checks that the network rule fires, that the
// alert reaches syslog (TLS, pinned CA), the webhook and the OCSF file,
// that the event reaches the ZAAFElegia file with Sigma names, and that
// the netpoll event left the process table untouched (N7).
func TestRunWiresNetworkAndOutputs(t *testing.T) {
	if runtime.GOOS != "darwin" {
		// Socket polling and the macOS network rules this test drives exist
		// only on macOS (Windows and Linux get network events from Sysmon).
		t.Skip("macOS socket polling")
	}
	dir := t.TempDir()
	// HTTPS webhook.
	var mu sync.Mutex
	var hooks []string
	web := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		mu.Lock()
		hooks = append(hooks, r.Header.Get("Authorization")+" "+string(b))
		mu.Unlock()
	}))
	defer web.Close()
	webCA := filepath.Join(dir, "web-ca.pem")
	_ = os.WriteFile(webCA, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: web.Certificate().Raw}), 0o600)
	tok := filepath.Join(dir, "token")
	_ = os.WriteFile(tok, []byte("s3cret-token\n"), 0o600)
	// TLS syslog receiver reusing the webhook's certificate (it is valid
	// for 127.0.0.1).
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: web.TLS.Certificates})
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	syslogMsgs := make(chan string, 8)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
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
			syslogMsgs <- string(buf)
		}
	}()

	o := runOptions{rulesDir: "../../rules", rulesGiven: true, configPath: filepath.Join(dir, "none.yml"),
		noYara: true, noConsole: true, jsonKeep: 8, captureKeep: 2}
	o.netout = netOutOptions{netInterval: time.Second, syslogAddr: ln.Addr().String(), syslogCA: webCA, syslogFacility: "local4",
		webhookURL: web.URL + "/hook", webhookTokenFile: tok, webhookCA: webCA, webhookFormat: "json",
		spoolDir: filepath.Join(dir, "spool"), spoolMaxBytes: 1 << 20, elegiaOut: filepath.Join(dir, "events.ndjson"),
		elegiaMaxBytes: 1 << 20, alertsOCSF: filepath.Join(dir, "alerts.ocsf.ndjson"), ocsfMaxBytes: 1 << 20}
	var out, errb bytes.Buffer
	s, err := buildSensor(o, &out, &errb)
	if err != nil {
		t.Fatalf("%v\n%s", err, errb.String())
	}
	closed := false
	defer func() {
		if !closed {
			_ = s.close()
		}
	}()
	if s.net == nil {
		t.Fatalf("netpoll not wired:\n%s", errb.String())
	}
	before := s.snap.Len()
	s.p.handleNetwork(&event.Event{Time: time.Now().UTC(), Name: event.NetworkConnect, Source: "netpoll", Platform: event.PlatformMacOS,
		Proc: &event.Proc{PID: 4242, PPID: 4241, PIDVersion: 9, Exe: "/bin/bash", Name: "bash", UID: 501, EUID: 501, IsPlatform: true, IsSigned: true, Seeded: true},
		Net:  &event.Net{Proto: "tcp", Direction: "outbound", SrcIP: "10.0.0.5", SrcPort: 50111, DstIP: "203.0.113.9", DstPort: 4444},
		Args: map[string]string{"fd": "0", "identity": "unverified"}})
	if s.snap.Len() != before {
		t.Fatalf("a netpoll event changed the process table (%d -> %d)", before, s.snap.Len())
	}
	if s.p.alerts != 1 {
		t.Fatalf("alerts %d, want 1 (reverse shell rule); stderr:\n%s", s.p.alerts, errb.String())
	}
	select {
	case m := <-syslogMsgs:
		if !strings.HasPrefix(m, "<163>1 ") || !strings.Contains(m, `rule_id="46ecd3c3-0b67-42a4-99ef-c6a2854a5c9b"`) {
			t.Fatalf("syslog message %q", m)
		}
	case <-time.After(5 * time.Second):
		t.Fatalf("no syslog message; stderr:\n%s", errb.String())
	}
	deadline := time.Now().Add(5 * time.Second)
	for {
		mu.Lock()
		n := len(hooks)
		mu.Unlock()
		if n > 0 || time.Now().After(deadline) {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	mu.Lock()
	if len(hooks) != 1 || !strings.HasPrefix(hooks[0], "Bearer s3cret-token [") {
		t.Fatalf("webhook got %q", hooks)
	}
	mu.Unlock()
	if err := s.close(); err != nil {
		t.Fatal(err)
	}
	closed = true
	if strings.Contains(errb.String(), "s3cret") {
		t.Fatal("token in the log")
	}
	ev := readJSONLines(t, o.netout.elegiaOut)
	if len(ev) != 1 || ev[0]["Image"] != "/bin/bash" || ev[0]["DestinationPort"] != float64(4444) || ev[0]["Initiated"] != "true" ||
		ev[0]["EventID"] != float64(3) {
		t.Fatalf("elegia events %v", ev)
	}
	fs := readJSONLines(t, o.netout.alertsOCSF)
	if len(fs) != 1 || fs[0]["class_uid"] != float64(2004) || fs[0]["severity"] != "High" {
		t.Fatalf("ocsf %v", fs)
	}
	for _, p := range []string{o.netout.elegiaOut, o.netout.alertsOCSF} {
		if fi, _ := os.Stat(p); fi.Mode().Perm() != 0o600 {
			t.Fatalf("%s mode %o", p, fi.Mode().Perm())
		}
	}
}

func readJSONLines(t *testing.T, path string) []map[string]any {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var out []map[string]any
	for _, l := range strings.Split(strings.TrimSpace(string(b)), "\n") {
		if l == "" {
			continue
		}
		var m map[string]any
		if err := json.Unmarshal([]byte(l), &m); err != nil {
			t.Fatalf("%s: %v", l, err)
		}
		out = append(out, m)
	}
	return out
}
