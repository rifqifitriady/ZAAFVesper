//go:build zaafvesper_validate

package main

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net"
	"os/exec"
	"strings"
	"time"

	"github.com/rifqifitriady/ZAAFVesper/pkg/event"
	"github.com/rifqifitriady/ZAAFVesper/pkg/response"
)

// Helpers shared by the platform cases of the live harness.

func randID() string {
	b := make([]byte, 4)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func run(bin string, args ...string) (string, error) {
	out, err := exec.Command(bin, args...).CombinedOutput()
	return string(out), err
}

// stdout runs bin and returns its standard output only (pfctl writes
// notices such as "No ALTQ support in kernel" to stderr).
func stdout(bin string, args ...string) string {
	out, _ := exec.Command(bin, args...).Output()
	return string(out)
}

// writer starts a test process to play the untrusted writer or remover of
// a file event and returns its event identity.
func (h *vHarness) writer() (*event.Proc, error) {
	s, err := h.spawn()
	if err != nil {
		return nil, err
	}
	return procOf(s.pid)
}

// restoreCase finds path in `zaafvesper quarantine list`, restores it with
// `zaafvesper quarantine restore` and runs check on the result.
func (h *vHarness) restoreCase(action, path string, check func() string) {
	out, err := h.runSelf("quarantine", "list")
	id := ""
	for _, line := range strings.Split(out, "\n") {
		if strings.Contains(line, path) {
			id = strings.Fields(line)[0]
			break
		}
	}
	if err != nil || id == "" {
		h.reset()
		h.record(action, "quarantine list shows it", expectAct, false, fmt.Sprintf("list: %v %q", err, out))
		return
	}
	h.reset()
	h.record(action, "zaafvesper quarantine list shows it", expectAct, true, "id "+id)
	out, err = h.runSelf("quarantine", "restore", id)
	why := "restore failed"
	if err == nil {
		why = check()
	}
	h.record(action, "zaafvesper quarantine restore puts it back", expectAct, err == nil && why == "", strings.TrimSpace(why+" "+out))
}

func keys(m map[string]bool) []string {
	var out []string
	for k := range m {
		out = append(out, k)
	}
	return out
}

// isoCase describes the isolation case of a platform for isolateFlow.
type isoCase struct {
	probe   string                 // address the TCP probe dials (blocked by the case)
	port    string                 // its port
	extra   string                 // a documentation address that routes nowhere
	never   []string               // never-block addresses offered as peers
	listed  func() map[string]bool // addresses in ZAAFVesper's firewall objects now
	where   string                 // "nftables set", "Windows Firewall rules"
	ttl     time.Duration
	cleared func() (bool, string) // after Close: ZAAFVesper's objects are gone
}

// isolateFlow runs the isolation cases: block, never-block set, CLI list
// and release, expiry, clean shutdown.
func (h *vHarness) isolateFlow(c isoCase) {
	dial := func() error {
		conn, err := net.DialTimeout("tcp", net.JoinHostPort(c.probe, c.port), 3*time.Second)
		if err == nil {
			_ = conn.Close()
		}
		return err
	}
	if err := dial(); err != nil {
		h.untestable("isolate_process", "all cases", "the probe address is not reachable before isolation: "+err.Error())
		return
	}
	p, err := h.writer()
	if err != nil {
		h.untestable("isolate_process", "test process", err.Error())
		return
	}
	observe := func(ip string) {
		h.r.Observe(&event.Event{Name: event.NetworkConnect, Source: vSource(), Proc: p, Net: &event.Net{Proto: "tcp", Direction: "outbound", DstIP: ip, DstPort: 443}})
	}
	for _, ip := range append(append([]string{}, c.never...), c.extra) {
		observe(ip)
	}
	var dport uint16
	_, _ = fmt.Sscan(c.port, &dport)
	e := &event.Event{Name: event.NetworkConnect, Source: vSource(), Proc: p, Net: &event.Net{Proto: "tcp", Direction: "outbound", DstIP: c.probe, DstPort: dport}}
	h.reset()
	err = h.r.IsolateProcess(e, response.TargetProcess, "validate-isolate", "validation: isolate_process")
	listed := c.listed()
	blocked := dial() != nil
	h.record("isolate_process", "peers blocked ("+c.where+")", expectAct, err == nil && listed[c.probe] && listed[c.extra] && len(listed) == 2 && blocked,
		fmt.Sprintf("listed=%v new connection to %s blocked=%v", keys(listed), c.probe, blocked))
	var leaked []string
	for _, a := range c.never {
		if listed[a] {
			leaked = append(leaked, a)
		}
	}
	h.reset()
	h.record("isolate_process", "never-block set (gateways, DNS resolvers, loopback, this host's addresses)", expectDeny, len(c.never) > 0 && len(leaked) == 0,
		fmt.Sprintf("checked %v, blocked by mistake %v", c.never, leaked))
	out, lerr := h.runSelf("isolation", "list")
	h.reset()
	h.record("isolate_process", "zaafvesper isolation list shows the address", expectAct, lerr == nil && strings.Contains(out, c.probe), strings.TrimSpace(out))
	out, rerr := h.runSelf("isolation", "release", c.probe)
	reach := dial() == nil
	h.reset()
	h.record("isolate_process", "zaafvesper isolation release lifts the block", expectAct, rerr == nil && reach && !c.listed()[c.probe],
		fmt.Sprintf("reachable again=%v %s", reach, strings.TrimSpace(out)))
	time.Sleep(c.ttl + time.Second)
	h.r.Tick(time.Now())
	h.reset()
	left := c.listed()
	h.record("isolate_process", fmt.Sprintf("time-to-live expiry (%s in this run)", c.ttl), expectAct, len(left) == 0 && h.decision().Outcome == response.OutcomeReleased,
		fmt.Sprintf("listed now %v", keys(left)))
	_ = h.r.Close()
	ok, detail := c.cleared()
	h.reset()
	h.record("isolate_process", "clean shutdown removes ZAAFVesper's firewall objects", expectAct, ok, detail)
}

// runQuiet runs a setup or cleanup command, discarding its output.
func runQuiet(bin string, args ...string) error { return exec.Command(bin, args...).Run() }
