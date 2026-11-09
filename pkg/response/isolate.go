package response

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/rifqifitriady/ZAAFVesper/pkg/event"
)

// pf objects of isolate_process. pf has no per-process filter on macOS, so
// an isolation blocks the process's remote peers for the WHOLE host.
//
// The stock /etc/pf.conf evaluates only anchors under "com.apple/*", so
// ZAAFVesper's anchor com.rifqifitriady.zaafvesper is attached there; an
// anchor outside it would never be evaluated.
const (
	PFAnchor = "com.apple/com.rifqifitriady.zaafvesper"
	PFTable  = "zaafvesper_isolated"
)

// pfRules is the anchor's whole ruleset: one table, two quick block rules.
// It is a constant: no event data is ever written into a pf rule; peers
// only enter the table, as addresses that net/netip parsed and re-printed.
const pfRules = "table <" + PFTable + "> persist\n" +
	"block drop quick from any to <" + PFTable + ">\n" +
	"block drop quick from <" + PFTable + "> to any\n"

// Bounds of isolate_process.
const (
	maxPeersPerAction = 16               // addresses blocked by one action
	maxIsolated       = 256              // addresses in the table at once
	maxPeersPerProc   = 32               // peers remembered per process
	maxTrackedProcs   = 4096             // processes with remembered peers
	peerWindow        = 10 * time.Minute // a peer older than this is forgotten
	isolationState    = "isolation.json" // in Config.StateDir
	isolationLock     = "isolation.lock"
)

// Isolation is one blocked remote address.
type Isolation struct {
	Addr    string    `json:"addr"`
	Added   time.Time `json:"added"`
	Expires time.Time `json:"expires"`
	Rule    string    `json:"rule,omitempty"`
	Reason  string    `json:"reason,omitempty"`
	PID     int32     `json:"pid,omitempty"`
	Exe     string    `json:"exe,omitempty"`
}

type peerSet struct {
	last  time.Time
	addrs map[netip.Addr]time.Time
}

// procKey identifies a process incarnation for the peer table: the kernel
// unique id when known, else pid, pidversion and start time.
func procKey(p *event.Proc) string {
	if p.UniqueID != 0 {
		return fmt.Sprintf("u%d", p.UniqueID)
	}
	return fmt.Sprintf("p%d/%d/%d", p.PID, p.PIDVersion, p.StartTime.UnixNano())
}

// remoteAddrs returns the remote addresses of a network event: the
// destination of an outbound connection; for an inbound one, both ends
// (this host's own addresses are filtered later); none for a listener.
func remoteAddrs(n *event.Net) []string {
	if n == nil {
		return nil
	}
	switch n.Direction {
	case "outbound":
		return []string{n.DstIP}
	case "inbound":
		return []string{n.SrcIP, n.DstIP}
	case "listen":
		return nil
	}
	return []string{n.DstIP}
}

// Observe remembers the remote peers of NetworkConnect and NetworkAccept
// events per process, for a later isolate_process. Other events are
// ignored. Memory is bounded (maxTrackedProcs processes, maxPeersPerProc
// peers each, forgotten after peerWindow).
func (r *Responder) Observe(e *event.Event) {
	if e == nil || e.Proc == nil || e.Net == nil || (e.Name != event.NetworkConnect && e.Name != event.NetworkAccept) {
		return
	}
	now := r.cfg.Now()
	r.netMu.Lock()
	defer r.netMu.Unlock()
	key := procKey(e.Proc)
	ps, ok := r.peers[key]
	if !ok {
		if len(r.peers) >= maxTrackedProcs {
			r.prunePeers(now)
		}
		ps = &peerSet{addrs: map[netip.Addr]time.Time{}}
		r.peers[key] = ps
	}
	ps.last = now
	for _, s := range remoteAddrs(e.Net) {
		a, err := netip.ParseAddr(s)
		if err != nil {
			continue
		}
		a = a.Unmap()
		if _, seen := ps.addrs[a]; !seen && len(ps.addrs) >= maxPeersPerProc {
			var oldest netip.Addr
			var at time.Time
			for x, t := range ps.addrs {
				if at.IsZero() || t.Before(at) {
					oldest, at = x, t
				}
			}
			delete(ps.addrs, oldest)
		}
		ps.addrs[a] = now
	}
}

// prunePeers drops expired peer sets, then the least recently seen half if
// still full. Caller holds netMu.
func (r *Responder) prunePeers(now time.Time) {
	for k, ps := range r.peers {
		if now.Sub(ps.last) > peerWindow {
			delete(r.peers, k)
		}
	}
	if len(r.peers) < maxTrackedProcs {
		return
	}
	type kv struct {
		k string
		t time.Time
	}
	all := make([]kv, 0, len(r.peers))
	for k, ps := range r.peers {
		all = append(all, kv{k, ps.last})
	}
	sort.Slice(all, func(i, j int) bool { return all[i].t.Before(all[j].t) })
	for _, x := range all[:len(all)/2] {
		delete(r.peers, x.k)
	}
}

// peersOf returns the remembered peers of p seen within peerWindow, plus
// those of e itself when e is a network event of p.
func (r *Responder) peersOf(e *event.Event, p *event.Proc, now time.Time) []netip.Addr {
	set := map[netip.Addr]bool{}
	if e.Net != nil && e.Proc == p {
		for _, s := range remoteAddrs(e.Net) {
			if a, err := netip.ParseAddr(s); err == nil {
				set[a.Unmap()] = true
			}
		}
	}
	r.netMu.Lock()
	if ps, ok := r.peers[procKey(p)]; ok {
		for a, t := range ps.addrs {
			if now.Sub(t) <= peerWindow {
				set[a] = true
			}
		}
	}
	r.netMu.Unlock()
	out := make([]netip.Addr, 0, len(set))
	for a := range set {
		out = append(out, a)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Less(out[j]) })
	return out
}

// blockable returns why a must never be blocked, or "": invalid, loopback,
// unspecified, multicast, broadcast, link-local, with a zone, this host's
// own address, or inside the management allow-list.
// NeverBlockNetworks are networks isolate_process never blocks, whatever
// the configuration: Apple's 17.0.0.0/8 (software update, XProtect,
// notarization, push). Private RFC 1918 addresses can be isolated (owner
// decision 9 Nov 2026); protect your own servers with response.isolation_allow.
var NeverBlockNetworks = []netip.Prefix{netip.MustParsePrefix("17.0.0.0/8")}

// blockable returns why a must never be blocked, or "": invalid, scoped,
// loopback, unspecified, multicast, broadcast, link-local, this host's own
// address, a default gateway or DNS resolver of this Mac (never), Apple's
// 17.0.0.0/8, or inside the management allow-list. never holds the host's
// addresses, gateways and resolvers.
func (r *Responder) blockable(a netip.Addr, never map[netip.Addr]string) string {
	switch {
	case !a.IsValid():
		return "invalid"
	case a.Zone() != "":
		return "scoped address"
	case a.IsLoopback():
		return "loopback"
	case a.IsUnspecified():
		return "unspecified"
	case a.IsMulticast() || a == netip.AddrFrom4([4]byte{255, 255, 255, 255}):
		return "multicast or broadcast"
	case a.IsLinkLocalUnicast():
		return "link-local"
	case never[a] != "":
		return never[a]
	}
	for _, p := range NeverBlockNetworks {
		if p.Contains(a) {
			return "Apple's network " + p.String()
		}
	}
	for _, p := range r.cfg.IsolationAllow {
		if p.Contains(a) {
			return "management allow-list " + p.String()
		}
	}
	return ""
}

// neverBlock returns this Mac's own addresses, default gateways and DNS
// resolvers with the reason each is never blocked. It fails (and the
// isolation is refused) when the addresses or the gateways cannot be read.
// Caller holds actMu.
func (r *Responder) neverBlock() (map[netip.Addr]string, error) {
	never := map[netip.Addr]string{}
	as, err := r.cfg.LocalAddrs()
	if err != nil {
		return nil, fmt.Errorf("cannot list this host's addresses (%v)", err)
	}
	for _, a := range as {
		never[a.WithZone("").Unmap()] = "this host's address"
	}
	gws, err := r.cfg.Gateways()
	if err != nil {
		return nil, fmt.Errorf("cannot read the default gateway (%v)", err)
	}
	for _, a := range gws {
		never[a.WithZone("").Unmap()] = "a default gateway of this Mac"
	}
	for a := range r.resolvers() {
		never[a] = "a DNS resolver of this Mac (/etc/resolv.conf)"
	}
	return never, nil
}

// routeGateways is the default Config.Gateways: the gateway lines of
// `/sbin/route -n get default` and `/sbin/route -n get -inet6 default`
// (pinned, fixed argv). A family without a default route is not an error;
// a command that cannot run is.
func routeGateways(run Runner) func() ([]netip.Addr, error) {
	return func() ([]netip.Addr, error) {
		var out []netip.Addr
		for _, args := range [][]string{{"-n", "get", "default"}, {"-n", "get", "-inet6", "default"}} {
			b, err := run(context.Background(), RouteBin, args, nil)
			var ee *ExitError
			switch {
			case errors.As(err, &ee):
				continue // no default route for this family
			case err != nil:
				return nil, err
			}
			out = append(out, parseRouteGateway(b)...)
		}
		return out, nil
	}
}

// parseRouteGateway returns the address on the "gateway:" line of `route
// get` output (none when the gateway is an interface, not an address).
func parseRouteGateway(b []byte) []netip.Addr {
	for _, line := range strings.Split(string(b), "\n") {
		if v, ok := strings.CutPrefix(strings.TrimSpace(line), "gateway:"); ok {
			if a, err := netip.ParseAddr(strings.TrimSpace(v)); err == nil {
				return []netip.Addr{a.WithZone("").Unmap()}
			}
		}
	}
	return nil
}

// resolvers returns the DNS resolvers that are never blocked.
func (r *Responder) resolvers() map[netip.Addr]bool {
	out := map[netip.Addr]bool{}
	if r.cfg.Resolvers == nil {
		return out
	}
	for _, a := range r.cfg.Resolvers() {
		out[a.Unmap()] = true
	}
	return out
}

// resolvConfAddrs is the default Config.Resolvers: the nameserver lines of
// /private/var/run/resolv.conf (what /etc/resolv.conf points to), which
// macOS keeps in step with the system's DNS configuration.
func resolvConfAddrs() []netip.Addr {
	b, err := os.ReadFile("/private/var/run/resolv.conf")
	if err != nil {
		return nil
	}
	var out []netip.Addr
	for _, line := range strings.Split(string(b), "\n") {
		f := strings.Fields(line)
		if len(f) >= 2 && f[0] == "nameserver" {
			if a, err := netip.ParseAddr(f[1]); err == nil {
				out = append(out, a.WithZone("").Unmap())
			}
		}
	}
	return out
}

// interfaceAddrs is the default Config.LocalAddrs.
func interfaceAddrs() ([]netip.Addr, error) {
	as, err := net.InterfaceAddrs()
	if err != nil {
		return nil, err
	}
	var out []netip.Addr
	for _, a := range as {
		if p, err := netip.ParsePrefix(a.String()); err == nil {
			out = append(out, p.Addr().Unmap())
		}
	}
	return out, nil
}

// IsolateProcess blocks the remote peers of the process (target process)
// or of its parent (target parent) in the pf anchor for Config.IsolationTTL.
// The peers are the event's own (a NetworkConnect or NetworkAccept) and
// those Observe saw for the same process in the last ten minutes. Guard
// rails: the process identity rules of kill (protected pids, paths, names,
// platform binaries, seeded or unverified identity, signing category, a
// platform flag that must be known); never loopback, link-local, multicast,
// this host's addresses, its default gateways and DNS resolvers, Apple's
// 17.0.0.0/8 or the management allow-list; at most 16 addresses per action
// and 256 in all; the file/network budget; dry-run. pf filters by address, not by process: every
// program on this Mac loses those peers until the isolation expires or is
// released. Connections the process opens to new peers later are not
// blocked.
func (r *Responder) IsolateProcess(e *event.Event, target, rule, reason string) error {
	if target == "" {
		target = TargetProcess
	}
	p, _ := targetProc(e, target)
	d := Decision{Action: ActionIsolateProcess, PID: p.PID, Target: target, Name: p.Name, Exe: p.Exe, Reason: reason}
	return r.act(d, rule, func(budget func() *result) result {
		p, res := r.preflight(e, target, preProcess)
		if res != nil {
			return *res
		}
		now := r.cfg.Now()
		peers := r.peersOf(e, p, now)
		if len(peers) == 0 {
			return refused(OutcomeNoPeers, ErrNoPeers, "no remote peer seen for this process")
		}
		never, err := r.neverBlock()
		if err != nil {
			return refused(OutcomeNoPeers, ErrNoPeers, "%v; refusing to block anything", err)
		}
		var block []netip.Addr
		var skipped []string
		for _, a := range peers {
			if why := r.blockable(a, never); why != "" {
				skipped = append(skipped, a.String()+" ("+why+")")
				continue
			}
			if len(block) >= maxPeersPerAction {
				skipped = append(skipped, a.String()+" (over 16 per action)")
				continue
			}
			block = append(block, a)
		}
		if len(block) == 0 {
			return refused(OutcomeNoPeers, ErrNoPeers, "no remote peer seen for this process%s", skippedNote(skipped))
		}
		fresh := 0
		for _, a := range block {
			if _, ok := r.isolated[a.String()]; !ok {
				fresh++
			}
		}
		if len(r.isolated)+fresh > maxIsolated {
			return refused(OutcomeIsolationFull, ErrNoPeers, "%d addresses are isolated already (cap %d)", len(r.isolated), maxIsolated)
		}
		if res := budget(); res != nil {
			return *res
		}
		addrs := make([]string, len(block))
		for i, a := range block {
			addrs[i] = a.String()
		}
		note := fmt.Sprintf("%s for %s; pf blocks these addresses for the whole host, not only this process%s",
			strings.Join(addrs, ", "), r.cfg.IsolationTTL, skippedNote(skipped))
		if r.cfg.DryRun {
			return result{OutcomeDryRun, "would block " + note, nil}
		}
		if err := r.ensurePF(); err != nil {
			return result{OutcomeError, "pf: " + err.Error(), fmt.Errorf("response: isolate: %w", err)}
		}
		if _, err := r.pfctl(append([]string{"-a", PFAnchor, "-t", PFTable, "-T", "add"}, addrs...)...); err != nil {
			return result{OutcomeError, "pfctl add: " + err.Error(), fmt.Errorf("response: isolate: %w", err)}
		}
		for _, a := range block {
			r.killStates(a)
			iso := &Isolation{Addr: a.String(), Added: now.UTC(), Expires: now.Add(r.cfg.IsolationTTL).UTC(),
				Rule: rule, Reason: reason, PID: p.PID, Exe: p.Exe}
			if old, ok := r.isolated[iso.Addr]; ok && old.Expires.After(iso.Expires) {
				iso.Expires = old.Expires
			}
			r.isolated[iso.Addr] = iso
		}
		if err := r.saveIsolations(); err != nil {
			note += "; state file not written: " + err.Error()
		}
		return result{OutcomeIsolated, "blocked " + note + " (release: zaafvesper isolation release <addr>|all)", nil}
	})
}

// addrLess orders addresses as IPs (IPv4 before IPv6, numerically).
func addrLess(a, b string) bool {
	x, errx := netip.ParseAddr(a)
	y, erry := netip.ParseAddr(b)
	if errx != nil || erry != nil {
		return a < b
	}
	return x.Less(y)
}

func skippedNote(skipped []string) string {
	if len(skipped) == 0 {
		return ""
	}
	return "; not blocked: " + strings.Join(skipped, ", ")
}

// pfctl runs /sbin/pfctl with args through the Runner.
func (r *Responder) pfctl(args ...string) ([]byte, error) {
	return r.cfg.Runner(context.Background(), PfctlBin, args, nil)
}

var pfTokenRe = regexp.MustCompile(`Token : ([0-9]+)`)

// ensurePF loads the anchor's constant ruleset and takes a pf enable
// reference (pfctl -E), once. Caller holds actMu.
func (r *Responder) ensurePF() error {
	if r.pfLoaded {
		return nil
	}
	if _, err := r.cfg.Runner(context.Background(), PfctlBin, []string{"-a", PFAnchor, "-f", "-"}, []byte(pfRules)); err != nil {
		return fmt.Errorf("load anchor %s: %w", PFAnchor, err)
	}
	out, err := r.pfctl("-E")
	if err != nil {
		return fmt.Errorf("enable pf: %w", err)
	}
	if m := pfTokenRe.FindSubmatch(out); m != nil {
		r.pfToken = string(m[1])
	}
	r.pfLoaded = true
	return nil
}

// killStates drops pf states to and from a (connections already open would
// otherwise keep flowing). Errors are ignored: there may be no state.
func (r *Responder) killStates(a netip.Addr) {
	all := "0.0.0.0/0"
	if a.Is6() {
		all = "::/0"
	}
	_, _ = r.pfctl("-k", a.String())
	_, _ = r.pfctl("-k", all, "-k", a.String())
}

// StartResponse prepares the actions at sensor start: the pf anchor is
// flushed (an earlier run that did not shut down cleanly may have left
// blocks) and the isolation state is cleared. Dry-run touches nothing.
func (r *Responder) StartResponse() error {
	if r.cfg.DryRun {
		return nil
	}
	r.actMu.Lock()
	defer r.actMu.Unlock()
	_, err := r.pfctl("-a", PFAnchor, "-F", "all")
	r.isolated, r.saved = map[string]*Isolation{}, nil
	if fileOpsSupported {
		if serr := (IsolationStore{Dir: r.cfg.StateDir, RequireRootOwned: r.cfg.RequireRootOwned}).Save([]Isolation{}); serr != nil {
			err = errors.Join(err, serr)
		}
	}
	return err
}

// Tick runs the timed parts of the actions: suspended processes whose time
// is over are resumed, isolations whose time-to-live is over are released.
// run calls it every 2 seconds.
func (r *Responder) Tick(now time.Time) {
	r.mu.Lock()
	r.tickSuspended(now)
	r.mu.Unlock()
	// The event loop calls Tick: never wait for a slow action. When one is
	// running, isolation expiry waits for the next tick (2 s later).
	if !r.actMu.TryLock() {
		return
	}
	defer r.actMu.Unlock()
	var expired []string
	for a, iso := range r.isolated {
		if !now.Before(iso.Expires) {
			expired = append(expired, a)
		}
	}
	if len(expired) == 0 {
		if len(r.isolated) > 0 {
			_ = r.saveIsolations() // picks up releases done with the CLI
		}
		return
	}
	sort.Slice(expired, func(i, j int) bool { return addrLess(expired[i], expired[j]) })
	_, err := r.pfctl(append([]string{"-a", PFAnchor, "-t", PFTable, "-T", "delete"}, expired...)...)
	for _, a := range expired {
		iso := r.isolated[a]
		delete(r.isolated, a)
		d := Decision{Time: now, Action: ActionIsolateProcess, PID: iso.PID, Target: TargetProcess, Exe: iso.Exe,
			Reason: iso.Reason, Outcome: OutcomeReleased, Detail: a + " expired"}
		if err != nil {
			d.Outcome, d.Detail = OutcomeError, a+" expired, but pfctl delete failed: "+err.Error()
		}
		r.mu.Lock()
		r.logLocked(d)
		r.mu.Unlock()
	}
	_ = r.saveIsolations()
}

// Close ends the response at a clean shutdown, quickly enough for launchd's
// exit timeout: every suspended process is resumed first, then the worker
// stops (the action running now finishes, queued ones are dropped), the pf
// anchor is flushed, the pf enable reference released and the isolation
// state cleared.
func (r *Responder) Close() error {
	r.ResumeAll()
	r.stopWorker(true)
	if r.cfg.DryRun {
		return nil
	}
	r.actMu.Lock()
	defer r.actMu.Unlock()
	_, err := r.pfctl("-a", PFAnchor, "-F", "all")
	if r.pfToken != "" {
		if _, xerr := r.pfctl("-X", r.pfToken); xerr != nil {
			err = errors.Join(err, xerr)
		}
		r.pfToken = ""
	}
	r.pfLoaded = false
	r.isolated, r.saved = map[string]*Isolation{}, nil
	if fileOpsSupported {
		if serr := (IsolationStore{Dir: r.cfg.StateDir, RequireRootOwned: r.cfg.RequireRootOwned}).Save([]Isolation{}); serr != nil {
			err = errors.Join(err, serr)
		}
	}
	return err
}

// Isolations returns the current isolations, by address.
func (r *Responder) Isolations() []Isolation {
	r.actMu.Lock()
	defer r.actMu.Unlock()
	out := make([]Isolation, 0, len(r.isolated))
	for _, iso := range r.isolated {
		out = append(out, *iso)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Addr < out[j].Addr })
	return out
}

// IsolationStore is the isolation state file shared by the sensor and the
// CLI (`zaafvesper isolation list|release`), in a root-only directory.
type IsolationStore struct {
	Dir              string
	RequireRootOwned bool
}

func (s IsolationStore) withLock(create bool, f func(dirfd int) error) error {
	v := Vault{Dir: s.Dir, RequireRootOwned: s.RequireRootOwned}
	dfd, err := v.open(create)
	if err != nil {
		return err
	}
	defer closeFD(dfd)
	lfd, err := openLockAt(dfd, isolationLock)
	if err != nil {
		return err
	}
	defer closeFD(lfd)
	if err := flockFD(lfd); err != nil {
		return err
	}
	return f(dfd)
}

// Load returns the isolations in the state file (none when it is absent).
func (s IsolationStore) Load() ([]Isolation, error) {
	var out []Isolation
	err := s.withLock(false, func(dfd int) error {
		var err error
		out, err = loadIsolationsAt(dfd)
		return err
	})
	return out, err
}

// Save replaces the state file with isos.
func (s IsolationStore) Save(isos []Isolation) error {
	return s.withLock(true, func(dfd int) error { return saveIsolationsAt(dfd, isos) })
}

// saveIsolations writes r.isolated to the state file. An address that was
// in the file at the last save and is gone now was released with
// `zaafvesper isolation release`: it is dropped from r.isolated first (and
// deleted from the pf table again, which is harmless when the CLI already
// did), so the CLI's release sticks and no block is left untracked. A state
// file that cannot be read or parsed is not taken as a release. Caller holds
// actMu.
func (r *Responder) saveIsolations() error {
	if !fileOpsSupported {
		return nil
	}
	store := IsolationStore{Dir: r.cfg.StateDir, RequireRootOwned: r.cfg.RequireRootOwned}
	return store.withLock(true, func(dfd int) error {
		cur, rerr := loadIsolationsAt(dfd)
		if rerr == nil {
			inFile := map[string]bool{}
			for _, iso := range cur {
				inFile[iso.Addr] = true
			}
			var gone []string
			for a := range r.saved {
				if !inFile[a] {
					if _, ok := r.isolated[a]; ok {
						delete(r.isolated, a) // released by the CLI
						gone = append(gone, a)
					}
				}
			}
			if len(gone) > 0 {
				sort.Slice(gone, func(i, j int) bool { return addrLess(gone[i], gone[j]) })
				_, _ = r.pfctl(append([]string{"-a", PFAnchor, "-t", PFTable, "-T", "delete"}, gone...)...)
			}
		}
		isos := make([]Isolation, 0, len(r.isolated))
		r.saved = map[string]bool{}
		for a, iso := range r.isolated {
			isos = append(isos, *iso)
			r.saved[a] = true
		}
		sort.Slice(isos, func(i, j int) bool { return addrLess(isos[i].Addr, isos[j].Addr) })
		return saveIsolationsAt(dfd, isos)
	})
}

// loadIsolationsAt reads the state file in dfd (none when it is absent).
func loadIsolationsAt(dfd int) ([]Isolation, error) {
	b, err := readAllAt(dfd, isolationState, 4<<20)
	if isNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var out []Isolation
	if err := json.Unmarshal(b, &out); err != nil {
		return nil, fmt.Errorf("%s: %w", isolationState, err)
	}
	return out, nil
}

func saveIsolationsAt(dfd int, isos []Isolation) error {
	if isos == nil {
		isos = []Isolation{}
	}
	b, err := json.MarshalIndent(isos, "", "  ")
	if err != nil {
		return err
	}
	return writeAtomicAt(dfd, isolationState, append(b, '\n'))
}

// ReleaseIsolation removes addr (or every address when addr is "all") from
// the pf table and from the state file, for `zaafvesper isolation release`.
// The state file stays locked from its read to its write, so a sensor that
// isolates another address meanwhile waits and keeps it. A running sensor
// stops tracking a released address at its next tick.
func ReleaseIsolation(store IsolationStore, run Runner, addr string) ([]string, error) {
	if run == nil {
		run = RunPinned
	}
	var target string
	if addr != "all" {
		a, err := netip.ParseAddr(addr)
		if err != nil || a.Zone() != "" {
			return nil, fmt.Errorf("%q is not an IP address", addr)
		}
		target = a.Unmap().String()
	}
	var released []string
	err := store.withLock(false, func(dfd int) error {
		isos, err := loadIsolationsAt(dfd)
		if err != nil {
			return err
		}
		keep := []Isolation{}
		if target == "" {
			if _, err := run(context.Background(), PfctlBin, []string{"-a", PFAnchor, "-t", PFTable, "-T", "flush"}, nil); err != nil {
				return fmt.Errorf("pfctl flush: %w", err)
			}
			for _, iso := range isos {
				released = append(released, iso.Addr)
			}
		} else {
			if _, err := run(context.Background(), PfctlBin, []string{"-a", PFAnchor, "-t", PFTable, "-T", "delete", target}, nil); err != nil {
				return fmt.Errorf("pfctl delete: %w", err)
			}
			released = []string{target}
			for _, iso := range isos {
				if iso.Addr != target {
					keep = append(keep, iso)
				}
			}
		}
		return saveIsolationsAt(dfd, keep)
	})
	return released, err
}
