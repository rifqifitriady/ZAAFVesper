package response

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sort"
	"strings"
	"time"

	"github.com/rifqifitriady/ZAAFVesper/pkg/event"
)

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

// fwItem is one address for the firewall and how long it stays blocked
// (nftables keeps that time in the kernel too, so a block outlives no
// crashed sensor by more than its time to live).
type fwItem struct {
	Addr netip.Addr
	TTL  time.Duration
}

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

// remoteAddrs returns the remote address of a network event, following the
// netpoll (Sysmon) convention of event.Net: outbound src=local dst=remote,
// inbound src=remote dst=local, listen dst=local (no peer).
func remoteAddrs(n *event.Net) []string {
	if n == nil {
		return nil
	}
	switch n.Direction {
	case "outbound":
		return []string{n.DstIP}
	case "inbound":
		return []string{n.SrcIP}
	}
	return nil
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

// blockable returns why a must never be blocked, or "": invalid, scoped,
// loopback, unspecified, multicast, broadcast, link-local, this host's own
// address, a default gateway or DNS resolver of this host (never), a
// NeverBlockNetworks network (Apple's 17.0.0.0/8 on macOS), or inside the
// management allow-list. never holds the host's
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
			return neverBlockLabel + p.String()
		}
	}
	for _, p := range r.cfg.IsolationAllow {
		if p.Contains(a) {
			return "management allow-list " + p.String()
		}
	}
	return ""
}

// neverBlock returns this host's own addresses, default gateways and DNS
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
		never[a.WithZone("").Unmap()] = "a default gateway of this host"
	}
	for a := range r.resolvers() {
		never[a] = "a DNS resolver of this host"
	}
	return never, nil
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
// or of its parent (target parent) in ZAAFVesper's firewall objects (pf
// anchor, nftables table, Windows Firewall rules) for Config.IsolationTTL.
// The peers are the event's own (a NetworkConnect or NetworkAccept) and
// those Observe saw for the same process in the last ten minutes. Guard
// rails: the process identity rules of kill (protected pids, paths, names,
// platform binaries, seeded or unverified identity, signing category, a
// platform flag that must be known); never loopback, link-local, multicast,
// this host's addresses, its default gateways and DNS resolvers, Apple's
// 17.0.0.0/8 or the management allow-list; at most 16 addresses per action
// and 256 in all; the file/network budget; dry-run. The firewall filters by
// address, not by process: every program on this host loses those peers
// until the isolation expires or is
// released. Connections the process opens to new peers later are not
// blocked.
func (r *Responder) IsolateProcess(e *event.Event, target, rule, reason string) error {
	var run func() error
	run = func() error {
		key := ActionIsolateProcess + "|" + rule + "|" + target
		if e != nil && e.Proc != nil {
			key += "|" + procKey(e.Proc)
		}
		return r.retryOnLimit(key, rule, reason, r.isolateProcess(e, target, rule, reason), run)
	}
	return run()
}

func (r *Responder) isolateProcess(e *event.Event, target, rule, reason string) error {
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
		note := fmt.Sprintf("%s for %s; %s%s",
			strings.Join(addrs, ", "), r.cfg.IsolationTTL, firewallScope, skippedNote(skipped))
		if r.cfg.DryRun {
			return result{OutcomeDryRun, "would block " + note, nil}
		}
		if err := r.fwEnsure(); err != nil {
			return result{OutcomeError, firewallKind + ": " + err.Error(), fmt.Errorf("response: isolate: %w", err)}
		}
		isos := make([]*Isolation, len(block))
		items := make([]fwItem, len(block))
		for i, a := range block {
			iso := &Isolation{Addr: a.String(), Added: now.UTC(), Expires: now.Add(r.cfg.IsolationTTL).UTC(),
				Rule: rule, Reason: reason, PID: p.PID, Exe: p.Exe}
			if old, ok := r.isolated[iso.Addr]; ok && old.Expires.After(iso.Expires) {
				iso.Expires = old.Expires
			}
			isos[i], items[i] = iso, fwItem{Addr: a, TTL: iso.Expires.Sub(now)}
		}
		if err := r.fwAdd(items); err != nil {
			return result{OutcomeError, firewallKind + " add: " + err.Error(), fmt.Errorf("response: isolate: %w", err)}
		}
		for _, iso := range isos {
			r.isolated[iso.Addr] = iso
		}
		if err := r.saveIsolations(); err != nil {
			note += "; state file not written: " + err.Error()
		}
		if warn, partial := r.fwWarn(); warn != "" {
			note += "; " + warn
			if partial {
				return result{OutcomePartial, "rules added for " + note + " (release: zaafvesper isolation release <addr>|all)", nil}
			}
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

// StartResponse prepares the actions at sensor start: ZAAFVesper's
// firewall objects (pf anchor, nftables table, Windows Firewall rules) are
// flushed (an earlier run that did not shut down cleanly may have left
// blocks) and the isolation state is cleared. Dry-run touches nothing.
func (r *Responder) StartResponse() error {
	if r.cfg.DryRun {
		return nil
	}
	r.actMu.Lock()
	defer r.actMu.Unlock()
	err := r.fwFlush()
	r.isolated, r.saved = map[string]*Isolation{}, nil
	if fileOpsSupported {
		if serr := (IsolationStore{Dir: r.cfg.StateDir, RequireRootOwned: r.cfg.RequireRootOwned}).Save([]Isolation{}); serr != nil {
			err = errors.Join(err, serr)
		}
	}
	return err
}

// Tick runs the timed parts of the actions: suspended processes whose time
// is over are resumed, and the isolation upkeep (expiry, the never-block
// recheck, the pick-up of releases done with the CLI) is handed to the
// slow-action worker. run calls it every 2 seconds, on the event loop, so
// Tick never waits for a slow action and never starts a process itself
// (netsh, nft, pfctl, route): a Windows expiry once ran netsh per address
// here, up to 256 times with a 10 s timeout each.
func (r *Responder) Tick(now time.Time) {
	r.mu.Lock()
	r.tickSuspended(now)
	r.mu.Unlock()
	r.tickRetries(now)
	if !r.actMu.TryLock() {
		return // a slow action runs; the upkeep waits for the next tick
	}
	due := len(r.isolated) > 0
	r.actMu.Unlock()
	if !due || !r.queueHasRoom() || !r.upkeepQueued.CompareAndSwap(false, true) {
		return
	}
	if !r.Go(func() {
		defer r.upkeepQueued.Store(false)
		r.actMu.Lock()
		defer r.actMu.Unlock()
		r.isolationUpkeep(now)
	}) {
		r.upkeepQueued.Store(false)
	}
}

// isolationUpkeep releases the isolations that are now never-block or
// whose time to live is over, in one firewall call, and saves the state
// (which picks up releases done with the CLI). It runs on the worker (or
// inline without one). Caller holds actMu.
func (r *Responder) isolationUpkeep(now time.Time) {
	r.recheckNeverBlock(now)
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
	err := r.fwDelete(expired)
	for _, a := range expired {
		iso := r.isolated[a]
		delete(r.isolated, a)
		d := Decision{Time: now, Action: ActionIsolateProcess, PID: iso.PID, Target: TargetProcess, Exe: iso.Exe,
			Reason: iso.Reason, Outcome: OutcomeReleased, Detail: a + " expired"}
		if err != nil {
			d.Outcome, d.Detail = OutcomeError, a+" expired, but the "+firewallKind+" delete failed: "+err.Error()
		}
		r.mu.Lock()
		r.logLocked(d)
		r.mu.Unlock()
	}
	_ = r.saveIsolations()
}

// Close ends the response at a clean shutdown, quickly enough for the
// service manager's exit timeout: every suspended process is resumed
// first, then the worker stops (the action running now finishes, queued
// ones are dropped), ZAAFVesper's firewall objects are flushed (macOS: the
// pf enable reference is released too) and the isolation state cleared.
func (r *Responder) Close() error {
	r.ResumeAll()
	r.mu.Lock()
	r.retries = map[string]*retryEntry{} // no retry after shutdown
	r.mu.Unlock()
	r.stopWorker(true)
	if r.cfg.DryRun {
		return nil
	}
	r.actMu.Lock()
	defer r.actMu.Unlock()
	err := r.fwClose()
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

var errUnsupportedState = errors.New("the isolation state is not implemented on this platform")

// IsolationStore is the isolation state file shared by the sensor and the
// CLI (`zaafvesper isolation list|release`), in a root-only directory.
type IsolationStore struct {
	Dir              string
	RequireRootOwned bool
}

func (s IsolationStore) withLock(create bool, f func(dirfd int) error) error {
	if !fileOpsSupported {
		return errUnsupportedState
	}
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
// deleted from the firewall again, which is harmless when the CLI already
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
				_ = r.fwDelete(gone)
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
// ZAAFVesper's firewall objects and from the state file, for `zaafvesper isolation release`.
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
			if err := fwRelease(run, nil, nil); err != nil {
				return fmt.Errorf("%s flush: %w", firewallKind, err)
			}
			for _, iso := range isos {
				released = append(released, iso.Addr)
			}
		} else {
			var rest []string
			for _, iso := range isos {
				if iso.Addr != target {
					keep = append(keep, iso)
					rest = append(rest, iso.Addr)
				}
			}
			if err := fwRelease(run, []string{target}, rest); err != nil {
				return fmt.Errorf("%s delete: %w", firewallKind, err)
			}
			released = []string{target}
		}
		return saveIsolationsAt(dfd, keep)
	})
	return released, err
}

// neverRecheckEvery is how often isolated addresses are checked again
// against the never-block set (the host may have moved to a network where
// one of them is now the gateway or a DNS resolver).
const neverRecheckEvery = time.Minute

// recheckNeverBlock releases every isolated address that is now in the
// never-block set (a new gateway or resolver), at most once a minute. A
// lookup that fails changes nothing. Caller holds actMu.
func (r *Responder) recheckNeverBlock(now time.Time) {
	if len(r.isolated) == 0 || now.Sub(r.lastNeverCheck) < neverRecheckEvery {
		return
	}
	r.lastNeverCheck = now
	never, err := r.neverBlock()
	if err != nil {
		return
	}
	var release []string
	for a := range r.isolated {
		if ip, err := netip.ParseAddr(a); err == nil && r.blockable(ip, never) != "" {
			release = append(release, a)
		}
	}
	if len(release) == 0 {
		return
	}
	sort.Slice(release, func(i, j int) bool { return addrLess(release[i], release[j]) })
	err = r.fwDelete(release)
	for _, a := range release {
		iso := r.isolated[a]
		ip, _ := netip.ParseAddr(a)
		d := Decision{Time: now, Action: ActionIsolateProcess, PID: iso.PID, Target: TargetProcess, Exe: iso.Exe,
			Reason: iso.Reason, Outcome: OutcomeReleased, Detail: a + " released: now " + r.blockable(ip, never)}
		if err != nil {
			d.Outcome, d.Detail = OutcomeError, a+" is now never-block, but the "+firewallKind+" delete failed: "+err.Error()
		} else {
			delete(r.isolated, a)
		}
		r.mu.Lock()
		r.logLocked(d)
		r.mu.Unlock()
	}
	_ = r.saveIsolations()
}
