//go:build darwin

package response

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"regexp"
	"strings"
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

// FirewallName names ZAAFVesper's firewall objects (for the CLI).
const FirewallName = "pf anchor " + PFAnchor + ", table " + PFTable

// firewallKind prefixes firewall errors; firewallScope is said with every
// isolation.
const (
	firewallKind  = "pf"
	firewallScope = "pf blocks these addresses for the whole host, not only this process"
)

// pfRules is the anchor's whole ruleset: one table, two quick block rules.
// It is a constant: no event data is ever written into a pf rule; peers
// only enter the table, as addresses that net/netip parsed and re-printed.
const pfRules = "table <" + PFTable + "> persist\n" +
	"block drop quick from any to <" + PFTable + ">\n" +
	"block drop quick from <" + PFTable + "> to any\n"

// NeverBlockNetworks are networks isolate_process never blocks, whatever
// the configuration: Apple's 17.0.0.0/8 and 2620:149::/32 (software update,
// XProtect, notarization, push). Private RFC 1918 addresses can be isolated
// (owner decision 9 Nov 2026); protect your own servers with
// response.isolation_allow.
var NeverBlockNetworks = []netip.Prefix{netip.MustParsePrefix("17.0.0.0/8"), netip.MustParsePrefix("2620:149::/32")}

// neverBlockLabel names a NeverBlockNetworks network in a decision.
const neverBlockLabel = "Apple's network "

func defaultGateways(run Runner) func() ([]netip.Addr, error) { return routeGateways(run) }

func defaultResolvers() []netip.Addr { return resolvConfAddrs() }

// routeGateways is the default Config.Gateways: the gateway lines of
// `/sbin/route -n get default` and `/sbin/route -n get -inet6 default`
// (pinned, fixed argv). A family without a default route (exit 1, "not in
// table") is not an error; a command that cannot run, times out or answers
// anything else is.
func routeGateways(run Runner) func() ([]netip.Addr, error) {
	return func() ([]netip.Addr, error) {
		var out []netip.Addr
		for _, args := range [][]string{{"-n", "get", "default"}, {"-n", "get", "-inet6", "default"}} {
			b, err := run(context.Background(), RouteBin, args, nil)
			var ee *ExitError
			switch {
			case errors.As(err, &ee) && ee.Code == 1 && strings.Contains(ee.Output, "not in table"):
				continue // no default route for this family
			case err != nil:
				// A timeout, a crash or any other answer: the gateway is
				// unknown, so the caller refuses (fail closed).
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

// pfctl runs /sbin/pfctl with args through the Runner.
func (r *Responder) pfctl(args ...string) ([]byte, error) {
	return r.cfg.Runner(context.Background(), PfctlBin, args, nil)
}

var pfTokenRe = regexp.MustCompile(`Token : ([0-9]+)`)

// fwEnsure loads the anchor's constant ruleset and takes a pf enable
// reference (pfctl -E), once. Caller holds actMu.
func (r *Responder) fwEnsure() error {
	if r.fwLoaded {
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
		r.fwToken = string(m[1])
	}
	r.fwLoaded = true
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

// fwAdd puts the addresses into the anchor's table and drops their open
// states. The time to live is kept by Tick (pf tables have none).
func (r *Responder) fwAdd(items []fwItem) error {
	addrs := make([]string, len(items))
	for i, it := range items {
		addrs[i] = it.Addr.String()
	}
	if _, err := r.pfctl(append([]string{"-a", PFAnchor, "-t", PFTable, "-T", "add"}, addrs...)...); err != nil {
		return err
	}
	for _, it := range items {
		r.killStates(it.Addr)
	}
	return nil
}

// fwDelete removes addresses from the anchor's table.
func (r *Responder) fwDelete(addrs []string) error {
	_, err := r.pfctl(append([]string{"-a", PFAnchor, "-t", PFTable, "-T", "delete"}, addrs...)...)
	return err
}

// fwFlush flushes the anchor (rules and table) at start.
func (r *Responder) fwFlush() error {
	_, err := r.pfctl("-a", PFAnchor, "-F", "all")
	return err
}

// fwClose flushes the anchor and releases the pf enable reference.
func (r *Responder) fwClose() error {
	_, err := r.pfctl("-a", PFAnchor, "-F", "all")
	if r.fwToken != "" {
		if _, xerr := r.pfctl("-X", r.fwToken); xerr != nil {
			err = errors.Join(err, xerr)
		}
		r.fwToken = ""
	}
	r.fwLoaded = false
	return err
}

// fwWarn: pf is enabled by fwEnsure itself.
func (r *Responder) fwWarn() (string, bool) { return "", false }

// fwRelease removes addrs (all when nil) from the table, for the CLI.
func fwRelease(run Runner, addrs, _ []string) error {
	args := []string{"-a", PFAnchor, "-t", PFTable, "-T", "flush"}
	if addrs != nil {
		args = append([]string{"-a", PFAnchor, "-t", PFTable, "-T", "delete"}, addrs...)
	}
	_, err := run(context.Background(), PfctlBin, args, nil)
	return err
}
