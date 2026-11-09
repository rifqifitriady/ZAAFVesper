//go:build linux

package response

import (
	"context"
	"errors"
	"net/netip"
	"os"
	"strings"
)

// FirewallName names ZAAFVesper's firewall objects (for the CLI).
const FirewallName = "nftables table inet " + NftTable + " (sets " + nftSet4 + ", " + nftSet6 + ")"

// firewallKind prefixes firewall errors; firewallScope is said with every
// isolation.
const (
	firewallKind  = "nft"
	firewallScope = "nftables drops these addresses for the whole host (also forwarded container traffic), not only this process"
)

// NeverBlockNetworks: Linux has no vendor network that must stay reachable;
// use response.isolation_allow for your own servers.
var NeverBlockNetworks []netip.Prefix

const neverBlockLabel = "never-block network "

// nft runs /usr/sbin/nft -f - with script on stdin.
func (r *Responder) nft(script string) error {
	_, err := r.cfg.Runner(context.Background(), NftBin, []string{"-f", "-"}, []byte(script))
	return err
}

// fwEnsure creates ZAAFVesper's table (atomically replacing a leftover one),
// once. Caller holds actMu.
func (r *Responder) fwEnsure() error {
	if r.fwLoaded {
		return nil
	}
	if err := r.nft(nftReplaceTable); err != nil {
		return err
	}
	r.fwLoaded = true
	return nil
}

func (r *Responder) fwAdd(items []fwItem) error { return r.nft(nftAddScript(items)) }

func (r *Responder) fwDelete(addrs []string) error {
	s := nftDeleteScript(addrs)
	if s == "" || !r.fwLoaded {
		return nil
	}
	return r.nft(s)
}

// fwFlush removes ZAAFVesper's table at start (nothing else is touched).
func (r *Responder) fwFlush() error {
	r.fwLoaded = false
	return r.nft(nftDropTable)
}

func (r *Responder) fwClose() error { return r.fwFlush() }

func (r *Responder) fwWarn() (string, bool) { return "", false }

// fwRelease removes addrs (all when nil) from the sets, for the CLI. A
// missing table (the sensor is not running) has nothing to release.
func fwRelease(run Runner, addrs []string) error {
	_, err := run(context.Background(), NftBin, []string{"list", "table", "inet", NftTable}, nil)
	var ee *ExitError
	if errors.As(err, &ee) && strings.Contains(ee.Output, "No such file or directory") {
		return nil
	}
	if err != nil {
		return err
	}
	script := nftFlushSets
	if addrs != nil {
		script = nftDeleteScript(addrs)
	}
	if script == "" {
		return nil
	}
	_, err = run(context.Background(), NftBin, []string{"-f", "-"}, []byte(script))
	return err
}

// defaultGateways reads every gateway of the IPv4 and IPv6 routing tables
// (/proc/net/route, /proc/net/ipv6_route). An unreadable IPv4 table is an
// error (the isolation is then refused); a host without IPv6 has no
// ipv6_route.
func defaultGateways(Runner) func() ([]netip.Addr, error) {
	return func() ([]netip.Addr, error) {
		b, err := os.ReadFile("/proc/net/route")
		if err != nil {
			return nil, err
		}
		out := parseProcNetRoute(b)
		if b6, err := os.ReadFile("/proc/net/ipv6_route"); err == nil {
			out = append(out, parseProcNetIPv6Route(b6)...)
		} else if !errors.Is(err, os.ErrNotExist) {
			return nil, err
		}
		return out, nil
	}
}

// defaultResolvers are the nameservers of /etc/resolv.conf and, behind
// systemd-resolved's stub, of /run/systemd/resolve/resolv.conf.
func defaultResolvers() []netip.Addr {
	var out []netip.Addr
	for _, f := range []string{"/etc/resolv.conf", "/run/systemd/resolve/resolv.conf"} {
		if b, err := os.ReadFile(f); err == nil {
			out = append(out, parseResolvConf(b)...)
		}
	}
	return out
}
