//go:build windows

package response

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

// FirewallName names ZAAFVesper's firewall objects (for the CLI).
const FirewallName = "Windows Firewall rules named " + WinRuleName

// firewallKind prefixes firewall errors; firewallScope is said with every
// isolation.
const (
	firewallKind  = "netsh"
	firewallScope = "Windows Firewall blocks these addresses for the whole host, not only this process; connections already open are not cut"
)

// NeverBlockNetworks: none beyond the built-in set; use
// response.isolation_allow for your own servers.
var NeverBlockNetworks []netip.Prefix

const neverBlockLabel = "never-block network "

func (r *Responder) netsh(args []string) ([]byte, error) {
	return r.cfg.Runner(context.Background(), NetshBin, args, nil)
}

// netshDelete deletes the rules of a (every ZAAFVesper rule when a is
// invalid). netsh answers "No rules match" with a non-zero exit, in the
// system's language, so a failed delete is checked with a listing: it is an
// error only when a rule for a (any rule, for all) is still listed.
func netshDelete(run Runner, a netip.Addr) error {
	_, err := run(context.Background(), NetshBin, netshDeleteArgs(a), nil)
	if err == nil {
		return nil
	}
	out, serr := run(context.Background(), NetshBin, netshShowArgs, nil)
	var ee *ExitError
	switch {
	case errors.As(serr, &ee):
		return nil // no ZAAFVesper rule at all
	case serr != nil:
		return fmt.Errorf("%v; listing the rules failed: %v", err, serr)
	case !a.IsValid() || netshListsAddr(string(out), a):
		return err
	}
	return nil
}

func (r *Responder) fwEnsure() error {
	r.fwLoaded = true
	return nil
}

// fwAdd adds an outbound and an inbound block rule per address (after
// removing older rules of the same address, so a refresh leaves one pair).
// Windows rules have no time to live: Tick deletes them at expiry, and
// StartResponse deletes every ZAAFVesper rule an earlier run left.
func (r *Responder) fwAdd(items []fwItem) error {
	for _, it := range items {
		_ = netshDelete(r.cfg.Runner, it.Addr)
		for _, dir := range []string{"out", "in"} {
			if _, err := r.netsh(netshAddArgs(it.Addr, dir)); err != nil {
				_ = netshDelete(r.cfg.Runner, it.Addr)
				return fmt.Errorf("add rule %s %s: %w", dir, it.Addr, err)
			}
		}
	}
	return nil
}

func (r *Responder) fwDelete(addrs []string) error {
	var errs []error
	for _, s := range addrs {
		a, err := netip.ParseAddr(s)
		if err != nil || a.Zone() != "" {
			continue
		}
		if err := netshDelete(r.cfg.Runner, a); err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", a, err))
		}
	}
	return errors.Join(errs...)
}

// fwFlush deletes every rule named ZAAFVesper-isolation (nothing else).
func (r *Responder) fwFlush() error {
	r.fwLoaded = false
	return netshDelete(r.cfg.Runner, netip.Addr{})
}

func (r *Responder) fwClose() error { return r.fwFlush() }

// fwRelease removes addrs (all when nil), for the CLI.
func fwRelease(run Runner, addrs []string) error {
	if addrs == nil {
		return netshDelete(run, netip.Addr{})
	}
	var errs []error
	for _, s := range addrs {
		a, err := netip.ParseAddr(s)
		if err != nil {
			continue
		}
		if err := netshDelete(run, a); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// firewallProfiles are the Windows Firewall profiles and their registry
// key names (policy first, then the local setting).
var firewallProfiles = []struct{ name, key string }{
	{"domain", "DomainProfile"}, {"private", "StandardProfile"}, {"public", "PublicProfile"},
}

// fwWarn reports profiles whose firewall is off (a block rule does nothing
// there); all off makes the isolation partial.
func (r *Responder) fwWarn() (string, bool) {
	var off []string
	for _, p := range firewallProfiles {
		if !firewallEnabled(p.key) {
			off = append(off, p.name)
		}
	}
	if len(off) == 0 {
		return "", false
	}
	return "Windows Firewall is off for the " + strings.Join(off, ", ") + " profile(s): the rules do nothing there", len(off) == len(firewallProfiles)
}

func firewallEnabled(profile string) bool {
	for _, base := range []string{`SOFTWARE\Policies\Microsoft\WindowsFirewall\`, `SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\`} {
		k, err := registry.OpenKey(registry.LOCAL_MACHINE, base+profile, registry.QUERY_VALUE)
		if err != nil {
			continue
		}
		v, _, err := k.GetIntegerValue("EnableFirewall")
		k.Close()
		if err == nil {
			return v != 0
		}
	}
	return true // not configured: Windows defaults to on
}

// adapterAddrs walks GetAdaptersAddresses (gateways and DNS servers
// included).
func adapterAddrs() (gw, dns []netip.Addr, err error) {
	var buf []byte
	size := uint32(16 << 10)
	for i := 0; i < 4; i++ {
		buf = make([]byte, size)
		err = windows.GetAdaptersAddresses(windows.AF_UNSPEC, windows.GAA_FLAG_INCLUDE_GATEWAYS|windows.GAA_FLAG_SKIP_MULTICAST|windows.GAA_FLAG_SKIP_ANYCAST,
			0, (*windows.IpAdapterAddresses)(unsafe.Pointer(&buf[0])), &size)
		if err != windows.ERROR_BUFFER_OVERFLOW {
			break
		}
	}
	if err != nil {
		return nil, nil, err
	}
	for aa := (*windows.IpAdapterAddresses)(unsafe.Pointer(&buf[0])); aa != nil; aa = aa.Next {
		for g := aa.FirstGatewayAddress; g != nil; g = g.Next {
			if a, ok := sockAddr(g.Address); ok {
				gw = append(gw, a)
			}
		}
		for d := aa.FirstDnsServerAddress; d != nil; d = d.Next {
			if a, ok := sockAddr(d.Address); ok {
				dns = append(dns, a)
			}
		}
	}
	return gw, dns, nil
}

func sockAddr(s windows.SocketAddress) (netip.Addr, bool) {
	if s.Sockaddr == nil {
		return netip.Addr{}, false
	}
	sa, err := s.Sockaddr.Sockaddr()
	if err != nil {
		return netip.Addr{}, false
	}
	switch v := sa.(type) {
	case *syscall.SockaddrInet4:
		return netip.AddrFrom4(v.Addr), true
	case *syscall.SockaddrInet6:
		return netip.AddrFrom16(v.Addr).Unmap(), true
	}
	return netip.Addr{}, false
}

// defaultGateways are every adapter's gateways (GetAdaptersAddresses); a
// failed call refuses the isolation.
func defaultGateways(Runner) func() ([]netip.Addr, error) {
	return func() ([]netip.Addr, error) {
		gw, _, err := adapterAddrs()
		return gw, err
	}
}

// defaultResolvers are every adapter's DNS servers.
func defaultResolvers() []netip.Addr {
	_, dns, _ := adapterAddrs()
	return dns
}
