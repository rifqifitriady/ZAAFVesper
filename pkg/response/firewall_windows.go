//go:build windows

package response

import (
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

// NeverBlockNetworks are networks isolate_process never blocks on Windows:
// the cloud platform addresses a virtual machine depends on that are not
// link-local (cloudPlatformNetworks: Azure's WireServer). Use
// response.isolation_allow for your own servers, load-balancer health
// checks and VPN gateways.
var NeverBlockNetworks = cloudPlatformNetworks

const neverBlockLabel = "cloud platform address "

func (r *Responder) fwEnsure() error {
	r.fwLoaded = true
	return nil
}

// isolatedWith returns the isolated addresses plus add, minus drop: the
// list the rules must hold after a change. Caller holds actMu.
func (r *Responder) isolatedWith(add []fwItem, drop []string) []string {
	gone := map[string]bool{}
	for _, a := range drop {
		gone[a] = true
	}
	var out []string
	for a := range r.isolated {
		if !gone[a] {
			out = append(out, a)
		}
	}
	for _, it := range add {
		out = append(out, it.Addr.Unmap().String())
	}
	return out
}

// fwAdd puts the addresses into ZAAFVesper's two rules (one per
// direction), which list every isolated address: two netsh runs, however
// many addresses are isolated. Windows rules have no time to live: the
// isolation upkeep (Tick, on the worker) removes an address at its expiry,
// and StartResponse deletes every ZAAFVesper rule an earlier run left.
func (r *Responder) fwAdd(items []fwItem) error {
	return netshSync(r.cfg.Runner, NetshBin, r.isolatedWith(items, nil))
}

// fwDelete removes addrs from the rules (the rest of the isolated
// addresses stay in them, without a gap); no address left deletes them.
func (r *Responder) fwDelete(addrs []string) error {
	return netshSync(r.cfg.Runner, NetshBin, r.isolatedWith(nil, addrs))
}

// fwFlush deletes every rule named ZAAFVesper-isolation (nothing else).
func (r *Responder) fwFlush() error {
	r.fwLoaded = false
	return netshDeleteAll(r.cfg.Runner, NetshBin)
}

func (r *Responder) fwClose() error { return r.fwFlush() }

// fwRelease removes addrs (all when nil), for the CLI: the rules are set
// to keep, the addresses that stay isolated in the state file. A running
// sensor that isolated another address meanwhile puts it back at its next
// state save (the CLI's release shows up there as a change).
func fwRelease(run Runner, addrs, keep []string) error {
	if addrs == nil {
		return netshDeleteAll(run, NetshBin)
	}
	return netshSync(run, NetshBin, keep)
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
