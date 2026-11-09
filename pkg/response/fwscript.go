package response

import (
	"encoding/hex"
	"fmt"
	"math"
	"net/netip"
	"strings"
	"time"
)

// This file holds the platform-neutral parts of the Linux and Windows
// firewall back ends (script and argument builders, route and resolver
// parsers), so that they are tested on every platform.

// nftables objects of isolate_process on Linux: one table owned by
// ZAAFVesper. Nothing else of the host's ruleset is ever read or changed
// (never "flush ruleset").
const (
	NftTable = "zaafvesper" // family inet
	nftSet4  = "isolated4"
	nftSet6  = "isolated6"
)

// nftRuleset is the table's whole ruleset, a constant: no event data is
// ever written into it. A drop in this table's base chains is final for
// the packet, whatever accept other tables (ufw, docker, firewalld) say,
// and it applies to packets of connections already open. The sets carry a
// kernel timeout per element, so a block ends at its time to live even if
// the sensor is gone.
const nftRuleset = `table inet zaafvesper {
	set isolated4 { type ipv4_addr; flags timeout; }
	set isolated6 { type ipv6_addr; flags timeout; }
	chain output {
		type filter hook output priority -10; policy accept;
		ip daddr @isolated4 drop
		ip6 daddr @isolated6 drop
	}
	chain input {
		type filter hook input priority -10; policy accept;
		ip saddr @isolated4 drop
		ip6 saddr @isolated6 drop
	}
	chain forward {
		type filter hook forward priority -10; policy accept;
		ip daddr @isolated4 drop
		ip saddr @isolated4 drop
		ip6 daddr @isolated6 drop
		ip6 saddr @isolated6 drop
	}
}
`

// nftReplaceTable recreates the table atomically (the "add, delete, add"
// idiom works whether or not it exists).
const nftReplaceTable = "table inet zaafvesper\ndelete table inet zaafvesper\n" + nftRuleset

// nftDropTable removes the table whether or not it exists.
const nftDropTable = "table inet zaafvesper\ndelete table inet zaafvesper\n"

func nftSet(a netip.Addr) string {
	if a.Is4() {
		return nftSet4
	}
	return nftSet6
}

// nftAddScript sets each address with its time to live (whole seconds,
// at least 1). "add, delete, add" refreshes the timeout of an element that
// is already there. Only addresses parsed and re-printed by net/netip enter
// the script.
func nftAddScript(items []fwItem) string {
	var b strings.Builder
	for _, it := range items {
		a := it.Addr.Unmap()
		secs := int64(math.Ceil(it.TTL.Seconds()))
		if secs < 1 {
			secs = 1
		}
		set := nftSet(a)
		fmt.Fprintf(&b, "add element inet %s %s { %s }\n", NftTable, set, a)
		fmt.Fprintf(&b, "delete element inet %s %s { %s }\n", NftTable, set, a)
		fmt.Fprintf(&b, "add element inet %s %s { %s timeout %ds }\n", NftTable, set, a, secs)
	}
	return b.String()
}

// nftDeleteScript removes each address, whether or not the kernel already
// expired it ("add, delete"). Strings that are not addresses are skipped.
func nftDeleteScript(addrs []string) string {
	var b strings.Builder
	for _, s := range addrs {
		a, err := netip.ParseAddr(s)
		if err != nil || a.Zone() != "" {
			continue
		}
		a = a.Unmap()
		set := nftSet(a)
		fmt.Fprintf(&b, "add element inet %s %s { %s }\n", NftTable, set, a)
		fmt.Fprintf(&b, "delete element inet %s %s { %s }\n", NftTable, set, a)
	}
	return b.String()
}

// nftFlushSets empties both sets (zaafvesper isolation release all).
const nftFlushSets = "flush set inet zaafvesper isolated4\nflush set inet zaafvesper isolated6\n"

// Windows Firewall objects of isolate_process: rules that all carry this
// name, one per address and direction. Only rules with this exact name are
// ever added, deleted or listed (never "netsh advfirewall reset").
const WinRuleName = "ZAAFVesper-isolation"

// netshAddArgs is the fixed argument vector adding one block rule.
func netshAddArgs(a netip.Addr, dir string) []string {
	return []string{"advfirewall", "firewall", "add", "rule", "name=" + WinRuleName, "dir=" + dir,
		"action=block", "enable=yes", "profile=any", "remoteip=" + a.Unmap().String()}
}

// netshDeleteArgs deletes the rules of one address (both directions), or
// every ZAAFVesper rule when a is invalid.
func netshDeleteArgs(a netip.Addr) []string {
	args := []string{"advfirewall", "firewall", "delete", "rule", "name=" + WinRuleName}
	if a.IsValid() {
		args = append(args, "remoteip="+a.Unmap().String())
	}
	return args
}

// netshShowArgs lists ZAAFVesper's rules.
var netshShowArgs = []string{"advfirewall", "firewall", "show", "rule", "name=" + WinRuleName, "verbose"}

// netshListsAddr reports whether `netsh ... show rule` output names a as a
// remote address ("RemoteIP: 192.0.2.7/32"; the label is localized, the
// address is not).
func netshListsAddr(out string, a netip.Addr) bool {
	a = a.Unmap()
	for _, f := range strings.FieldsFunc(out, func(r rune) bool { return r == ' ' || r == '\t' || r == '\r' || r == '\n' || r == ',' }) {
		f = strings.TrimSuffix(strings.TrimSuffix(f, "/32"), "/128")
		if x, err := netip.ParseAddr(f); err == nil && x.Unmap() == a {
			return true
		}
	}
	return false
}

// parseProcNetRoute returns the gateways of /proc/net/route (every route
// with RTF_GATEWAY; addresses are little-endian hex).
func parseProcNetRoute(b []byte) []netip.Addr {
	var out []netip.Addr
	for i, line := range strings.Split(string(b), "\n") {
		f := strings.Fields(line)
		if i == 0 || len(f) < 4 {
			continue
		}
		var flags uint64
		if _, err := fmt.Sscanf(f[3], "%x", &flags); err != nil || flags&0x2 == 0 {
			continue
		}
		raw, err := hex.DecodeString(f[2])
		if err != nil || len(raw) != 4 {
			continue
		}
		a := netip.AddrFrom4([4]byte{raw[3], raw[2], raw[1], raw[0]})
		if !a.IsUnspecified() {
			out = append(out, a)
		}
	}
	return out
}

// parseProcNetIPv6Route returns the next hops of /proc/net/ipv6_route
// (field 5, 32 hex digits, network order).
func parseProcNetIPv6Route(b []byte) []netip.Addr {
	var out []netip.Addr
	for _, line := range strings.Split(string(b), "\n") {
		f := strings.Fields(line)
		if len(f) < 10 {
			continue
		}
		raw, err := hex.DecodeString(f[4])
		if err != nil || len(raw) != 16 {
			continue
		}
		a := netip.AddrFrom16([16]byte(raw))
		if !a.IsUnspecified() {
			out = append(out, a)
		}
	}
	return out
}

// parseResolvConf returns the nameserver addresses of a resolv.conf.
func parseResolvConf(b []byte) []netip.Addr {
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

// ttlSeconds is a time to live in whole seconds for a log line.
func ttlSeconds(d time.Duration) int64 { return int64(math.Ceil(d.Seconds())) }
