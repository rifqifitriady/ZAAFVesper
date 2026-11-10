package response

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"math"
	"net/netip"
	"sort"
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

// cloudPlatformNetworks are cloud platform addresses outside the
// link-local range that a virtual machine needs (never blocked on Linux and
// Windows): Azure's WireServer 168.63.129.16 (DHCP, DNS, health probes,
// the VM agent). The instance metadata services (169.254.169.254) are
// link-local and never blocked anyway.
var cloudPlatformNetworks = []netip.Prefix{netip.MustParsePrefix("168.63.129.16/32")}

// Windows Firewall objects of isolate_process: two rules, one per
// direction, that both carry this name and list every isolated address in
// one remoteip value. Only rules with this exact name are ever added,
// changed, deleted or listed (never "netsh advfirewall reset").
const WinRuleName = "ZAAFVesper-isolation"

// netshRemoteList is the remoteip value for addrs: each parsed and
// re-printed by net/netip (anything else is skipped), unmapped, without
// duplicates, sorted, comma-separated. "" when none is left.
func netshRemoteList(addrs []string) string {
	seen := map[netip.Addr]bool{}
	var list []netip.Addr
	for _, s := range addrs {
		a, err := netip.ParseAddr(s)
		if err != nil || a.Zone() != "" {
			continue
		}
		if a = a.Unmap(); !seen[a] {
			seen[a] = true
			list = append(list, a)
		}
	}
	sort.Slice(list, func(i, j int) bool { return list[i].Less(list[j]) })
	out := make([]string, len(list))
	for i, a := range list {
		out[i] = a.String()
	}
	return strings.Join(out, ",")
}

// netshAddArgs is the fixed argument vector adding the block rule of one
// direction for the remoteip list.
func netshAddArgs(list, dir string) []string {
	return []string{"advfirewall", "firewall", "add", "rule", "name=" + WinRuleName, "dir=" + dir,
		"action=block", "enable=yes", "profile=any", "remoteip=" + list}
}

// netshSetArgs replaces, in place, the remoteip list of the rule (or
// rules) of one direction: the change is atomic for that rule, so no
// address that stays isolated is ever unblocked while the list changes.
func netshSetArgs(list, dir string) []string {
	return []string{"advfirewall", "firewall", "set", "rule", "name=" + WinRuleName, "dir=" + dir,
		"new", "action=block", "enable=yes", "profile=any", "remoteip=" + list}
}

// netshDeleteArgs deletes every ZAAFVesper rule.
var netshDeleteArgs = []string{"advfirewall", "firewall", "delete", "rule", "name=" + WinRuleName}

// netshShowArgs lists ZAAFVesper's rules of one direction ("" for both).
func netshShowArgs(dir string) []string {
	args := []string{"advfirewall", "firewall", "show", "rule", "name=" + WinRuleName}
	if dir != "" {
		args = append(args, "dir="+dir)
	}
	return append(args, "verbose")
}

// netshDeleteAll deletes every ZAAFVesper rule. netsh answers "No rules
// match" with a non-zero exit, in the system's language, so a failed
// delete is checked with a listing: it is an error only when a rule is
// still listed.
func netshDeleteAll(run Runner, bin string) error {
	_, err := run(context.Background(), bin, netshDeleteArgs, nil)
	if err == nil {
		return nil
	}
	_, serr := run(context.Background(), bin, netshShowArgs(""), nil)
	var ee *ExitError
	switch {
	case errors.As(serr, &ee):
		return nil // no ZAAFVesper rule at all
	case serr != nil:
		return fmt.Errorf("%v; listing the rules failed: %v", err, serr)
	}
	return err
}

// netshSync makes ZAAFVesper's rules block exactly addrs, with at most two
// netsh runs when nothing goes wrong (one per direction), whatever the
// number of addresses: the rule of each direction gets the whole list in
// place (set rule); a direction without a rule gets one (add rule, after a
// listing shows none); no address left deletes the rules.
func netshSync(run Runner, bin string, addrs []string) error {
	list := netshRemoteList(addrs)
	if list == "" {
		return netshDeleteAll(run, bin)
	}
	for _, dir := range []string{"out", "in"} {
		_, err := run(context.Background(), bin, netshSetArgs(list, dir), nil)
		if err == nil {
			continue
		}
		_, serr := run(context.Background(), bin, netshShowArgs(dir), nil)
		var ee *ExitError
		switch {
		case errors.As(serr, &ee): // no rule of this direction yet
			if _, aerr := run(context.Background(), bin, netshAddArgs(list, dir), nil); aerr != nil {
				return fmt.Errorf("add rule %s: %w", dir, aerr)
			}
		case serr != nil:
			return fmt.Errorf("set rule %s: %v; listing the rules failed: %v", dir, err, serr)
		default:
			return fmt.Errorf("set rule %s: %w", dir, err) // the rule exists and kept its old list
		}
	}
	return nil
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
