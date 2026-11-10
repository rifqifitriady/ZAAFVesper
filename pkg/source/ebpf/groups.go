package ebpf

import (
	"sort"

	"github.com/rifqifitriady/ZAAFVesper/pkg/event"
)

// group is a set of kernel programs that together produce some canonical
// events. Only the groups some rule needs are loaded and attached, so an
// unused hook costs nothing. Groups other than "process" are optional: when
// the running kernel lacks a hook (for example a kernel built without
// CONFIG_SECURITY_PATH has no security_path_unlink), that group is skipped
// with a warning and the rest still runs.
type group struct {
	name     string
	events   []string
	programs []string
	required bool
}

var groups = []group{
	{name: "process", required: true,
		events:   []string{event.CreateProcess, event.TerminateProcess, event.Fork},
		programs: []string{"on_exec", "on_exit", "on_fork"}},
	{name: "file-open-create",
		events:   []string{event.OpenFile, event.CreateFile},
		programs: []string{"on_file_open"}},
	{name: "file-delete",
		events:   []string{event.DeleteFile},
		programs: []string{"on_unlink"}},
	{name: "file-rename",
		events:   []string{event.RenameFile},
		programs: []string{"on_rename"}},
	{name: "setuid",
		events:   []string{event.SetUID},
		programs: []string{"on_commit_creds"}},
	{name: "process-access",
		events: []string{event.Ptrace, event.OpenProcess},
		programs: []string{"on_enter_ptrace", "on_exit_ptrace", "on_enter_vm_readv", "on_exit_vm_readv",
			"on_enter_vm_writev", "on_exit_vm_writev", "on_ptrace_check"}},
	{name: "kernel-module",
		events: []string{event.DriverLoad},
		programs: []string{"on_enter_init_module", "on_enter_finit_module", "on_kernel_read_file",
			"on_kernel_load_data", "on_module_load"}},
	{name: "tcp",
		events:   []string{event.NetworkConnect, event.NetworkAccept},
		programs: []string{"on_tcp_v4_connect", "on_tcp_v6_connect", "on_inet_csk_accept"}},
	{name: "dns",
		events:   []string{event.DNSQuery},
		programs: []string{"on_udp_sendmsg", "on_udpv6_sendmsg"}},
}

// Supported returns the canonical events this source can produce, sorted.
func Supported() []string {
	var out []string
	for _, g := range groups {
		out = append(out, g.events...)
	}
	sort.Strings(out)
	return out
}

// plan returns the groups to load for a subscription (nil: every event)
// and whether OpenFile itself is wanted (the open hook always reports
// creations; plain opens only when a rule asks for OpenFile).
func plan(events []string) (use []group, wantOpen bool) {
	if events == nil {
		return groups, true
	}
	want := map[string]bool{}
	for _, n := range events {
		want[n] = true
	}
	for _, g := range groups {
		if g.required {
			use = append(use, g)
			continue
		}
		for _, n := range g.events {
			if want[n] {
				use = append(use, g)
				break
			}
		}
	}
	return use, want[event.OpenFile]
}
