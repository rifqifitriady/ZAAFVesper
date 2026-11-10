package ebpf

import "fmt"

// requirements is what the kernel programs need; it ends every message that
// says the kernel refused them, so an operator sees what to check.
const requirements = "the eBPF source needs Linux 5.17 or later (x86-64; 6.0 or later on arm64) " +
	"built with BTF (CONFIG_DEBUG_INFO_BTF, /sys/kernel/btf/vmlinux), and root with CAP_BPF and CAP_PERFMON " +
	"(a privileged container)"

// refusedMessage explains a load failure that is not a missing BTF file.
func refusedMessage(detail string) string {
	return fmt.Sprintf("the kernel refused the core programs: %s; %s", detail, requirements)
}
