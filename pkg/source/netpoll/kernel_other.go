//go:build !darwin

package netpoll

// platformKernel: socket polling is only implemented on macOS (Windows and
// Linux get network events from Sysmon).
func platformKernel() Kernel { return nil }
