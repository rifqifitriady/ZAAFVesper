//go:build zaafvesper_validate

package response

// KernelIdentity reads pid's identity from the kernel exactly as the
// responder does right before it acts (kernel unique id or start stamp,
// start time, executable, code-signing flags). It exists for the live
// validation harness (`zaafvesper validate-response`, v0.3 workstream D),
// which builds its test events from it because no event source runs there.
func KernelIdentity(pid int32) (Identity, error) { return identify(pid) }

// PlatformBinary reports whether the identity's code-signing flags carry
// CS_PLATFORM_BINARY (macOS; always false elsewhere).
func (id Identity) PlatformBinary() bool { return id.CSKnown && id.CSFlags&csPlatformBinary != 0 }
