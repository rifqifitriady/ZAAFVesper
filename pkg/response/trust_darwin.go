//go:build darwin

package response

import "github.com/rifqifitriady/ZAAFVesper/pkg/event"

// trustedWriter returns why the writer of a persistence item is trusted
// (remove_persistence then refuses), or "" when it is untrusted: no verified
// identity, or an Apple tool (cp, sh) in an untrusted chain (untrustedChain;
// owner decision 9 Nov 2026).
func trustedWriter(p *event.Proc) string {
	switch {
	case p.IsPlatform && !untrustedChain(p):
		return "written by an Apple platform binary whose parent and ancestors are trusted"
	case !p.IsPlatform && verifiedVendor(p):
		return "written by a process with a verified Developer ID or App Store identity"
	}
	return ""
}
