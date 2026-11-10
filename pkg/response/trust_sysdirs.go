//go:build linux || windows

package response

import "github.com/rifqifitriady/ZAAFVesper/pkg/event"

// trustedWriter returns why the writer of a persistence item is trusted
// (remove_persistence then refuses), or "" when it is untrusted. Linux and
// Windows have no platform-binary flag, so a program counts as a system
// program when it runs from a directory only an administrator can write
// (systemImage: /usr, /bin, /opt...; C:\Windows, C:\Program Files...). The
// writer is untrusted when it runs from anywhere else, or when it is a
// system program (sh, cp, reg.exe, powershell.exe) and its parent or any
// known ancestor runs from anywhere else. A system program whose parent is
// unknown is trusted: the process table on these platforms does not know
// processes that started before the sensor (an administrator's login
// shell), so an unknown parent proves nothing.
func trustedWriter(p *event.Proc) string {
	if !systemImage(p.Exe) {
		return ""
	}
	for _, a := range p.Ancestors {
		if a != "" && !systemImage(a) {
			return ""
		}
	}
	if par := p.Parent; par != nil && par.Exe != "" && !systemImage(par.Exe) {
		return ""
	}
	return "written by a system program (" + p.Exe + ") whose known parent and ancestors are system programs too"
}
