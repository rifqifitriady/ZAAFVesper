package response

import "testing"

func TestProtectedWinImage(t *testing.T) {
	f := winFolders{SystemRoot: `C:\Windows`, ProgramData: `C:\ProgramData`, ProgramFiles: `C:\Program Files`, Self: `C:\Program Files\ZAAFVesper\zaafvesper.exe`}
	protected := []string{
		`C:\Windows\System32\lsass.exe`, `c:\windows\system32\LSASS.EXE`, `C:\Windows\Sysmon64.exe`,
		`C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.24090.11-0\MsMpEng.exe`,
		`C:\Program Files\Windows Defender\MsMpEng.exe`, `C:\Program Files\ZAAFVesper\zaafvesper.exe`,
	}
	for _, p := range protected {
		if protectedWinImage(p, f) == "" {
			t.Errorf("%s not protected", p)
		}
	}
	// Masquerading names elsewhere are not protected.
	for _, p := range []string{
		`C:\Users\alice\AppData\Local\Temp\lsass.exe`, `C:\Users\Public\Sysmon64.exe`, `C:\Windows\Temp\MsMpEng.exe`,
		`C:\ProgramData\Microsoft\Windows Defender\Platform\x\evil.exe`, `C:\Windows\System32\cmd.exe`,
	} {
		if why := protectedWinImage(p, f); why != "" {
			t.Errorf("%s protected (%s)", p, why)
		}
	}
}
