/*
 * ZAAFVesper - fake password dialog builders.
 * Original rule written for ZAAFVesper. Targets binaries or scripts that construct an
 * AppleScript/JXA dialog with a hidden answer field and wording that asks for
 * the account password - the credential-capture step of most macOS stealers.
 * Goodware check (7 Nov 2026, /bin /usr/bin /usr/sbin /usr/libexec
 * /System/Applications /Applications /opt/homebrew/bin ~/Downloads): an editor's
 * AppleScript snippet pack matched before the file-type gate was added; 0 after.
 */

rule SUSP_Mac_OsascriptPasswordDialog_Nov26 : stealer phishing macos
{
    meta:
        author = "ZAAFVesper"
        description = "Detects Mach-O files or scripts that build an osascript dialog with a hidden answer field asking for the user's password"
        reference = "https://attack.mitre.org/techniques/T1056/002/"
        attack = "T1056.002"
        date = "2026-11-07"

    strings:
        $dlg1 = "display dialog" ascii
        $dlg2 = "displayDialog" ascii
        $hid1 = "with hidden answer" ascii
        $hid2 = "hiddenAnswer" ascii
        $ans1 = "default answer" ascii
        $ans2 = "defaultAnswer" ascii
        $ask1 = "password" ascii nocase
        $ask2 = "passphrase" ascii nocase
        $run1 = "osascript" ascii
        $run2 = "NSAppleScript" ascii

    condition:
        filesize < 20MB
        // Mach-O (thin/universal), shebang script, or compiled AppleScript (FasdUAS);
        // keeps editor snippet packs and documentation out.
        and (uint32(0) == 0xfeedfacf or uint32(0) == 0xfeedface or uint32be(0) == 0xcafebabe
             or uint16(0) == 0x2123 or uint32be(0) == 0x46617364)
        and any of ($dlg*)
        and any of ($hid*)
        and any of ($ans*)
        and any of ($ask*)
        and any of ($run*)
}
