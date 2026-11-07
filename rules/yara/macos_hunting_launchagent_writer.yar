/*
 * ZAAFVesper - hunting signature (tag: hunting).
 * Original rule written for ZAAFVesper. A small Mach-O that embeds a complete
 * LaunchAgent property list template. Many legitimate updaters do this too,
 * so the rule is tagged `hunting`: the built-in "YARA signature match" rule
 * ignores it, and it only feeds custom rules or threat hunts.
 */

rule SUSP_Mac_EmbeddedLaunchAgentTemplate_Nov26 : hunting persistence macos
{
    meta:
        author = "ZAAFVesper"
        description = "Detects small Mach-O files embedding a RunAtLoad LaunchAgent plist template and a LaunchAgents path (hunting only)"
        reference = "https://attack.mitre.org/techniques/T1543/001/"
        attack = "T1543.001"
        date = "2026-11-07"

    strings:
        $p1 = "Library/LaunchAgents/" ascii
        $k1 = "<key>RunAtLoad</key>" ascii
        $k2 = "<key>ProgramArguments</key>" ascii
        $k3 = "<key>KeepAlive</key>" ascii
        $k4 = "launchctl load" ascii
        $k5 = "launchctl bootstrap" ascii

    condition:
        filesize < 15MB
        and (uint32(0) == 0xfeedfacf or uint32be(0) == 0xcafebabe)
        and $p1 and $k1 and $k2
        and any of ($k3, $k4, $k5)
}
