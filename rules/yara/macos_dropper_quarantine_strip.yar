/*
 * ZAAFVesper - dropper that fetches a payload, strips quarantine and runs it.
 * Original rule written for ZAAFVesper. Matches shell scripts and Mach-O loaders that
 * contain all three steps: download, quarantine removal, make-executable.
 */

rule SUSP_Mac_Dropper_QuarantineStripExec_Nov26 : dropper macos
{
    meta:
        author = "ZAAFVesper"
        description = "Detects scripts or Mach-O loaders that download a payload, remove com.apple.quarantine and mark it executable"
        reference = "https://attack.mitre.org/techniques/T1553/001/"
        attack = "T1553.001"
        date = "2026-11-07"

    strings:
        $dl1 = /curl (-[a-zA-Z]{1,6} ){0,4}(-o|--output) / ascii
        $dl2 = "NSURLSession" ascii
        $q1 = "xattr -c " ascii
        $q2 = "xattr -cr " ascii
        $q3 = /xattr -[rd]{1,2} com\.apple\.quarantine/ ascii
        $q4 = "removexattr" ascii
        $q5 = "com.apple.quarantine" ascii
        $x1 = "chmod +x " ascii
        $x2 = "chmod 755 " ascii
        $x3 = "chmod 777 " ascii

    condition:
        filesize < 10MB
        and any of ($dl*)
        and (any of ($q1, $q2, $q3) or ($q4 and $q5))
        and any of ($x*)
}
