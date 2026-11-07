/*
 * ZAAFVesper - reverse shell one-liners embedded in binaries or scripts.
 * Original rule written for ZAAFVesper. Each string below is an interactive shell
 * wired to a socket; legitimate software has no reason to carry one.
 */

rule SUSP_Mac_ReverseShell_OneLiner_Nov26 : backdoor macos
{
    meta:
        author = "ZAAFVesper"
        description = "Detects files carrying a reverse-shell one-liner (bash /dev/tcp, mkfifo+nc, python pty over socket, perl Socket+exec)"
        reference = "https://attack.mitre.org/techniques/T1059/004/"
        attack = "T1059.004"
        date = "2026-11-07"

    strings:
        $bash_tcp = /(ba)?sh -i >& ?\/dev\/tcp\/[0-9a-zA-Z.\-]{3,64}\/[0-9]{2,5}/ ascii
        $bash_tcp2 = /exec [0-9]{1,2}<>\/dev\/tcp\/[0-9a-zA-Z.\-]{3,64}\/[0-9]{2,5}/ ascii
        $fifo_nc = /mkfifo \/tmp\/[A-Za-z0-9_.]{1,32}; ?(cat|nc)[^\n]{0,80}\/bin\/(ba|z)?sh -i/ ascii
        $nc_e = /nc(at)? (-[a-z]{1,3} ){0,3}-e \/bin\/(ba|z)?sh [0-9a-zA-Z.\-]{3,64} [0-9]{2,5}/ ascii
        $py_pty = "pty.spawn(\"/bin/" ascii
        $py_sock = "socket.socket(socket.AF_INET,socket.SOCK_STREAM)" ascii
        $py_dup = "os.dup2(s.fileno(),0)" ascii
        $pl_sock = "use Socket;" ascii
        $pl_exec = /exec\(["']\/bin\/(ba|z)?sh -i["']\)/ ascii

    condition:
        filesize < 10MB
        and (
            any of ($bash_tcp*, $fifo_nc, $nc_e)
            or ($py_sock and ($py_pty or $py_dup))
            or ($pl_sock and $pl_exec)
        )
}
