#!/bin/bash
# Fires safe, local actions on the throw-away runner that built-in macOS rules
# (and their Atomic Red Team tests) cover. Nothing leaves the machine: no
# network beyond 127.0.0.1, no real credentials, no system changes that
# outlive the job. Each action records:  id <TAB> rule file <TAB> what <TAB> exit
#
# Usage: triggers.sh PHASE OUTFILE WORKDIR DROPPED_BIN
#   PHASE a: the main set; PHASE b: a few more while the SIEM receivers are down.
set -u
phase=$1 out=$2 work=$3 dropped=$4
# Started by run.sh (itself guarded to GitHub-hosted runners) through
# launchd, which does not pass the job's environment: check run.sh's marker.
if [ ! -f /tmp/zaafvesper-live-macos.ci ]; then
	echo "$0: runs only from scripts/ci/c/run.sh on a GitHub-hosted runner" >&2
	exit 2
fi
mkdir -p "$work"
trig() { # id rulefile what -- command...
	local id=$1 rule=$2 what=$3
	shift 4
	"$@" >/dev/null 2>&1
	printf '%s\t%s\t%s\t%s\n' "$id" "$rule" "$what" "$?" >>"$out"
	sleep 1
}

if [ "$phase" = b ]; then
	f="$work/q-down.bin"; echo x >"$f"; /usr/bin/xattr -w com.apple.quarantine "0081;00000000;Safari;" "$f"
	trig b-quarantine defense_impairment_quarantine_attribute_removed "xattr -d com.apple.quarantine while the SIEM is down" -- /usr/bin/xattr -d com.apple.quarantine "$f"
	echo x >"$work/h-down.txt"
	trig b-hidden stealth_hidden_file_flag "chflags hidden while the SIEM is down" -- /usr/bin/chflags hidden "$work/h-down.txt"
	exit 0
fi

# T1553.001: quarantine attribute removed (ART T1553.001 #1 shape).
f="$work/app.bin"; echo x >"$f"; /usr/bin/xattr -w com.apple.quarantine "0081;00000000;Safari;" "$f"
trig quarantine defense_impairment_quarantine_attribute_removed "xattr -d com.apple.quarantine on a test file" -- /usr/bin/xattr -d com.apple.quarantine "$f"

# T1543.001: Launch Agent plist written into the user's LaunchAgents (not loaded).
cat >"$work/com.zaafvesper.ci.plist" <<'P'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict><key>Label</key><string>com.zaafvesper.ci</string>
<key>ProgramArguments</key><array><string>/usr/bin/true</string></array></dict></plist>
P
mkdir -p "$HOME/Library/LaunchAgents"
trig launchagent persistence_launch_agent_plist "cp a test plist into ~/Library/LaunchAgents" -- /bin/cp "$work/com.zaafvesper.ci.plist" "$HOME/Library/LaunchAgents/com.zaafvesper.ci.plist"
rm -f "$HOME/Library/LaunchAgents/com.zaafvesper.ci.plist"

# T1543.004: Launch Daemon plist written with sudo (not loaded), then removed.
trig launchdaemon persistence_launch_daemon_plist "sudo cp a test plist into /Library/LaunchDaemons" -- sudo /bin/cp "$work/com.zaafvesper.ci.plist" /Library/LaunchDaemons/com.zaafvesper.ci.plist
sudo rm -f /Library/LaunchDaemons/com.zaafvesper.ci.plist

# T1059.002: osascript "do shell script" with base64 (no UI).
trig osascript execution_suspicious_osascript "osascript -e do shell script with base64 (no UI)" -- /usr/bin/osascript -e 'do shell script "echo ZWNobyBoaQ== | base64 -D"'

# T1564.001: file hidden with chflags (ART T1564.001 #6 shape).
echo x >"$work/hidden.txt"
trig chflags stealth_hidden_file_flag "chflags hidden on a test file" -- /usr/bin/chflags hidden "$work/hidden.txt"

# T1070.003: shell history deleted (a history file created for the test).
echo "ls" >"$HOME/.bash_history.zvci"; cp "$HOME/.bash_history.zvci" "$HOME/.zsh_history" 2>/dev/null
trig history stealth_shell_history_deleted "rm ~/.zsh_history (created for the test)" -- /bin/rm -f "$HOME/.zsh_history"
rm -f "$HOME/.bash_history.zvci"

# T1546.004: shell start-up file modified by a non-editor process.
trig zshrc persistence_shell_profile_modification "append a comment to ~/.zshrc from sh" -- /bin/sh -c 'echo "# zaafvesper ci" >> "$HOME/.zshrc"'

# T1518.001: security software enumeration (ART T1518.001 #3 shape).
trig secsw discovery_security_software_enumeration "ps | egrep for security tools" -- /bin/sh -c '/bin/ps aux | /usr/bin/egrep "Little Snitch|CbOsxSensorService|falcond"'

# T1082: system profiling burst from one shell (ART T1082 #2 shape).
trig profiling discovery_system_profiling_burst "system_profiler then sw_vers from one sh" -- /bin/sh -c '/usr/sbin/system_profiler SPSoftwareDataType >/dev/null; /usr/bin/sw_vers'

# T1569.001: launchctl submit (ART T1569.001 #1 shape), then removed.
trig launchctl execution_launchctl_submit_or_load_from_temp "launchctl submit a test job" -- /bin/launchctl submit -l com.zaafvesper.ci.submit -- /usr/bin/true
/bin/launchctl remove com.zaafvesper.ci.submit 2>/dev/null

# T1548.001: setuid bit on a test file (ART T1548.001 #3 shape).
echo x >"$work/evilBinary"
trig setuid privilege_escalation_setuid_bit_set "chmod u+xs on a test file" -- /bin/chmod u+xs "$work/evilBinary"

# T1113: non-interactive screen capture (ART T1113 #2 shape); it may fail
# without the screen-recording permission, the exec is what is detected.
trig screencapture collection_noninteractive_screencapture "screencapture -x to a test file" -- /usr/sbin/screencapture -x "$work/shot.png"

# T1059.004: decoded script piped into a shell.
trig pipe execution_remote_script_piped_to_shell "echo payload | base64 -d | sh" -- /bin/sh -c 'echo ZWNobyBoaQ== | /usr/bin/base64 -d | /bin/sh'

# T1555.001: keychain dump with the security CLI (metadata only, no -d).
trig keychain credential_access_keychain_dump_via_security "security dump-keychain (metadata, no secrets)" -- /usr/bin/security dump-keychain

# T1053.003: crontab replaced from a file in /tmp (ART T1053.003 #1 shape), then removed.
echo "# zaafvesper ci" >/tmp/zv_persistevil
trig cron persistence_cron_periodic "crontab replaced from /tmp" -- /usr/bin/crontab /tmp/zv_persistevil
/usr/bin/crontab -r 2>/dev/null; rm -f /tmp/zv_persistevil

# T1204.002: unsigned binary dropped in /tmp and executed.
trig dropped execution_untrusted_binary_dropped_and_run_from_temp "cp an unsigned Go binary to /tmp and run it" -- /bin/sh -c "cp '$dropped' /tmp/zv_dropped && /tmp/zv_dropped"

# Network: a shell holding a socket to another process (reverse-shell shape,
# over loopback; the sensor runs with --net-loopback for this test).
/usr/bin/nc -l 127.0.0.1 4444 >/dev/null 2>&1 &
ncpid=$!
sleep 1
trig revshell network_shell_remote_socket "bash holds a /dev/tcp connection to 127.0.0.1:4444" -- /bin/bash -c 'exec 3<>/dev/tcp/127.0.0.1/4444; sleep 4'
kill "$ncpid" 2>/dev/null
exit 0
