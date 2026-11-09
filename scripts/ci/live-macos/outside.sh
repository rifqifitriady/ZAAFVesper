#!/bin/bash
# Runs a command as the runner user from a launchd job, outside the GitHub
# job's process tree. On GitHub macOS runners Endpoint Security reports no
# event for processes in the job's own tree (see docs/validation/macos.md,
# "eslogger"), so anything the sensor must see is started this way.
# Usage: outside.sh LABEL TIMEOUT_SECONDS command [args...]   (waits for it)
set -u
label="com.zaafvesper.ci.$1" timeout=$2; shift 2
done_file=$(mktemp /tmp/zvci-done.XXXXXX); rm -f "$done_file"
user=$(id -un) home=$HOME
cmd=$(printf '%q ' "$@")
sudo /bin/launchctl submit -l "$label" -- /usr/bin/sudo -u "$user" -H /bin/bash -c \
	"cd /tmp; export HOME='$home'; $cmd; echo \$? > '$done_file'"
for _ in $(seq 1 $((timeout * 5))); do [ -s "$done_file" ] && break; sleep 0.2; done
sudo /bin/launchctl remove "$label" 2>/dev/null
if [ -s "$done_file" ]; then rc=$(cat "$done_file"); rm -f "$done_file"; exit "$rc"; fi
echo "outside.sh: $label did not finish within ${timeout}s" >&2
exit 124
