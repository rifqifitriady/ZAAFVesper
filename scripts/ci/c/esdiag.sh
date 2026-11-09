#!/bin/bash
# Diagnoses which processes eslogger reports on this runner: commands run
# from the job's own process tree, the same commands run through launchd
# (outside that tree), and with a small (exec) or a large (the sensor's)
# subscription. Writes esdiag.tsv to $1 and the raw heads next to it.
set -u
# Refuses to run anywhere but a throw-away GitHub-hosted runner: it changes
# the user's shell files and crontab and installs into /usr/local as root.
if [ "${GITHUB_ACTIONS:-}" != true ] || [ "${RUNNER_ENVIRONMENT:-}" != github-hosted ]; then
	echo "$0: runs only on a GitHub-hosted runner" >&2
	exit 2
fi
out=$1; mkdir -p "$out"
probe() { # name subscription...
	local name=$1; shift
	local tag="zvdiag$RANDOM$RANDOM"
	sudo /usr/bin/eslogger "$@" >"$out/es-$name.json" 2>"$out/es-$name.err" &
	local pid=$!
	sleep 3
	/bin/sh -c "/bin/echo $tag-tree >/dev/null"
	/usr/bin/env "ZVTAG=$tag" /usr/bin/true "$tag-tree2"
	sudo /bin/launchctl submit -l "com.zaafvesper.ci.$tag" -- /bin/sh -c "/bin/echo $tag-launchd >/dev/null; /bin/sleep 2"
	sleep 4
	sudo /bin/launchctl remove "com.zaafvesper.ci.$tag" 2>/dev/null
	sudo /usr/bin/pkill -TERM -x eslogger
	for _ in $(seq 1 50); do kill -0 "$pid" 2>/dev/null || break; sleep 0.2; done
	sudo /usr/bin/pkill -KILL -x eslogger 2>/dev/null
	local lines tree launchd execs
	lines=$(wc -l <"$out/es-$name.json" | tr -d ' ')
	tree=$(grep -c "$tag-tree" "$out/es-$name.json")
	launchd=$(grep -c "$tag-launchd" "$out/es-$name.json")
	execs=$(grep -c '"event_type":9,' "$out/es-$name.json")
	printf '%s\tlines=%s exec=%s tree_hits=%s launchd_hits=%s\n' "$name" "$lines" "$execs" "$tree" "$launchd" >>"$out/esdiag.tsv"
	head -c 4000 "$out/es-$name.json" >"$out/es-$name.head"; rm -f "$out/es-$name.json"
}
probe exec-only exec
probe sensor-set btm_launch_item_add close create deleteextattr exec exit fork get_task kextload open remote_thread_create rename trace unlink xp_malware_detected
cat "$out/esdiag.tsv"
