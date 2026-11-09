#!/bin/bash
# Live validation of the response actions on a throw-away GitHub macOS
# runner (v0.3 workstream D). Called by .github/workflows/live-response.yml.
# It runs the real zaafvesper binary as root: `validate-response` kills,
# suspends and quarantines only objects it creates itself, loads and boots
# out its own test launch items, and blocks a loopback alias and a
# documentation address in pf. Never run it on your own Mac.
#
# usage: live-response-macos.sh <zaafvesper binary> <results.json>
set -euo pipefail

if [ "${GITHUB_ACTIONS:-}" != "true" ]; then
	echo "refusing: this script changes pf, launchd and /var/db and runs only on a GitHub Actions runner" >&2
	exit 2
fi
bin=$1
out=$2
alias_ip=10.254.254.2
anchor='com.apple/com.rifqifitriady.zaafvesper'

cleanup() {
	sudo /sbin/pfctl -a "$anchor" -F all >/dev/null 2>&1 || true
	sudo /sbin/ifconfig lo0 -alias "$alias_ip" >/dev/null 2>&1 || true
}
trap cleanup EXIT

# The package normally creates the state directory (root:wheel 0700).
sudo /usr/bin/install -d -m 0700 -o root -g wheel /private/var/db/zaafvesper
# A loopback alias: the isolation case blocks it in pf. Traffic to it never
# leaves the runner, so the runner's own connectivity is not touched.
sudo /sbin/ifconfig lo0 alias "$alias_ip" netmask 255.255.255.255

echo "::group::environment"
sw_vers || true
uname -a
echo "console user: $(/usr/bin/stat -f '%Su (uid %u)' /dev/console)"
sudo /sbin/pfctl -s info 2>/dev/null | head -3 || true
echo "anchors in the main ruleset:"
sudo /sbin/pfctl -s Anchors 2>/dev/null || true
echo "::endgroup::"

sudo /usr/bin/env ZAAFVESPER_VALIDATE_RESPONSE=throwaway-runner GITHUB_ACTIONS="$GITHUB_ACTIONS" \
	RUNNER_ENVIRONMENT="${RUNNER_ENVIRONMENT:-}" "$bin" validate-response --out "$out"
