#!/bin/bash
# Probe the runner: OS, SIP, owners of candidate install paths, toolchains,
# and whether /usr/bin/eslogger can start under sudo (Full Disk Access/TCC).
set -u
echo "== os"; sw_vers; uname -a; id; csrutil status 2>&1 || true
echo "== owners"; for p in / /usr /usr/local /usr/local/sbin /usr/local/etc /opt /Library /private/var/db /Users/runner; do ls -ld "$p" 2>&1; done
echo "== tools"; command -v go cargo rustup nc openssl python3 jq 2>&1; go version 2>&1; cargo --version 2>&1
echo "== tcc"; sudo /usr/bin/sqlite3 "/Library/Application Support/com.apple.TCC/TCC.db" "select client,auth_value from access where service='kTCCServiceSystemPolicyAllFiles'" 2>&1 | head -40
echo "== eslogger"
sudo /usr/bin/eslogger exec fork > /tmp/eslogger-probe.json 2> /tmp/eslogger-probe.err &
pid=$!
sleep 3; /bin/ls / >/dev/null; /usr/bin/true; sleep 2
sudo kill -INT "$pid" 2>/dev/null; sleep 1; sudo kill -TERM "$pid" 2>/dev/null; wait "$pid"; echo "eslogger exit=$?"
echo "stderr:"; head -20 /tmp/eslogger-probe.err
echo "lines: $(wc -l < /tmp/eslogger-probe.json)"; head -c 600 /tmp/eslogger-probe.json; echo
