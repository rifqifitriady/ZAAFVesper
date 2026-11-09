#!/bin/bash
# live-macos validation driver (GitHub macos runner only: it installs into
# /usr/local as root and writes to the runner's home). Expects in $BIN:
# zaafvesper, receiver, dropped, zaaf. Writes everything to $ART.
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
repo=$(cd "$here/../../.." && pwd)
: "${BIN:?}" "${ART:?}"
mkdir -p "$ART"
work=$(mktemp -d /tmp/zvci.XXXXXX)
ETC=/usr/local/etc/zaafvesper
SBIN=/usr/local/sbin/zaafvesper
OUTDIR=/var/log/zaafvesper-ci
SPOOL=/var/db/zaafvesper/spool
status() { printf '%s\t%s\n' "$1" "$2" >>"$ART/status.tsv"; }
# alive_for PID SECONDS: wait up to SECONDS for PID to exit; 0 when it did.
alive_for() {
	local i
	for i in $(seq 1 $(($2 * 5))); do kill -0 "$1" 2>/dev/null || return 0; sleep 0.2; done
	return 1
}

echo "== 1. eslogger under sudo"
"$here/esdiag.sh" "$ART/esdiag" || true
sudo /usr/bin/eslogger exec >"$work/es.json" 2>"$ART/eslogger-probe.err" &
espid=$!
sleep 3; /usr/bin/true; sleep 1
# eslogger ignores SIGINT; SIGTERM stops it (as the sensor does).
sudo /usr/bin/pkill -TERM -x eslogger || true
alive_for "$espid" 10 || { sudo /usr/bin/pkill -KILL -x eslogger || true; }
wait "$espid" 2>/dev/null || true
n=$(wc -l <"$work/es.json" | tr -d ' ')
if [ "$n" -gt 0 ]; then status eslogger "ok ($n exec events in 4 s)"; else status eslogger "blocked: $(head -c 300 "$ART/eslogger-probe.err" | tr '\n\t' '  ')"; fi
csrutil status >>"$ART/runner.txt" 2>&1 || true; sw_vers >>"$ART/runner.txt"

echo "== 2. install as root (root-owned tree, as the package does)"
sudo /usr/bin/install -d -o root -g wheel -m 0755 /usr/local/sbin "$ETC" "$ETC/rules"
sudo /usr/bin/install -o root -g wheel -m 0755 "$BIN/zaafvesper" "$SBIN"
sudo /usr/bin/rsync -a --delete "$repo/rules/" "$ETC/rules/"
sudo /usr/bin/rsync -a "$repo/configs/" "$ETC/"
sudo /usr/sbin/chown -R root:wheel "$ETC"
sudo /bin/chmod -R go-w "$ETC"

echo "== 3. SIEM receivers on 127.0.0.1 (throw-away CA, random token)"
token=$(/usr/bin/openssl rand -hex 24)
echo "::add-mask::$token"
umask 077
printf '%s\n' "$token" >"$work/token"
mkdir -p "$work/pki" "$ART/receiver"
start_receiver() {
	"$BIN/receiver" -pki "$work/pki" -out "$ART/receiver" -token-file "$work/token" >>"$ART/receiver/receiver.log" 2>&1 &
	echo $! >"$work/receiver.pid"
	for _ in $(seq 1 50); do [ -s "$work/pki/ca.pem" ] && /usr/bin/nc -z 127.0.0.1 8443 2>/dev/null && return 0; sleep 0.2; done
	echo "receiver did not start"; return 1
}
start_receiver
sudo /usr/bin/install -o root -g wheel -m 0644 "$work/pki/ca.pem" "$ETC/ci-ca.pem"
sudo /usr/bin/install -o root -g wheel -m 0600 "$work/token" "$ETC/webhook.token"
umask 022

echo "== 4. sensor as root, events piped into zaaf hunt"
sudo /bin/rm -rf "$OUTDIR" "$SPOOL"
cat >"$work/sensor.sh" <<S
#!/bin/bash
exec $SBIN run --rules $ETC/rules --config $ETC/zaafvesper.yml --no-yara --no-console --no-color \
  --output-dir $OUTDIR --capture-in-dir --dedup-window 1s \
  --net-interval 500ms --net-loopback \
  --syslog 127.0.0.1:6514 --syslog-ca $ETC/ci-ca.pem \
  --webhook https://127.0.0.1:8443/hook --webhook-token-file $ETC/webhook.token --webhook-ca $ETC/ci-ca.pem \
  --spool-dir $SPOOL --elegia-out - --alerts-ocsf $OUTDIR/alerts.ocsf.ndjson
S
chmod 0755 "$work/sensor.sh"
( sudo "$work/sensor.sh" 2>"$ART/sensor.log" | tee "$ART/events.ndjson" | "$BIN/zaaf" hunt -r "$here/sigma" -o ndjson - >"$ART/zaaf-findings.ndjson" 2>"$ART/zaaf.log" ) &
pipe=$!
for _ in $(seq 1 60); do grep -q "rules enabled" "$ART/sensor.log" 2>/dev/null && break; sleep 0.5; done
if ! grep -q "rules enabled" "$ART/sensor.log"; then status sensor "did not start"; cat "$ART/sensor.log"; exit 1; fi
status sensor "started as root"
sleep 5 # eslogger subscription

echo "== 5. socket polling: nc listener and an outbound connection over loopback, as uid $(id -u)"
/usr/bin/nc -l 127.0.0.1 5555 >/dev/null 2>&1 &
nclisten=$!
sleep 1.5
"$BIN/dropped" -connect 127.0.0.1:5555 -hold 4s >/dev/null 2>&1 &
holder=$!
echo "$nclisten $holder" >"$ART/netpoll-pids.txt"
sleep 5
kill "$nclisten" 2>/dev/null || true
alive_for "$holder" 10 || kill "$holder" 2>/dev/null || true

echo "== 6. triggers (receivers up)"
"$here/triggers.sh" a "$ART/triggers.tsv" "$work/a" "$BIN/dropped"
sleep 6

echo "== 7. receivers down: alerts must be spooled"
kill "$(cat "$work/receiver.pid")"; sleep 1
"$here/triggers.sh" b "$ART/triggers.tsv" "$work/b" "$BIN/dropped"
sleep 4
sudo /usr/bin/find "$SPOOL" -type f -name 'spool-*.ndjson' -exec /bin/ls -l {} + >"$ART/spool-while-down.txt" 2>&1 || true
status spool_while_down "$(wc -l <"$ART/spool-while-down.txt" | tr -d ' ') spool file(s)"

echo "== 8. receivers back: the spool must drain"
start_receiver
for _ in $(seq 1 90); do
	left=$(sudo /usr/bin/find "$SPOOL" -type f -name 'spool-*.ndjson' | wc -l | tr -d ' ')
	[ "$left" = 0 ] && break; sleep 1
done
status spool_after_up "$left spool file(s) left"

echo "== 9. stop the sensor"
sudo /usr/bin/pkill -INT -f "^$SBIN run" || true
if ! alive_for "$pipe" 30; then
	status sensor_stop "did not stop within 30 s of SIGINT"
	sudo /usr/bin/pkill -KILL -f "^$SBIN run" || true
	alive_for "$pipe" 10 || kill "$pipe" 2>/dev/null || true
else
	status sensor_stop "stopped cleanly on SIGINT"
fi
wait "$pipe" 2>/dev/null || true
kill "$(cat "$work/receiver.pid")" 2>/dev/null || true
sudo /bin/cp -R "$OUTDIR" "$ART/outdir"
sudo /usr/sbin/chown -R "$(id -u)" "$ART/outdir"
if grep -rqF "$token" "$ART/sensor.log" "$ART/events.ndjson" "$ART/outdir" "$ART/receiver/syslog.log"; then status token_in_outputs yes; else status token_in_outputs no; fi
cp "$here/sigma/"*.yml "$ART/" 2>/dev/null || true
echo "done"
