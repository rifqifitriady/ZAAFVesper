#!/usr/bin/env bash
# Live validation, Linux (v0.3 workstream B): install Sysmon for Linux and
# ZAAFVesper the way packaging/linux/README.md says, from pinned,
# hash-checked downloads. Runs on a throw-away GitHub runner with sudo.
set -euo pipefail

# Microsoft builds Sysmon for Linux per Ubuntu release; the workflow pins
# the packages for 24.04 and 26.04.
. /etc/os-release
case "${ID:-}-${VERSION_ID:-}" in
  ubuntu-24.04) sfl_sha=$SYSMONFORLINUX_SHA256_2404; ebpf_sha=$SYSINTERNALSEBPF_SHA256_2404 ;;
  ubuntu-26.04) sfl_sha=$SYSMONFORLINUX_SHA256_2604; ebpf_sha=$SYSINTERNALSEBPF_SHA256_2604 ;;
  *) echo "runner is ${PRETTY_NAME:-unknown}: no Sysmon for Linux pins for it; add them (scripts/ci/b/README.md)" >&2; exit 1 ;;
esac
echo "runner: $PRETTY_NAME"

work="$RUNNER_TEMP/zv"
mkdir -p "$work"
pinned() { # url out sha256
  curl -fsSL --retry 3 -o "$2" "$1"
  echo "$3  $2" | sha256sum -c -
}

# 1. Sysmon for Linux and its eBPF library, Microsoft's packages at pinned
#    versions (dependencies come from Ubuntu's signed archive through apt).
base="https://packages.microsoft.com/ubuntu/${VERSION_ID}/prod/pool/main/s"
pinned "$base/sysinternalsebpf/sysinternalsebpf_${SYSINTERNALSEBPF_VERSION}_amd64.deb" "$work/sysinternalsebpf.deb" "$ebpf_sha"
pinned "$base/sysmonforlinux/sysmonforlinux_${SYSMONFORLINUX_VERSION}_amd64.deb" "$work/sysmonforlinux.deb" "$sfl_sha"
sudo apt-get update -qq
sudo DEBIAN_FRONTEND=noninteractive apt-get install -y -qq "$work/sysinternalsebpf.deb" "$work/sysmonforlinux.deb"
# journald's rate limit off for Sysmon (packaging/linux/sysmon-log-ratelimit.conf),
# installed before Sysmon creates its unit so the first start already has it.
sudo install -D -m 0644 packaging/linux/sysmon-log-ratelimit.conf /etc/systemd/system/sysmon.service.d/zaafvesper.conf
sudo /usr/bin/sysmon -accepteula -i scripts/ci/b/sysmon-linux.xml
sudo systemctl daemon-reload
sudo systemctl restart sysmon
systemctl is-active --quiet sysmon
systemctl --no-pager status sysmon | head -20

# 2. ZAAFVesper, as in packaging/linux/README.md (step 4).
sudo install -m 0755 build/zaafvesper /usr/local/sbin/zaafvesper
sudo install -d -m 0755 /usr/local/etc/zaafvesper
sudo install -m 0644 configs/zaafvesper.yml /usr/local/etc/zaafvesper/zaafvesper.yml
sudo cp -R configs/config.d /usr/local/etc/zaafvesper/config.d
sudo cp -R rules /usr/local/etc/zaafvesper/rules
sudo chown -R root:root /usr/local/etc/zaafvesper
sudo chmod -R go-w /usr/local/etc/zaafvesper
sudo install -m 0644 packaging/linux/zaafvesper.service /etc/systemd/system/zaafvesper.service
# The unit uses the eBPF source by default (v0.4); this run validates Sysmon
# for Linux, so switch with the documented drop-in.
sudo install -D -m 0644 packaging/linux/zaafvesper-source-sysmon.conf /etc/systemd/system/zaafvesper.service.d/source-sysmon.conf
sudo systemctl daemon-reload
sudo systemctl start zaafvesper
started=no
for _ in $(seq 1 30); do
  sleep 2
  if sudo journalctl -u zaafvesper --no-pager | grep -q 'events:'; then started=yes; break; fi
done
sudo journalctl -u zaafvesper --no-pager | tail -40
if [ "$started" != yes ]; then echo "zaafvesper did not start (see its journal above)" >&2; exit 1; fi
systemctl is-active zaafvesper
systemctl show zaafvesper -p ExecStart | grep -q -- '--source sysmon' || { echo 'the Sysmon drop-in is not in effect' >&2; exit 1; }
