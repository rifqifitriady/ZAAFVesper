#!/usr/bin/env bash
# Installs ZAAFVesper on a throw-away GitHub runner exactly as
# packaging/linux/README.md says (Install, steps 2-3), with the shipped unit,
# which uses the eBPF source. No Sysmon is installed. Run from the
# repository root after build/zaafvesper exists.
#
# Fails when the unit does not start or when the start-up log says that a
# group of kernel programs is unavailable on this kernel (that would be
# reduced coverage, which must not look like a green run).
set -euo pipefail

if systemctl list-unit-files sysmon.service >/dev/null 2>&1 && systemctl is-active --quiet sysmon; then
  echo "sysmon is running on this runner; this run must not use it" >&2
  exit 1
fi
test -r /sys/kernel/btf/vmlinux
uname -r

sudo install -m 0755 build/zaafvesper /usr/local/sbin/zaafvesper
sudo install -d -m 0755 /usr/local/etc/zaafvesper
sudo install -m 0644 configs/zaafvesper.yml /usr/local/etc/zaafvesper/zaafvesper.yml
sudo cp -R configs/config.d /usr/local/etc/zaafvesper/config.d
sudo cp -R rules /usr/local/etc/zaafvesper/rules
sudo chown -R root:root /usr/local/etc/zaafvesper
sudo chmod -R go-w /usr/local/etc/zaafvesper
sudo install -m 0644 packaging/linux/zaafvesper.service /etc/systemd/system/zaafvesper.service
sudo systemctl daemon-reload
sudo systemctl start zaafvesper

started=no
for _ in $(seq 1 30); do
  sleep 2
  if sudo journalctl -u zaafvesper --no-pager | grep -q 'events:'; then started=yes; break; fi
done
# The "events:" line is printed before the kernel programs load; give the
# load time to fail (the unit would then be restarting).
sleep 10
sudo journalctl -u zaafvesper --no-pager | tail -40
if [ "$started" != yes ]; then echo "zaafvesper did not start (see its journal above)" >&2; exit 1; fi
if sudo journalctl -u zaafvesper --no-pager | grep -q 'eBPF source cannot run'; then
  echo "the eBPF source failed to load under the systemd unit (journal above)" >&2
  exit 1
fi
systemctl is-active zaafvesper
test "$(systemctl show zaafvesper -p NRestarts --value)" = 0
systemctl show zaafvesper -p ExecStart | grep -q -- '--source ebpf'
if sudo journalctl -u zaafvesper --no-pager | grep -E 'events unavailable on this kernel|running without'; then
  echo "some kernel programs did not load under the systemd unit (lines above)" >&2
  exit 1
fi
