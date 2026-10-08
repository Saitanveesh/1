#!/usr/bin/env bash
# Exercises the PC2 orchestration contract with fake SSH and SCP, not real hosts.
set -Eeuo pipefail
HERE="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
T="$(mktemp -d)"
trap 'rm -rf "$T"' EXIT
mkdir -p "$T/bin" "$T/automation"
cp "$HERE/controller.sh" "$HERE/node.sh" "$T/automation/"
cat > "$T/automation/lab.env" <<'CONF'
LAB_USER=lab
MON_REF=8f66baa9f8d287b8c05da379259b289c661c5828
PC1_MGMT_IP=192.168.99.11
PC2_MGMT_IP=192.168.99.12
PC3_MGMT_IP=192.168.99.13
PC4_MGMT_IP=192.168.99.14
PC5_MGMT_IP=192.168.99.15
PC6_MGMT_IP=192.168.99.16
PC7_MGMT_IP=192.168.99.17
CONF
cat > "$T/bin/ip" <<'CMD'
#!/usr/bin/env bash
printf '2: enp1s0 inet 192.168.99.12/24 scope global enp1s0\n'
CMD
cat > "$T/bin/ssh" <<'CMD'
#!/usr/bin/env bash
printf 'ssh %s\n' "$*" >> "$MOCKLOG"
case "$*" in
  *wg-public.key*) printf '%043d=\n' 0 | tr '0' 'A' ;;
  *) echo MOCK-OK ;;
esac
CMD
cat > "$T/bin/scp" <<'CMD'
#!/usr/bin/env bash
printf 'scp %s\n' "$*" >> "$MOCKLOG"
for arg in "$@"; do last="$arg"; done
case "$last" in /*) printf 'mock-transported-file\n' > "$last";; esac
CMD
chmod +x "$T/bin/"*
export MOCKLOG="$T/mock.log" PATH="$T/bin:$PATH"
cd "$T/automation"
for stage in preflight install keys network control site sensors register status; do
  bash controller.sh "$stage" > "$T/$stage.out" 2>&1 || { echo "mock stage failed: $stage"; cat "$T/$stage.out"; exit 1; }
done
if bash controller.sh lockdown > "$T/denied.out" 2>&1; then
  echo 'FAIL: lockdown allowed without explicit approval' >&2; exit 1
fi
[[ "$(grep -c 'sudo bash' "$MOCKLOG")" -gt 10 ]]
grep -q "'PC3' 'wg-hub'" "$MOCKLOG"
grep -q "'PC1' 'enroll-site'" "$MOCKLOG"
grep -q "'PC4' 'collector-start'" "$MOCKLOG"
grep -q "'PC5' 'collector-start'" "$MOCKLOG"
grep -q "'PC1' 'register-router'" "$MOCKLOG"
echo 'PASS: SSH and SCP stage ordering, CSR transfers and lockdown confirmation gate'
