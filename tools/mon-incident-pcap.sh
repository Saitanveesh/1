#!/usr/bin/env bash
# Analyst-approved bounded PCAP collection for the existing authorized 3-PC lab.
# Never runs from AI or the browser; no active scanning or packet modification.
set -euo pipefail
umask 077
[[ "$(id -un)" == "pc-2" ]] || { echo 'Run as pc-2 on PC2'; exit 1; }
command -v tcpdump >/dev/null || { echo 'tcpdump is not installed on PC2'; exit 1; }
ip link show wg0 >/dev/null
printf 'Capture only PC6 (10.77.0.60) ↔ PC5 (10.77.0.50) on wg0 for 30s.\n'
printf 'This may record packet content. Explicit analyst approval is required.\n'
read -r -p "Type AUTHORIZE PCAP 30S: " approval
[[ "$approval" == "AUTHORIZE PCAP 30S" ]] || { echo 'Not authorized. No capture performed.'; exit 1; }
OUTDIR=/home/pc-2/mon-three/evidence-pcap
install -d -m 0700 "$OUTDIR"
timestamp=$(date -u +%Y%m%dT%H%M%SZ)
FILE="$OUTDIR/lab-pc6-pc5-$timestamp.pcap"
echo "Saving bounded incident sample to $FILE"
set +e
sudo timeout --signal=INT --kill-after=4s 30s tcpdump \
  -i wg0 -nn -s 96 -U -c 2400 -w "$FILE" \
  '((src host 10.77.0.60 and dst host 10.77.0.50) or (src host 10.77.0.50 and dst host 10.77.0.60))'
rc=$?
set -e
sudo chown pc-2:pc-2 "$FILE" 2>/dev/null || true
chmod 0600 "$FILE" 2>/dev/null || true
if [[ "$rc" != 0 && "$rc" != 124 && "$rc" != 130 ]]; then
  echo "[CHECK] tcpdump exited $rc; inspect the capture and sudo journal"
  exit "$rc"
fi
echo "Capture closed; packet bytes can be read with: tcpdump -nn -r '$FILE'"
echo "Case evidence remains local; nothing was uploaded to MON or Grafana."
