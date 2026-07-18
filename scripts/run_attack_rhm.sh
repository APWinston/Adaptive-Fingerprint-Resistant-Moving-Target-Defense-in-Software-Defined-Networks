#!/bin/bash
# Bursty reconnaissance attack for the RHM pipeline.
# Scans the virtual pool in bursts separated by randomised quiet gaps that
# exceed the threat engine's decay window, so the score falls between bursts.
# This produces irregular threat-driven mutation timing AND lets the idle
# floor engage during long quiet periods.
# Usage: attacker bash scripts/run_attack_rhm.sh 350
DURATION="${1:-350}"
POOL="10.0.0.100-199"
LOG_FILE="results/attack_rhm_$(date +%Y%m%d_%H%M%S).log"
GAP_MIN=8
GAP_MAX=35
PORTS_MIN=15
PORTS_MAX=60
mkdir -p results
echo "[*] Bursty RHM reconnaissance"
echo "[*] Target: $POOL (virtual; real addresses shielded)"
echo "[*] Duration: ${DURATION}s | gaps ${GAP_MIN}-${GAP_MAX}s"
echo ""
END=$(( $(date +%s) + DURATION ))
ROUND=0
while [ "$(date +%s)" -lt "$END" ]; do
    ROUND=$(( ROUND + 1 ))
    REMAIN=$(( END - $(date +%s) ))
    VIPS=$(nmap -sn -n --host-timeout 2s "$POOL" 2>/dev/null \
           | grep -oE '10\.0\.0\.[0-9]+' | grep -vE '\.99$')
    if [ -z "$VIPS" ]; then
        echo "[!] R$ROUND: no live addresses (controller up?)" | tee -a "$LOG_FILE"
        sleep 3
        continue
    fi
    TARGET=$(echo "$VIPS" | shuf -n1)
    NPORTS=$(( RANDOM % (PORTS_MAX - PORTS_MIN + 1) + PORTS_MIN ))
    echo "[*] R$ROUND (${REMAIN}s left): scan $TARGET, $NPORTS ports" | tee -a "$LOG_FILE"
    nmap -sS -p "1-${NPORTS}" -n --host-timeout 10s "$TARGET" 2>&1 \
        | tail -3 | tee -a "$LOG_FILE"
    GAP=$(( RANDOM % (GAP_MAX - GAP_MIN + 1) + GAP_MIN ))
    [ "$(( $(date +%s) + GAP ))" -lt "$END" ] || break
    echo "[*]   quiet ${GAP}s" | tee -a "$LOG_FILE"
    sleep "$GAP"
done
echo "" | tee -a "$LOG_FILE"
echo "[*] Done after $ROUND bursts." | tee -a "$LOG_FILE"
