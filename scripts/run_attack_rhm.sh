#!/bin/bash
# ============================================================
# Attack Simulation for the RHM Pipeline
#
# WHY THIS REPLACES run_attack.sh
# --------------------------------
# run_attack.sh scans TARGET_IP="10.0.0.1" - a REAL address. Under the
# RHM pipeline that address is shielded: the SYN reaches table 1, matches
# the priority-90 drop rule, and dies there. A dropped packet never
# reaches table 2, so it never becomes a packet_in, so the threat engine
# never sees it.
#
# The consequence is not a smaller threat score, it is NO threat score.
# nmap fires 1000 SYNs, the engine registers nothing, the trigger never
# fires, and the adaptive controller performs ZERO mutations for the whole
# run. No mutations means no intervals, no entropy, and nothing for the
# classifier to fingerprint. The measured evidence: the adaptive_floor run
# logged 5 mutations and all 5 were idle-floor triggers - not one came
# from threat detection, despite a 100-address sweep during the run.
#
# So the attacker must scan what is actually reachable: the VIRTUAL
# address space. That is not a concession, it is the correct threat model.
# Under OF-RHM real addresses are never published; virtual ones are all an
# attacker can resolve. An attacker that keeps hammering an address space
# it cannot reach is not a threat model, it is a broken experiment.
#
# WHAT IT DOES
# ------------
#   1. Sweep 10.0.0.100-199 to find the live virtual addresses.
#   2. SYN-scan the ports of each one found.
#   3. Repeat until the duration expires.
#
# The loop matters. A single scan is not enough: mutation moves the target
# out from under nmap and the scan dies, ending the threat activity after
# one burst. A persistent attacker rediscovers and keeps probing, which is
# both realistic and what sustains the threat score across the run so the
# adaptive controller keeps triggering.
#
# Usage, from the Mininet CLI:
#   attacker bash scripts/run_attack_rhm.sh 350
#
# Group 46 - Adaptive Fingerprint-Resistant MTD in SDN
# ============================================================

DURATION="${1:-350}"
POOL="10.0.0.100-199"
LOG_FILE="results/attack_rhm_$(date +%Y%m%d_%H%M%S).log"

mkdir -p results

echo "[*] RHM reconnaissance attack"
echo "[*] Target space: $POOL (virtual - real addresses are shielded)"
echo "[*] Duration: ${DURATION}s"
echo "[*] Log: $LOG_FILE"
echo ""

END=$(( $(date +%s) + DURATION ))
ROUND=0

while [ "$(date +%s)" -lt "$END" ]; do
    ROUND=$(( ROUND + 1 ))
    REMAIN=$(( END - $(date +%s) ))
    echo "[*] Round $ROUND (${REMAIN}s left) - discovery sweep" | tee -a "$LOG_FILE"

    # Host discovery across the pool. Every request for a DEAD virtual
    # address falls through the ARP proxy to the controller and is scored
    # as reconnaissance, so the sweep itself feeds the threat engine.
    VIPS=$(nmap -sn -n --host-timeout 2s "$POOL" 2>/dev/null \
           | grep -oE 'Nmap scan report for 10\.0\.0\.[0-9]+' \
           | grep -oE '10\.0\.0\.[0-9]+')

    if [ -z "$VIPS" ]; then
        echo "[!] No live virtual addresses found - is the controller up?" | tee -a "$LOG_FILE"
        sleep 2
        continue
    fi

    echo "[*] Live: $(echo $VIPS | tr '\n' ' ')" | tee -a "$LOG_FILE"

    for V in $VIPS; do
        [ "$(date +%s)" -ge "$END" ] && break
        # Per-port microflow rules make every unseen port a table miss, so
        # a port sweep arrives at the controller port by port and drives
        # the score up. --host-timeout caps the loss when a mutation moves
        # this address mid-scan.
        echo "[*] SYN scan $V" | tee -a "$LOG_FILE"
        nmap -sS -p 1-1000 -n --host-timeout 25s "$V" 2>&1 | tail -5 | tee -a "$LOG_FILE"
    done
done

echo "" | tee -a "$LOG_FILE"
echo "[*] Attack complete after $ROUND rounds." | tee -a "$LOG_FILE"
echo "[*] Check logs/threat_scores.log for trigger events," | tee -a "$LOG_FILE"
echo "[*] and logs/mutations.log for what actually fired." | tee -a "$LOG_FILE"
