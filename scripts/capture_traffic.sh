#!/bin/bash
# ============================================================
# Traffic Capture for Fingerprint Classifier
# Captures all control-plane + data traffic during an experiment
# run, so a real classifier can later try to detect mutations.
#
# Run this in a SEPARATE SSH window, started just before you
# launch the attack, and stop it (Ctrl+C) when the run ends.
#
# Usage:
#   bash scripts/capture_traffic.sh adaptive
#   bash scripts/capture_traffic.sh baseline
#
# Output: results/capture_<mode>_<timestamp>.pcap
# Group 46 - Adaptive Fingerprint-Resistant MTD in SDN
# ============================================================

MODE="${1:-adaptive}"
mkdir -p results
TS=$(date +%Y%m%d_%H%M%S)
OUT="results/capture_${MODE}_${TS}.pcap"

echo "[*] Capturing traffic for ${MODE} run"
echo "[*] Writing to ${OUT}"
echo "[*] Press Ctrl+C to stop when the experiment finishes."
echo ""

# Capture OpenFlow control traffic (port 6633/6653) on the loopback,
# where the controller <-> switch messages flow. This is exactly what
# a fingerprinting attacker observing the control channel would see.
sudo tcpdump -i any -w "${OUT}" \
  '(tcp port 6633) or (tcp port 6653) or (ip proto 1) or (tcp[tcpflags] & tcp-syn != 0)' \
  2>/dev/null

echo ""
echo "[*] Capture saved: ${OUT}"
echo "[*] Transfer it to Windows with scp, then run the classifier."
