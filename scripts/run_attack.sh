#!/bin/bash
# ============================================================
# Attack Simulation Script
# Simulates an Nmap reconnaissance attack from the attacker
# host inside Mininet to trigger the Threat Scoring Engine.
#
# Run from inside Mininet CLI:
#   attacker bash scripts/run_attack.sh
#
# Or from the Mininet prompt:
#   attacker nmap -sS -p 1-1000 10.0.0.1
#
# Group 46 - Adaptive Fingerprint-Resistant MTD in SDN
# ============================================================

TARGET_IP="10.0.0.1"
LOG_FILE="results/attack_$(date +%Y%m%d_%H%M%S).log"

mkdir -p results

echo "[*] Starting reconnaissance attack against $TARGET_IP"
echo "[*] Log: $LOG_FILE"
echo ""

# SYN scan — most common reconnaissance technique
echo "[*] Phase 1: SYN port scan (ports 1-1000)"
nmap -sS -p 1-1000 $TARGET_IP 2>&1 | tee -a $LOG_FILE

# UDP scan
echo ""
echo "[*] Phase 2: UDP scan (common ports)"
nmap -sU -p 53,67,68,123,161 $TARGET_IP 2>&1 | tee -a $LOG_FILE

# OS fingerprinting
echo ""
echo "[*] Phase 3: OS detection"
nmap -O $TARGET_IP 2>&1 | tee -a $LOG_FILE

echo ""
echo "[*] Attack simulation complete. Check logs/threat_scores.log for trigger events."
