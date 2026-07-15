#!/bin/bash
# Reset all logs before a new experiment run
# Usage: bash scripts/reset_logs.sh

echo "[*] Clearing logs for fresh experiment run..."
> logs/mutations.log
> logs/triggers.log
> logs/threat_scores.log
> logs/install_trace.log
echo "[*] Logs cleared. Ready for new run."
