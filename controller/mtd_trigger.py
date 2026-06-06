"""
Adaptive MTD Trigger
====================
Bridges the Threat Scoring Engine and the Mutation Module.
Listens for threshold signals from the engine and calls the
mutation module — replacing the fixed-timer approach used in
traditional MTD systems.

Also provides a BASELINE mode that mimics fixed-interval MTD
for comparison/evaluation purposes.

Group 46 - Adaptive Fingerprint-Resistant MTD in SDN
"""

import time
import logging
import json
import os
from threading import Timer

logger = logging.getLogger(__name__)
os.makedirs("logs", exist_ok=True)
TRIGGER_LOG = "logs/triggers.log"

# ── Configuration ─────────────────────────────────────────────────────────────
BASELINE_INTERVAL   = 30     # Seconds between mutations in baseline (fixed) mode
COOLDOWN_PERIOD     = 5      # Minimum seconds between adaptive mutations
# ─────────────────────────────────────────────────────────────────────────────


class MTDTrigger:
    """
    Adaptive trigger: fires mutations based on threat scores, not timers.

    Set mode='adaptive' for the proposed system.
    Set mode='baseline' for fixed-interval comparison.
    """

    def __init__(self, mutation_module, mode='adaptive'):
        self.mutation_module  = mutation_module
        self.mode             = mode
        self.last_trigger     = 0
        self.trigger_count    = 0
        self._baseline_timer  = None

        logger.info("MTD Trigger initialised in %s mode", mode.upper())

        if mode == 'baseline':
            self._start_baseline_timer()

    # ── Adaptive Mode ─────────────────────────────────────────────────────────

    def on_threat_detected(self, attacker_ip, score):
        """
        Called by ThreatScoringEngine when threshold is exceeded.
        Fires mutation if cooldown period has passed.
        """
        now = time.time()
        if now - self.last_trigger < COOLDOWN_PERIOD:
            logger.info("Cooldown active — mutation suppressed (%.1fs remaining)",
                        COOLDOWN_PERIOD - (now - self.last_trigger))
            return

        self.trigger_count += 1
        self.last_trigger   = now
        logger.warning("ADAPTIVE TRIGGER #%d — attacker=%s score=%d",
                       self.trigger_count, attacker_ip, score)
        self._log_trigger('adaptive', attacker_ip, score)
        self.mutation_module.trigger_mutation(attacker_ip)

    # ── Baseline Mode ─────────────────────────────────────────────────────────

    def _start_baseline_timer(self):
        """Fire mutations on a fixed interval regardless of traffic."""
        logger.info("Baseline timer started (interval=%ds)", BASELINE_INTERVAL)
        self._fire_baseline()

    def _fire_baseline(self):
        self.trigger_count += 1
        logger.info("BASELINE TRIGGER #%d (fixed interval)", self.trigger_count)
        self._log_trigger('baseline', None, 0)
        self.mutation_module.trigger_mutation()
        # Schedule next
        self._baseline_timer = Timer(BASELINE_INTERVAL, self._fire_baseline)
        self._baseline_timer.daemon = True
        self._baseline_timer.start()

    def stop_baseline(self):
        if self._baseline_timer:
            self._baseline_timer.cancel()
            logger.info("Baseline timer stopped")

    # ── Logging ───────────────────────────────────────────────────────────────

    def _log_trigger(self, mode, attacker_ip, score):
        with open(TRIGGER_LOG, 'a') as f:
            entry = {
                'timestamp':     time.strftime('%Y-%m-%d %H:%M:%S'),
                'trigger_count': self.trigger_count,
                'mode':          mode,
                'attacker_ip':   attacker_ip,
                'threat_score':  score
            }
            f.write(json.dumps(entry) + '\n')
