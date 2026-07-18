"""
Adaptive MTD Trigger
====================
Bridges the Threat Scoring Engine and the Mutation Module.
Listens for threshold signals from the engine and calls the
mutation module — replacing the fixed-timer approach used in
traditional MTD systems.

Also provides a BASELINE mode that mimics fixed-interval MTD
for comparison/evaluation purposes.

THREE MODES
-----------
  baseline        fixed 30s timer. Mutates whether or not anyone is
                  looking. Timing entropy 0.000; a Random Forest pinpoints
                  its trigger instants at F1 0.958.

  adaptive        threat-driven only. Unpredictable (F1 0.000), but it has
                  a blind spot: an attacker that scans ONCE and then goes
                  quiet never raises the threat score again, so the trigger
                  never fires and its stolen addresses stay valid forever.
                  Measured: RDR 0.0057 against baseline's 0.6842 - the
                  adaptive system mutated once, during the attacker's
                  discovery sweep, then sat still for 180s while the
                  attacker exploited what it had learned.

  adaptive_floor  threat-driven, plus a RANDOMISED idle floor. If nothing
                  has fired for uniform(IDLE_MIN, IDLE_MAX) seconds, mutate
                  anyway. Caps how long stolen reconnaissance stays useful,
                  without handing the classifier a period to learn.

WHY THE FLOOR IS RANDOMISED
---------------------------
A FIXED idle floor would be a fixed timer wearing a disguise. Under a quiet
attacker - exactly the case the floor exists for - it would fire on a
metronome and hand back the 0.958 fingerprint the adaptive design was built
to defeat. Drawing a fresh interval per mutation keeps the schedule
irregular even when the floor is doing all the work, so the entropy and the
0.000 trigger-instant F1 survive.

IDLE_MIN is set at/above BASELINE_INTERVAL on purpose. A floor that fired
FASTER than the baseline would win RDR by mutating more often, which proves
nothing about adaptivity - anyone can shorten a timer. Ranging 30-60s around
the baseline's 30s means the adaptive system mutates no more often than the
baseline on average, and any RDR it wins is won by responding to threat, not
by brute force.

Group 46 - Adaptive Fingerprint-Resistant MTD in SDN
"""

import time
import random
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
IDLE_FLOOR_MIN      = 30     # adaptive_floor: shortest idle gap before a
IDLE_FLOOR_MAX      = 60     # forced mutation; redrawn every time
# ─────────────────────────────────────────────────────────────────────────────


class MTDTrigger:
    """
    Adaptive trigger: fires mutations based on threat scores, not timers.

    Set mode='adaptive'       for threat-driven triggering only.
    Set mode='adaptive_floor' for threat-driven plus a randomised idle floor.
    Set mode='baseline'       for fixed-interval comparison.
    """

    def __init__(self, mutation_module, mode='adaptive'):
        self.mutation_module  = mutation_module
        self.mode             = mode
        self.last_trigger     = 0
        self.trigger_count    = 0
        self._baseline_timer  = None
        self._idle_timer      = None

        logger.info("MTD Trigger initialised in %s mode", mode.upper())

        if mode == 'baseline':
            self._start_baseline_timer()
        elif mode == 'adaptive_floor':
            logger.info("Idle floor active: forced mutation after "
                        "uniform(%d, %d)s of quiet", IDLE_FLOOR_MIN, IDLE_FLOOR_MAX)
            # Armed from t=0 so a run that is never attacked still mutates.
            self.last_trigger = time.time()
            self._arm_idle_timer()

    # ── Idle Floor ────────────────────────────────────────────────────────────

    def _arm_idle_timer(self):
        """
        Schedule the next forced mutation, a fresh random interval away.

        Re-armed after EVERY mutation, threat-driven or forced, so the floor
        measures silence since the last mutation rather than since the last
        forced one. A threat-driven burst therefore pushes the floor back
        instead of stacking a redundant mutation on top of it.
        """
        if self.mode != 'adaptive_floor':
            return
        if self._idle_timer:
            self._idle_timer.cancel()
        delay = random.uniform(IDLE_FLOOR_MIN, IDLE_FLOOR_MAX)
        self._idle_timer = Timer(delay, self._fire_idle)
        self._idle_timer.daemon = True
        self._idle_timer.start()
        logger.debug("Idle floor armed for %.1fs", delay)

    def _fire_idle(self):
        """Forced mutation: the network has been quiet too long."""
        idle_for = time.time() - self.last_trigger
        if idle_for < IDLE_FLOOR_MIN:
            # A threat-driven mutation landed while this timer was pending.
            # Firing now would mutate twice in quick succession for no
            # reason, so stand down and re-arm.
            self._arm_idle_timer()
            return

        self.trigger_count += 1
        self.last_trigger   = time.time()
        logger.warning("IDLE FLOOR TRIGGER #%d — quiet for %.1fs, mutating anyway",
                       self.trigger_count, idle_for)
        self._log_trigger('adaptive_floor_idle', None, 0)
        # No detection preceded this, so there is no detection segment to
        # measure. None keeps it out of the response-time statistics rather
        # than polluting them with a zero.
        self.mutation_module.pending_detect_ts = None
        self.mutation_module.trigger_mutation()
        self._arm_idle_timer()

    def stop_idle_floor(self):
        if self._idle_timer:
            self._idle_timer.cancel()
            logger.info("Idle floor stopped")

    # ── Adaptive Mode ─────────────────────────────────────────────────────────

    def on_threat_detected(self, attacker_ip, score, detect_ts=None):
        """
        Called by ThreatScoringEngine when the threshold is exceeded.

        detect_ts defaults to None so that a threat engine which does not
        supply it still works; the mutation module then reports the
        detection segment as unmeasured rather than substituting the
        trigger time, which would fake a measured zero.

        The timestamp is handed over as an attribute rather than as an
        argument to trigger_mutation(). The legacy MutationModule accepts
        only (attacker_ip), so passing a second argument would break the
        old controllers outright; setting an attribute they never read
        leaves them untouched.
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
        self._log_trigger(self.mode, attacker_ip, score)
        self.mutation_module.pending_detect_ts = detect_ts
        self.mutation_module.trigger_mutation(attacker_ip)
        # Threat activity resets the silence clock.
        self._arm_idle_timer()

    # ── Baseline Mode ─────────────────────────────────────────────────────────

    def _start_baseline_timer(self):
        """Fire mutations on a fixed interval regardless of traffic."""
        logger.info("Baseline timer started (interval=%ds)", BASELINE_INTERVAL)
        self._fire_baseline()

    def _fire_baseline(self):
        self.trigger_count += 1
        logger.info("BASELINE TRIGGER #%d (fixed interval)", self.trigger_count)
        self._log_trigger('baseline', None, 0)
        # No detection precedes a timer tick, so there is no detection
        # segment to measure. Left as None rather than set to now(), which
        # would report a response time of zero for a system that never
        # responded to anything.
        self.mutation_module.pending_detect_ts = None
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
