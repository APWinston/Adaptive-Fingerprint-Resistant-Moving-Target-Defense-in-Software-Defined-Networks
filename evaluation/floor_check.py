"""
Idle Floor Randomness Check
===========================
The adaptive_floor run produced inter-mutation gaps of

    [45.2, 46.7, 47.9, 43.9]

when they should have been drawn from uniform(30, 60). All four landed
inside a 4-second window around 45 - the distribution's MEAN. Four
independent draws from a 30-second range falling that close together has
probability ~0.0003.

That matters more than the RDR number it produced. A floor that fires on a
near-constant 45s rhythm is a fixed timer wearing a disguise, and a Random
Forest will pinpoint its trigger instants exactly as it does the 30s
baseline's (F1 0.958). The floor would then have bought reconnaissance
disruption by destroying the fingerprint resistance it exists to protect.

Running the MTDTrigger class directly, with the floor scaled down 100x,
produces a correct full-width spread. So the logic is sound and the
difference must be the environment: ryu-manager runs under eventlet, which
monkey-patches threading.Timer, time.sleep and the rest.

This script runs the identical test twice - once plain, once with eventlet
patched in exactly as ryu does it - and compares. Whichever one flattens is
the culprit.

Run on the VM, where ryu's eventlet is installed:

    python3 evaluation/floor_check.py

Group 46 - Adaptive Fingerprint-Resistant MTD in SDN
"""

import subprocess
import sys
import textwrap


# The probe runs in a subprocess so the "plain" case is genuinely
# unpatched: eventlet.monkey_patch() is global and irreversible once
# applied, so both cases cannot share one interpreter.
PROBE = textwrap.dedent('''
    import sys
    PATCH = {patch}
    if PATCH:
        import eventlet
        eventlet.monkey_patch()

    import random, time
    from threading import Timer

    LO, HI = 0.30, 0.60      # the real floor is 30-60s, scaled 100x
    fires  = []
    state  = {{"timer": None, "stop": False}}

    def arm():
        if state["stop"]:
            return
        if state["timer"]:
            state["timer"].cancel()
        d = random.uniform(LO, HI)
        state["timer"] = Timer(d, fire)
        state["timer"].daemon = True
        state["timer"].start()

    def fire():
        fires.append(time.time())
        arm()

    arm()
    t0 = time.time()
    while time.time() - t0 < 10:
        time.sleep(0.05)
    state["stop"] = True
    if state["timer"]:
        state["timer"].cancel()

    gaps = [round(fires[i+1]-fires[i], 3) for i in range(len(fires)-1)]
    print(repr(gaps))
''')


def run(patch):
    out = subprocess.run([sys.executable, "-c", PROBE.format(patch=patch)],
                         capture_output=True, text=True, timeout=60)
    if out.returncode != 0:
        return None, out.stderr.strip()
    try:
        return eval(out.stdout.strip().splitlines()[-1]), None
    except Exception as exc:
        return None, "could not parse: %s (%s)" % (out.stdout.strip(), exc)


def report(name, gaps):
    if not gaps:
        print("  %-22s no gaps captured" % name)
        return None
    lo, hi = min(gaps), max(gaps)
    spread = hi - lo
    mean = sum(gaps) / len(gaps)
    print("  %-22s n=%-3d  range %.3f-%.3f  spread %.3f  mean %.3f"
          % (name, len(gaps), lo, hi, spread, mean))
    return spread


def main():
    print("\n" + "=" * 70)
    print("  IDLE FLOOR RANDOMNESS CHECK  -  Group 46")
    print("=" * 70)
    print("  Floor scaled to uniform(0.30, 0.60)s; 10s per case.")
    print("  A healthy floor spreads across ~0.30 of range.")
    print("  A flattened one clusters near the 0.45 mean.\n")

    plain, err1 = run(False)
    if err1:
        print("  plain run failed: %s" % err1)
    ev, err2 = run(True)
    if err2:
        print("  eventlet run failed: %s" % err2)
        print("  (is eventlet importable here? ryu depends on it)")

    s_plain = report("plain python", plain)
    s_event = report("eventlet patched", ev)

    print("\n" + "-" * 70)
    if s_plain is None or s_event is None:
        print("  Inconclusive - one case did not run.")
        return

    # A correct floor spans most of its 0.30 range. Anything under half of
    # that is clustering hard enough to be a rhythm rather than a draw.
    THRESH = 0.15
    if s_event < THRESH <= s_plain:
        print("  VERDICT: eventlet is flattening the timer.")
        print("  threading.Timer under ryu is not honouring the random delay.")
        print("  Fix: drive the floor from a loop that re-checks elapsed time,")
        print("  rather than scheduling a single Timer for the whole interval.")
    elif s_event >= THRESH and s_plain >= THRESH:
        print("  VERDICT: both spread correctly. The timer is NOT the problem.")
        print("  The 4 observed gaps were most likely a fluke of a tiny sample.")
        print("  Re-run adaptive_floor and collect more gaps before concluding;")
        print("  a 350s run gives ~7, which is still few but far more telling.")
    else:
        print("  VERDICT: unexpected - plain flattened too. Inspect by hand.")
    print("=" * 70)


if __name__ == '__main__':
    main()
