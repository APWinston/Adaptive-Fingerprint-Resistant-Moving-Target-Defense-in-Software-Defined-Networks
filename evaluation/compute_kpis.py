"""
KPI Calculator (v2)
===================
Computes all five proposal KPIs from the RHM re-architecture runs.

WHAT CHANGED AND WHY
--------------------

1. ENTROPY IS NOW BINNED AT A FIXED WIDTH, AND READ FROM THE INSTALL TRACE.

   The old estimator set its bin width from each series' own range:

       width = (max - min) / 5

   Baseline inter-mutation intervals are 30.004 .. 30.009s - five
   MILLISECONDS of scheduler jitter. That range produced 1ms bins, the
   jitter spread across all five of them, and a perfect metronome scored
   1.906 bits: HIGHER than the adaptive system's 1.352. The KPI inverted
   and would have destroyed the claim it was meant to support.

   Two series binned at two different widths are not comparable. A fixed
   width is applied to both, and reported alongside the result. At every
   width from 1s to 15s the baseline scores exactly 0.000 - which is what
   a fixed timer IS - and the adaptive system scores 0.9 to 2.4.

   The old code also derived mutation times from the experiment log, which
   samples a CUMULATIVE COUNTER every 5s. Mutations that fired before
   collection started all collapsed onto elapsed_s=0, inventing intervals
   of 0s that the 5s cooldown makes impossible, and mutations after the
   last sample vanished entirely. install_trace.log carries an exact
   trigger_ts per mutation. That is the source of truth here.

2. RDR IS MEASURED, NOT MODELLED.

   The old rdr() computed mutations / threat_events - a cooldown pass
   rate. It read 0.50 on a run with ~10 threshold crossings and 0.004 on a
   run with ~2000: the defence did not change, the denominator did. Real
   RDR now comes from evaluation/rdr_test.py, which counts probes to
   addresses the attacker actually discovered.

3. RESPONSE TIME IS REPORTED AS THREE SEGMENTS.

   The proposal defines Response Time = t_trigger - t_detection. The code
   measured install_ts - trigger_ts, which is the NEXT segment, and the
   graph axis said "detection to install delay", which is the whole span.
   Three different quantities were being treated as one number. All three
   are now reported separately:

       detection -> trigger   the proposal's formula
       trigger   -> install   what was previously reported as 1.93s
       detection -> install   end-to-end, what the graph plotted

   Expect detection -> trigger to be near zero: the threat engine calls
   the trigger inline, so there is no queue between them. That is a real
   finding, not a bug - it means the end-to-end figure is dominated by the
   deliberate stagger window, which is the interesting part.

4. INSTALL SPREAD GROUPS ON (mode, mutation_id).

   mutation_id restarts at 1 each run. Grouping on the id alone merges an
   adaptive mutation #1 with a baseline mutation #1 whenever two runs land
   in one trace file, turning a ~1s spread into the gap between two runs.

USAGE
-----
  python3 evaluation/compute_kpis.py \
      --adaptive-trace results/install_trace_rhm_adaptive.log \
      --baseline-trace results/install_trace_rhm_baseline.log \
      --rdr-adaptive   results/rdr_adaptive_*.json \
      --rdr-baseline   results/rdr_baseline_*.json \
      --scalability    results/scalability_*.jsonl \
      --f1-install-adaptive 0.741 --f1-install-baseline 0.833 \
      --f1-trigger-adaptive 0.000 --f1-trigger-baseline 0.958

Every argument is optional; whatever is missing is reported as N/A rather
than guessed.

Group 46 - Adaptive Fingerprint-Resistant MTD in SDN
"""

import argparse
import glob
import json
import math
import os
from collections import Counter

BIN_WIDTHS = [1, 2, 5, 10, 15]     # robustness sweep
DEFAULT_BIN = 5.0


# ------------------------------------------------------------------ loading
def load_jsonl(path):
    out = []
    if not path or not os.path.exists(path):
        return out
    with open(path) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                out.append(json.loads(line))
            except json.JSONDecodeError:
                pass
    return out


def resolve(pattern):
    """Accept a literal path or a glob; return the newest match."""
    if not pattern:
        return None
    if os.path.exists(pattern):
        return pattern
    files = glob.glob(pattern)
    return max(files, key=os.path.getmtime) if files else None


# ------------------------------------------------------------------ trace parsing
def trigger_times(trace):
    """
    One exact trigger timestamp per mutation.

    Every switch logs its own line for the same mutation, so the trace is
    deduplicated on (mode, mutation_id) before the intervals are taken -
    otherwise a 2-switch run would report each interval twice and a zero
    between the pair.
    """
    per = {}
    for e in trace:
        key = (e.get("mode", "?"), e.get("mutation_id"))
        if key not in per:
            per[key] = float(e["trigger_ts"])
    return sorted(per.values())


def intervals_of(times):
    return [times[i + 1] - times[i] for i in range(len(times) - 1)]


def install_spread(trace):
    """Mean/min/max spread between first and last switch install per mutation."""
    per = {}
    for e in trace:
        key = (e.get("mode", "?"), e.get("mutation_id"))
        per.setdefault(key, []).append(float(e["install_ts"]))
    spreads = [max(v) - min(v) for v in per.values() if len(v) > 1]
    if not spreads:
        return None, None, None, 0
    return (round(sum(spreads) / len(spreads), 4),
            round(min(spreads), 4), round(max(spreads), 4), len(spreads))


def response_segments(trace):
    """
    The three segments of the response path.

    detect_ts is only present if the controller threaded it through (see
    the threat_engine / mtd_trigger patches). Older traces simply report
    N/A for the segments that need it rather than silently substituting
    trigger_ts, which would make detection->trigger look like a measured
    zero when it was never measured at all.
    """
    d2t, t2i, d2i = [], [], []
    for e in trace:
        trig = float(e["trigger_ts"])
        inst = float(e["install_ts"])
        t2i.append(inst - trig)
        det = e.get("detect_ts")
        if det is not None:
            det = float(det)
            d2t.append(trig - det)
            d2i.append(inst - det)

    def stat(vals):
        if not vals:
            return None, None, 0
        return round(sum(vals) / len(vals), 4), round(max(vals), 4), len(vals)

    return {
        "detect_to_trigger":  stat(d2t),
        "trigger_to_install": stat(t2i),
        "detect_to_install":  stat(d2i),
    }


# ------------------------------------------------------------------ entropy
def shannon_entropy(intervals, width=DEFAULT_BIN):
    """
    H(X) over inter-mutation intervals, binned at a FIXED width.

    The bin width is a methodological choice and must be identical for
    every series being compared, and stated in the write-up. Deriving it
    from each series' own range (the previous behaviour) silently
    rescales the measurement per series and makes the numbers
    incomparable.

    abs() is applied because a single-bin distribution computes -0.0.
    """
    if len(intervals) < 2:
        return None
    counts = Counter(int(v // width) for v in intervals)
    n = len(intervals)
    h = -sum((c / n) * math.log2(c / n) for c in counts.values())
    return round(abs(h), 3)


def entropy_ceiling(intervals):
    """
    Maximum attainable H for this many samples: log2(n), reached only if
    every interval lands in its own bin. Reported because adaptive and
    baseline runs rarely have the same mutation count, so their ceilings
    differ and the raw H values are not on quite the same scale.
    """
    n = len(intervals)
    return round(math.log2(n), 3) if n > 1 else None


# ------------------------------------------------------------------ RDR
def read_rdr(path):
    if not path or not os.path.exists(path):
        return None
    with open(path) as f:
        d = json.load(f)
    return {
        "rdr":            d.get("rdr"),
        "attempts":       d.get("attempts"),
        "successes":      d.get("successes"),
        "discovered":     len(d.get("discovered", [])),
        "first_failure":  d.get("first_failure_s"),
        "window":         d.get("window_s"),
    }


# ------------------------------------------------------------------ scalability
def read_scalability(path):
    rows = load_jsonl(path)
    return sorted(rows, key=lambda r: r.get("n_hosts", 0))


# ------------------------------------------------------------------ reporting
def fmt(v, suffix=""):
    return "N/A" if v is None else ("%s%s" % (v, suffix))


def main():
    ap = argparse.ArgumentParser(description="MTD KPI calculator v2 (Group 46)")
    ap.add_argument("--adaptive-trace", default="results/install_trace_rhm_adaptive.log")
    ap.add_argument("--baseline-trace", default="results/install_trace_rhm_baseline.log")
    ap.add_argument("--rdr-adaptive", default="results/rdr_adaptive_*.json")
    ap.add_argument("--rdr-baseline", default="results/rdr_baseline_*.json")
    ap.add_argument("--scalability", default="results/scalability_*.jsonl")
    ap.add_argument("--bin-width", type=float, default=DEFAULT_BIN)
    ap.add_argument("--f1-install-adaptive", type=float, default=None)
    ap.add_argument("--f1-install-baseline", type=float, default=None)
    ap.add_argument("--f1-trigger-adaptive", type=float, default=None)
    ap.add_argument("--f1-trigger-baseline", type=float, default=None)
    ap.add_argument("--throughput", type=float, default=None,
                    help="single-topology aggregate Mbps, if not using the sweep")
    ap.add_argument("--nodes", type=int, default=None)
    args = ap.parse_args()

    a_path = resolve(args.adaptive_trace)
    b_path = resolve(args.baseline_trace)
    a_trace = load_jsonl(a_path)
    b_trace = load_jsonl(b_path)

    a_times, b_times = trigger_times(a_trace), trigger_times(b_trace)
    a_int,  b_int    = intervals_of(a_times), intervals_of(b_times)

    W = "=" * 72
    print("\n" + W)
    print("  MTD-SDN KPI REPORT v2  -  Group 46")
    print(W)
    print("  Adaptive trace : %s (%d installs, %d mutations)"
          % (a_path or "not found", len(a_trace), len(a_times)))
    print("  Baseline trace : %s (%d installs, %d mutations)"
          % (b_path or "not found", len(b_trace), len(b_times)))
    if a_times:
        print("  Adaptive run span : %.1fs" % (a_times[-1] - a_times[0]))
    if b_times:
        print("  Baseline run span : %.1fs" % (b_times[-1] - b_times[0]))
    print(W)

    # ---- KPI 1: Fingerprint resistance ---------------------------------
    print("\n[1] FINGERPRINT RESISTANCE  (Random Forest F1; lower = better defence)")
    print("-" * 72)
    print("    %-34s%14s%14s" % ("attacker task", "baseline", "adaptive"))
    print("    %-34s%14s%14s" % ("pinpointing trigger instant",
                                 fmt(args.f1_trigger_baseline),
                                 fmt(args.f1_trigger_adaptive)))
    print("    %-34s%14s%14s" % ("detecting installs (all FLOW_MODs)",
                                 fmt(args.f1_install_baseline),
                                 fmt(args.f1_install_adaptive)))
    print("    Supplied from fingerprint_classifier.py. The proposal's ARI is not")
    print("    computed: it scored a hand-written attacker model rather than a real")
    print("    one, and assumed its own conclusion.")

    # ---- KPI 2: RDR -----------------------------------------------------
    ra = read_rdr(resolve(args.rdr_adaptive))
    rb = read_rdr(resolve(args.rdr_baseline))
    print("\n[2] RECONNAISSANCE DISRUPTION RATE  (1 - successes/attempts)")
    print("-" * 72)
    if ra or rb:
        print("    %-34s%14s%14s" % ("", "baseline", "adaptive"))
        print("    %-34s%14s%14s" % ("RDR",
                                     fmt(rb and rb["rdr"]), fmt(ra and ra["rdr"])))
        print("    %-34s%14s%14s" % ("attempts",
                                     fmt(rb and rb["attempts"]), fmt(ra and ra["attempts"])))
        print("    %-34s%14s%14s" % ("successes",
                                     fmt(rb and rb["successes"]), fmt(ra and ra["successes"])))
        print("    %-34s%14s%14s" % ("addresses discovered",
                                     fmt(rb and rb["discovered"]), fmt(ra and ra["discovered"])))
        print("    %-34s%14s%14s" % ("knowledge stale after (s)",
                                     fmt(rb and rb["first_failure"]), fmt(ra and ra["first_failure"])))
        wa = ra and ra["window"]
        wb = rb and rb["window"]
        if wa and wb and wa != wb:
            print("    !! WINDOWS DIFFER (%ss vs %ss). RDR grows with the observation" % (wb, wa))
            print("       window, so these two numbers are NOT comparable. Re-run with")
            print("       the same --window on both arms.")
        print("    Both arms carry the identical real-IP shield, so any difference")
        print("    here is a difference in mutation policy, not in reachability.")
    else:
        print("    N/A - run evaluation/rdr_test.py for both arms first.")

    # ---- KPI 3: Scalability ---------------------------------------------
    rows = read_scalability(resolve(args.scalability))
    print("\n[3] SCALABILITY  (aggregate throughput / nodes)")
    print("-" * 72)
    if rows:
        print("    %-8s%-14s%-16s%-12s%-14s"
              % ("N", "aggregate", "per-node", "CPU %", "install win"))
        for r in rows:
            print("    %-8s%-14s%-16s%-12s%-14s"
                  % (r.get("n_hosts"), fmt(r.get("aggregate_mbps")),
                     fmt(r.get("per_node_mbps")), fmt(r.get("controller_cpu_pct")),
                     fmt(r.get("install_window_s"))))
        print("    The KPI is the per-node column AS A TREND. A single N is a ratio,")
        print("    not a scalability result.")
    elif args.throughput and args.nodes:
        print("    %.3f Mbps/node  (%.1f Mbps / %d nodes)"
              % (args.throughput / args.nodes, args.throughput, args.nodes))
        print("    Single point only - no trend. Run evaluation/scalability_test.py")
        print("    to sweep N and get a curve.")
    else:
        print("    N/A - run evaluation/scalability_test.py.")

    # ---- KPI 4: Entropy -------------------------------------------------
    print("\n[4] MUTATION EFFECTIVENESS  H(X) over inter-mutation intervals")
    print("-" * 72)
    a_h = shannon_entropy(a_int, args.bin_width) if a_int else None
    b_h = shannon_entropy(b_int, args.bin_width) if b_int else None
    print("    Bin width %.1fs (FIXED, identical for both series)" % args.bin_width)
    print("    %-34s%14s%14s" % ("", "baseline", "adaptive"))
    print("    %-34s%14s%14s" % ("H(X) bits", fmt(b_h), fmt(a_h)))
    print("    %-34s%14s%14s" % ("ceiling log2(n)",
                                 fmt(entropy_ceiling(b_int)), fmt(entropy_ceiling(a_int))))
    print("    %-34s%14s%14s" % ("intervals (n)", len(b_int), len(a_int)))

    if a_int and b_int:
        print("\n    Robustness across bin widths:")
        print("    %-14s%14s%14s" % ("width (s)", "baseline", "adaptive"))
        for w in BIN_WIDTHS:
            print("    %-14s%14s%14s"
                  % (w, fmt(shannon_entropy(b_int, w)), fmt(shannon_entropy(a_int, w))))
        print("    A conclusion that holds at every width is a property of the data.")
        print("    One that only holds at a single width is a property of the binning.")

    if a_int:
        print("\n    Adaptive intervals: %s" % [round(v, 1) for v in a_int])
    if b_int:
        print("    Baseline intervals: %s" % [round(v, 3) for v in b_int])

    # ---- KPI 5: Response time -------------------------------------------
    print("\n[5] RESPONSE TIME")
    print("-" * 72)
    seg = response_segments(a_trace)
    labels = [
        ("detect_to_trigger",  "detection -> trigger   (proposal formula)"),
        ("trigger_to_install", "trigger   -> install   (stagger window)"),
        ("detect_to_install",  "detection -> install   (end-to-end)"),
    ]
    for key, label in labels:
        mean, worst, n = seg[key]
        print("    %-42s mean %s  max %s  (n=%s)"
              % (label, fmt(mean, "s"), fmt(worst, "s"), n))
    if seg["detect_to_trigger"][2] == 0:
        print("    detection -> trigger is N/A: this trace has no detect_ts. Apply the")
        print("    threat_engine.py / mtd_trigger.py patches and re-run to measure it.")

    win, lo, hi, n = install_spread(a_trace)
    print("\n    Install spread (adaptive): mean %s  range %s - %s  (n=%s)"
          % (fmt(win, "s"), fmt(lo, "s"), fmt(hi, "s"), n))
    bwin, blo, bhi, bn = install_spread(b_trace)
    print("    Install spread (baseline): mean %s  range %s - %s  (n=%s)"
          % (fmt(bwin, "s"), fmt(blo, "s"), fmt(bhi, "s"), bn))
    print("    Baseline spread is MEASURED here, not asserted as 0. A simultaneous")
    print("    install is not exactly instantaneous, and a measured sub-millisecond")
    print("    figure is stronger evidence than a hardcoded zero.")

    print("\n" + W)


if __name__ == '__main__':
    main()
