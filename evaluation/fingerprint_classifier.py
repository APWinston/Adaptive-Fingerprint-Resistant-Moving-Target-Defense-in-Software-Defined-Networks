"""
Real Fingerprint Classifier (MTDSense-style)
============================================
Trains a Random Forest to detect MTD mutations from captured control-plane
traffic - the approach MTDSense uses.

WHY THIS PARSES OPENFLOW RATHER THAN COUNTING PACKETS
-----------------------------------------------------
A capture taken during an Nmap sweep is dominated by thousands of scan
packets. Each mutation only produces a handful of flow-rule messages, so
raw packet counts per time window cannot separate the two - the signal is
buried in scan noise.

What a control-channel observer actually watches is the OpenFlow FLOW_MOD
messages that reprogram a switch. This script therefore parses the
OpenFlow 1.3 headers inside the TCP payloads and counts FLOW_MODs only.

The controller also emits FLOW_MODs for ordinary L2 forwarding during a
scan, but those use priority 1, while mutation rules use priority 100
(set in mutation_module.py). Filtering on priority isolates the mutation
traffic exactly.

Expected result:
  BASELINE (simultaneous) -> all FLOW_MODs in one instant -> easy to detect
  ADAPTIVE (staggered)    -> FLOW_MODs smeared over 0.5-2.0s -> hard to detect

Usage:
  # see what is actually in the capture first
  python fingerprint_classifier.py --pcap X.pcap --trace Y.log --inspect

  # then classify
  python fingerprint_classifier.py --pcap X.pcap --trace Y.log --mode baseline

Group 46 - Adaptive Fingerprint-Resistant MTD in SDN
"""

import argparse, json, os, sys
from collections import Counter

try:
    from scapy.all import rdpcap, TCP, Raw
except ImportError:
    sys.exit("[!] scapy not found. Install with:  pip install scapy")
try:
    import numpy as np
    from sklearn.ensemble import RandomForestClassifier
    from sklearn.model_selection import cross_val_predict, StratifiedKFold
    from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score
except ImportError:
    sys.exit("[!] scikit-learn/numpy not found. Install with:  pip install scikit-learn numpy")

WINDOW      = 0.25   # seconds per analysis window
SPREAD      = 1      # label +/- this many windows around each trigger
OF_VERSION  = 0x04   # OpenFlow 1.3
OFPT_FLOW_MOD = 14
MUTATION_PRIORITY = 100   # priority used by mutation_module.py


def parse_flowmods(pcap_path):
    """
    Walk every TCP payload, decode OpenFlow 1.3 message headers, and return
    a list of (timestamp, priority) for each FLOW_MOD found.

    OF 1.3 header:  version(1) type(1) length(2) xid(4)
    FLOW_MOD body:  cookie(8) cookie_mask(8) table_id(1) command(1)
                    idle_timeout(2) hard_timeout(2) priority(2) ...
    -> priority sits at offset 30 within the message.
    """
    if not os.path.exists(pcap_path):
        sys.exit(f"[!] pcap not found: {pcap_path}")
    print(f"[*] Reading {pcap_path} ...")
    pkts = rdpcap(pcap_path)
    if len(pkts) == 0:
        sys.exit("[!] No packets in capture.")

    flowmods = []
    all_times = []
    for p in pkts:
        all_times.append(float(p.time))
        if not (p.haslayer(TCP) and p.haslayer(Raw)):
            continue
        data = bytes(p[Raw].load)
        off = 0
        # a single TCP segment may carry several OpenFlow messages
        while off + 8 <= len(data):
            if data[off] != OF_VERSION:
                break
            mtype = data[off + 1]
            mlen  = int.from_bytes(data[off + 2:off + 4], "big")
            if mlen < 8 or off + mlen > len(data):
                break
            if mtype == OFPT_FLOW_MOD and off + 32 <= len(data):
                prio = int.from_bytes(data[off + 30:off + 32], "big")
                flowmods.append((float(p.time), prio))
            off += mlen
    return flowmods, sorted(all_times)


def load_triggers(trace_path):
    if not os.path.exists(trace_path):
        sys.exit(f"[!] install trace not found: {trace_path}")
    rows = []
    with open(trace_path) as f:
        for line in f:
            line = line.strip()
            if line:
                try:
                    rows.append(json.loads(line))
                except json.JSONDecodeError:
                    pass
    if not rows:
        sys.exit("[!] install trace is empty.")
    modes = {r.get("mode", "?") for r in rows}
    triggers = sorted({round(float(r["trigger_ts"]), 4) for r in rows})
    installs = sorted({round(float(r["install_ts"]), 4) for r in rows})
    delays = [float(r.get("install_delay", 0)) for r in rows]
    return triggers, modes, delays, installs


def build_dataset(event_times, triggers, t_lo, t_hi):
    span  = t_hi - t_lo
    nbins = int(span / WINDOW) + 1
    counts = [0] * nbins
    for t in event_times:
        b = int((t - t_lo) / WINDOW)
        if 0 <= b < nbins:
            counts[b] += 1

    labels = [0] * nbins
    inside = 0
    for tg in triggers:
        bi = int((tg - t_lo) / WINDOW)
        if 0 <= bi < nbins:
            inside += 1
            for d in range(-SPREAD, SPREAD + 1):
                j = bi + d
                if 0 <= j < nbins:
                    labels[j] = 1

    feats = []
    for i in range(nbins):
        p1 = counts[i-1] if i-1 >= 0 else 0
        p2 = counts[i-2] if i-2 >= 0 else 0
        n1 = counts[i+1] if i+1 < nbins else 0
        n2 = counts[i+2] if i+2 < nbins else 0
        nb = (p1 + p2 + n1 + n2) / 4.0
        feats.append([counts[i], p1, p2, n1, n2,
                      counts[i] - nb,                    # burst sharpness
                      counts[i] / (nb + 1e-6)])          # relative spike
    return np.array(feats), np.array(labels), nbins, inside, span


def main():
    ap = argparse.ArgumentParser(description="MTDSense-style fingerprint classifier")
    ap.add_argument("--pcap", required=True)
    ap.add_argument("--trace", required=True)
    ap.add_argument("--mode", default="run")
    ap.add_argument("--inspect", action="store_true",
                    help="only report what is in the capture, do not classify")
    ap.add_argument("--label-installs", action="store_true",
                    help="label the INSTALL instants instead of the trigger instants. "
                         "Tests whether the attacker can spot each switch's install "
                         "burst even when it cannot pinpoint the mutation trigger.")
    ap.add_argument("--any-priority", action="store_true",
                    help="use all FLOW_MODs, not just mutation-priority ones")
    args = ap.parse_args()

    flowmods, all_times = parse_flowmods(args.pcap)
    triggers, modes, delays, installs = load_triggers(args.trace)

    prios = Counter(p for _, p in flowmods)
    print(f"[*] {len(all_times)} packets captured, span {all_times[-1]-all_times[0]:.1f}s")
    print(f"[*] {len(flowmods)} FLOW_MOD messages decoded")
    print(f"[*] FLOW_MOD priorities seen: {dict(sorted(prios.items()))}")
    print(f"[*] {len(triggers)} mutations in trace | install mode: {', '.join(modes)}")
    if delays:
        print(f"[*] install delay: min {min(delays):.3f}s  max {max(delays):.3f}s")

    if args.inspect:
        print("\n[*] --inspect only; stopping here.")
        return

    if not flowmods:
        sys.exit("[!] No FLOW_MOD messages found in the capture.\n"
                 "    The capture likely missed the control channel.\n"
                 "    Ensure tcpdump captured loopback traffic on port 6633.")

    if args.any_priority:
        events = [t for t, _ in flowmods]
        label = "all FLOW_MODs"
    else:
        events = [t for t, p in flowmods if p == MUTATION_PRIORITY]
        label = f"priority-{MUTATION_PRIORITY} FLOW_MODs"
        if not events:
            print(f"[!] No priority-{MUTATION_PRIORITY} FLOW_MODs found. "
                  f"Falling back to all FLOW_MODs.")
            events = [t for t, _ in flowmods]
            label = "all FLOW_MODs"

    print(f"[*] Using {len(events)} events ({label}) as the observable signal")

    if args.label_installs:
        marks = installs
        mark_kind = "install instants"
    else:
        marks = triggers
        mark_kind = "trigger instants"
    print(f"[*] Labelling {mark_kind} ({len(marks)} marks)")

    t_lo = min(min(events), marks[0])
    t_hi = max(max(events), marks[-1])
    X, y, nbins, inside, span = build_dataset(events, marks, t_lo, t_hi)
    pos = int(y.sum())
    print(f"[*] {nbins} windows of {WINDOW}s | {inside}/{len(marks)} marks inside capture")
    print(f"[*] {pos} mutation windows, {nbins-pos} quiet windows")

    if inside == 0:
        sys.exit("[!] Capture and trace do not overlap - files are from different runs.")
    if pos < 4 or pos >= nbins:
        sys.exit("[!] Not enough labelled windows for a reliable classifier.")

    folds = max(2, min(5, pos))
    clf = RandomForestClassifier(n_estimators=300, random_state=42)
    cv = StratifiedKFold(n_splits=folds, shuffle=True, random_state=42)
    y_pred = cross_val_predict(clf, X, y, cv=cv)

    acc  = accuracy_score(y, y_pred)
    prec = precision_score(y, y_pred, zero_division=0)
    rec  = recall_score(y, y_pred, zero_division=0)
    f1   = f1_score(y, y_pred, zero_division=0)
    base_rate = pos / nbins

    print("\n" + "=" * 60)
    print(f"  FINGERPRINT DETECTION RESULT  -  {args.mode.upper()}")
    print("=" * 60)
    print(f"  Observable:          {label}")
    print(f"  Labelled on:         {mark_kind}")
    print(f"  Classifier:          Random Forest (300 trees, {folds}-fold CV)")
    print(f"  Detection accuracy:  {acc*100:5.1f}%")
    print(f"  Precision:           {prec*100:5.1f}%")
    print(f"  Recall (catch rate): {rec*100:5.1f}%")
    print(f"  F1 score:            {f1:5.3f}")
    print("-" * 60)
    print(f"  {base_rate*100:.1f}% of windows are mutations, so guessing 'quiet'")
    print(f"  every time already scores {(1-base_rate)*100:.1f}% accuracy.")
    print(f"  Judge this by F1, not accuracy.")
    print("-" * 60)
    if f1 >= 0.7:
        print("  Verdict: mutations are DETECTABLE - fingerprintable.")
    elif f1 >= 0.4:
        print("  Verdict: partially detectable - moderate fingerprint risk.")
    elif f1 > 0.05:
        print("  Verdict: barely detectable - strong fingerprint resistance.")
    else:
        print("  Verdict: classifier cannot locate the mutations at all.")
    print("=" * 60 + "\n")


if __name__ == "__main__":
    main()
