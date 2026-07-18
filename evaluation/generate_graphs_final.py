"""
Generate the seven final figures for the MTD-SDN report (three-arm data).
Values are the measured results from the RHM pipeline session.
Light theme, consistent with the group's existing figures.
"""
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
import math
from collections import Counter

OUT = "results/graphs"
BLUE   = "#1f77b4"
ORANGE = "#ff7f0e"
GREEN  = "#2ca02c"
GREY   = "#7f7f7f"
plt.rcParams.update({"font.size": 12, "axes.grid": True,
                     "grid.alpha": 0.35, "figure.dpi": 150})

def save(name):
    plt.tight_layout()
    plt.savefig("%s/%s.png" % (OUT, name), bbox_inches="tight")
    plt.close()
    print("wrote", name)

# ---- measured data ---------------------------------------------------------
arms = ["Baseline", "Adaptive", "Adaptive+Floor"]

f1_trigger = [0.941, 0.000, 0.000]
f1_install = [0.971, 0.989, 0.987]

rdr        = [0.6375, 0.0029, 0.5111]   # adaptive from clean-pipeline ablation run

entropy    = {"Baseline": 0.000, "Adaptive+Floor": 2.117}
bin_widths = [1, 2, 5, 10, 15]
H_base     = [0.0, 0.0, 0.0, 0.0, 0.0]
H_adapt    = [3.418, 3.022, 2.117, 1.281, 1.281]

adaptive_intervals = [32.3, 26.2, 23.6, 36.0, 36.7, 26.5, 31.8, 10.1, 28.1, 27.7, 25.7, 22.6]
baseline_intervals = [30.008, 30.012, 30.01, 30.008, 30.009, 30.013, 30.007, 30.01, 30.008, 30.008, 30.009]

resp_labels = ["detection\u2192trigger", "trigger\u2192install", "detection\u2192install"]
resp_mean   = [0.0003, 2.0406, 1.9895]
resp_max    = [0.0004, 3.635, 3.6353]

install_spread_adaptive = 1.2916
install_spread_baseline = 0.0012

scale_N       = [4, 8, 16, 32]
scale_cpu     = [0.5, 1.625, 2.875, 0.75]     # N=32 idle (iperf failed) -> annotate
scale_window  = [None, 1.1799, 1.4345, None]
scale_pernode = [51.47, None, None, 46.907]

# ===========================================================================
# 1. Fingerprint detectability - the headline
# ===========================================================================
x = np.arange(len(arms)); w = 0.38
fig, ax = plt.subplots(figsize=(8, 5))
b1 = ax.bar(x - w/2, f1_trigger, w, label="Pinpointing trigger instant", color=BLUE)
b2 = ax.bar(x + w/2, f1_install, w, label="Detecting installs (all FLOW_MODs)", color=ORANGE)
ax.set_ylabel("Classifier F1 score")
ax.set_title("Fingerprint Detectability (Random Forest)  \u2014  lower is better")
ax.set_xticks(x); ax.set_xticklabels(arms)
ax.set_ylim(0, 1.08)
ax.legend()
for bars in (b1, b2):
    for r in bars:
        h = r.get_height()
        ax.annotate("%.3f" % h, (r.get_x()+r.get_width()/2, h),
                    ha="center", va="bottom", fontsize=10,
                    xytext=(0, 2), textcoords="offset points")
# make the two 0.000 bars legible as a labelled zero
for xi in (1, 2):
    ax.annotate("0.000", (x[xi]-w/2, 0), ha="center", va="bottom",
                fontsize=10, xytext=(0, 2), textcoords="offset points")
save("01_fingerprint_detectability")

# ===========================================================================
# 2. RDR - three arms
# ===========================================================================
fig, ax = plt.subplots(figsize=(8, 5))
cols = [BLUE, ORANGE, GREEN]
bars = ax.bar(arms, rdr, color=cols, width=0.6)
ax.set_ylabel("Reconnaissance Disruption Rate")
ax.set_title("Reconnaissance Disruption Rate  \u2014  higher is better")
ax.set_ylim(0, 0.75)
for r, v in zip(bars, rdr):
    ax.annotate("%.3f" % v, (r.get_x()+r.get_width()/2, v),
                ha="center", va="bottom", fontsize=11,
                xytext=(0, 2), textcoords="offset points")
ax.annotate("blind to a\npatient attacker", (1, rdr[1]),
            ha="center", va="bottom", fontsize=9, color=GREY,
            xytext=(0, 18), textcoords="offset points")
save("02_rdr")

# ===========================================================================
# 3. Mutation timing entropy + robustness
# ===========================================================================
fig, axes = plt.subplots(1, 2, figsize=(12, 4.6))
axes[0].bar(["Baseline", "Adaptive"], [entropy["Baseline"], entropy["Adaptive+Floor"]],
            color=[BLUE, GREEN], width=0.55)
axes[0].set_ylabel("Entropy H(X) (bits)")
axes[0].set_title("Mutation Timing Entropy (5 s bins)")
axes[0].set_ylim(0, 2.5)
for i, v in enumerate([entropy["Baseline"], entropy["Adaptive+Floor"]]):
    axes[0].annotate("%.3f" % v, (i, v), ha="center", va="bottom",
                     fontsize=11, xytext=(0, 2), textcoords="offset points")

axes[1].plot(bin_widths, H_adapt, "o-", color=GREEN, label="Adaptive")
axes[1].plot(bin_widths, H_base, "s--", color=BLUE, label="Baseline")
axes[1].set_xlabel("Bin width (s)")
axes[1].set_ylabel("Entropy H(X) (bits)")
axes[1].set_title("Entropy vs Bin Width (robustness)")
axes[1].set_ylim(-0.15, 3.6)
axes[1].legend()
save("03_entropy")

# ===========================================================================
# 4. Inter-mutation intervals - the three schedules
# ===========================================================================
fig, ax = plt.subplots(figsize=(9, 5))
ax.plot(range(1, len(adaptive_intervals)+1), adaptive_intervals,
        "o-", color=GREEN, label="Adaptive+Floor (irregular)")
ax.plot(range(1, len(baseline_intervals)+1), baseline_intervals,
        "s--", color=BLUE, label="Baseline (fixed 30 s)")
ax.set_xlabel("Mutation number")
ax.set_ylabel("Interval since previous mutation (s)")
ax.set_title("Inter-Mutation Intervals")
ax.set_ylim(0, 40)
ax.legend()
save("04_intervals")

# ===========================================================================
# 5. Response time - three segments
# ===========================================================================
fig, ax = plt.subplots(figsize=(8.5, 5))
y = np.arange(len(resp_labels))
ax.barh(y, resp_mean, color=[GREY, ORANGE, GREEN], height=0.55)
ax.set_yticks(y); ax.set_yticklabels(resp_labels)
ax.set_xlabel("Time (s)")
ax.set_title("Response Time by Segment (mean)")
ax.invert_yaxis()
for i, (m, mx) in enumerate(zip(resp_mean, resp_max)):
    ax.annotate("mean %.3f s  (max %.2f s)" % (m, mx), (m, i),
                va="center", ha="left", fontsize=10,
                xytext=(4, 0), textcoords="offset points")
ax.set_xlim(0, 3.0)
save("05_response_time")

# ===========================================================================
# 6. Install spread - adaptive vs baseline (log scale to show 3 orders)
# ===========================================================================
fig, ax = plt.subplots(figsize=(7, 5))
bars = ax.bar(["Adaptive+Floor\n(staggered)", "Baseline\n(simultaneous)"],
              [install_spread_adaptive, install_spread_baseline],
              color=[GREEN, BLUE], width=0.5)
ax.set_yscale("log")
ax.set_ylabel("Mean install spread per mutation (s, log scale)")
ax.set_title("Install Spread: Staggered vs Simultaneous")
for r, v in zip(bars, [install_spread_adaptive, install_spread_baseline]):
    ax.annotate("%.4f s" % v, (r.get_x()+r.get_width()/2, v),
                ha="center", va="bottom", fontsize=11,
                xytext=(0, 2), textcoords="offset points")
save("06_install_spread")

# ===========================================================================
# 7. Scalability - CPU + install window vs N (clean signal)
# ===========================================================================
fig, ax1 = plt.subplots(figsize=(9, 5))
# use 4,8,16 for CPU trend (N=32 idle-biased); mark N=32 separately
N_trend = [4, 8, 16]
cpu_trend = [0.5, 1.625, 2.875]
ax1.plot(N_trend, cpu_trend, "o-", color=BLUE, label="Controller CPU (%)")
ax1.scatter([32], [0.75], color=BLUE, marker="x", s=70, zorder=5)
ax1.annotate("N=32 CPU idle-biased\n(iperf incomplete)", (32, 0.75),
             ha="right", va="bottom", fontsize=8, color=GREY,
             xytext=(-6, 6), textcoords="offset points")
ax1.set_xlabel("Number of hosts (N)")
ax1.set_ylabel("Controller CPU (%)", color=BLUE)
ax1.tick_params(axis="y", labelcolor=BLUE)
ax1.set_xticks(scale_N)

ax2 = ax1.twinx()
win_N = [8, 16]; win_v = [1.1799, 1.4345]
ax2.plot(win_N, win_v, "s--", color=ORANGE, label="Install window (s)")
ax2.set_ylabel("Mean install window (s)", color=ORANGE)
ax2.tick_params(axis="y", labelcolor=ORANGE)
ax2.set_ylim(0, 2.0)
ax2.grid(False)

plt.title("Scalability: Controller Cost vs Network Size")
lines1, labels1 = ax1.get_legend_handles_labels()
lines2, labels2 = ax2.get_legend_handles_labels()
ax1.legend(lines1 + lines2, labels1 + labels2, loc="upper left")
save("07_scalability")

print("ALL FIGURES DONE")
