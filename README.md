# Adaptive Fingerprint-Resistant MTD in SDN

**Group 46** — Department of Computer Science, KNUST
Supervisor: Dr. Justice Owusu Agyemang

A Moving Target Defense (MTD) system for Software-Defined Networks that resists
machine-learning fingerprinting of its mutation schedule. Mutations are driven
by observed threat activity rather than a fixed timer, installed across a
randomised stagger window, and backed by a randomised idle floor so the defence
never stalls against a patient attacker. The system runs a shielded three-table
address-translation pipeline: real host addresses are unreachable from the data
plane, and only mutating virtual addresses are exposed to an attacker.

## Headline Results (three-arm evaluation)

Lower F1 = better defence; higher RDR = better disruption.

| Metric | Baseline | Adaptive | Adaptive + Floor |
|---|---|---|---|
| Trigger-instant F1 (fingerprint) | 0.941 | 0.000 | 0.000 |
| Install-detection F1 | 0.971 | 0.989 | 0.987 |
| Reconnaissance Disruption Rate | 0.638 | 0.003 | 0.511 |
| Mutation timing entropy (bits) | 0.000 | - | 2.117 |
| Mean response time (s) | - | - | 1.99 |

A real Random Forest classifier pinpoints the fixed baseline mutation instants
at F1 0.941, but scores 0.000 against both adaptive controllers. The randomised
idle floor lifts RDR from 0.003 (pure adaptive, blind to a patient attacker) to
0.511 at no cost to fingerprint resistance.

## The Three Controller Modes

All run the same shielded pipeline; only the mutation policy differs. Mode is
chosen by environment variable.
## Reproducing the Evaluation

One command per arm (runs the full experiment, fails loudly if a stage breaks):
RDR (same --window for every arm):
Scalability sweep (owns its own controller per size):
Fingerprint classifier (Windows-side, two runs per arm):
KPIs and figures:
## Environment

- Ryu 4.34, Mininet 2.3.0, Open vSwitch, OpenFlow 1.3
- Linux VirtualBox VM on a Windows host
- VM login: mininet / mininet  -  ssh -p 2222 mininet@localhost
- Classifier runs on the Windows host (scapy + scikit-learn)

## Known Limitations

- Small emulated topology (5 hosts main runs, up to 32 for scalability).
- Fingerprinting tested against a single classifier family.
- Install-detection stays high across all arms: the schedule is hidden, the
  existence of control traffic is not.
- Host-to-switch location inferred from first packet-in, which mis-assigns some
  hosts at larger N and causes the throughput-measurement artefact in the sweep.

## Superseded Files

Legacy two-arm / dst-only-pipeline code is in archive/ (in the VM), replaced by
mtd_controller_rhm.py, mutation_module_rhm.py, run_attack_rhm.sh, and
generate_graphs_final.py.
