# Adaptive Fingerprint-Resistant MTD in SDN
## Group 46 — First Semester Project

### Project Structure
```
mtd_sdn_project/
├── controller/         # Ryu SDN controller apps
│   ├── threat_engine.py        # Threat Scoring Engine (core)
│   ├── mtd_trigger.py          # Adaptive MTD trigger logic
│   ├── mutation_module.py      # Fingerprint-resistant mutation
│   └── mtd_controller.py      # Main controller (combines all)
│
├── topology/           # Mininet network topologies
│   ├── simple_topo.py          # Basic 2-host test topology
│   └── mtd_topo.py             # Full MTD evaluation topology
│
├── scripts/            # Attack simulation & utility scripts
│   ├── run_attack.sh           # Nmap reconnaissance attack
│   ├── run_baseline.sh         # Run fixed-interval MTD (comparison)
│   └── run_mtd.sh              # Run adaptive MTD system
│
├── evaluation/         # Performance measurement scripts
│   ├── measure_overhead.py     # CPU/memory/latency metrics
│   └── fingerprint_test.py     # Timing analysis / fingerprint test
│
├── tests/              # Unit tests
│   └── test_threat_engine.py
│
├── logs/               # Runtime logs (auto-generated)
├── results/            # Evaluation results/pcap files
├── docs/               # Documentation
└── README.md
```

### How to Run
1. Start Ryu controller: `ryu-manager controller/mtd_controller.py`
2. Start Mininet topology: `sudo python topology/mtd_topo.py`
3. Run attack simulation: `bash scripts/run_attack.sh`
4. Check logs in `logs/` folder

### Credentials
- VM login: mininet / mininet
- SSH: `ssh -p 2222 mininet@127.0.0.1`
