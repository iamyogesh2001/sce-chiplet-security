# Secure Die-to-Die Communication for Chiplet-Based AI Accelerators

**A Lightweight Framework for Trusted Multi-Vendor Integration**

**Authors:** Yogesh Rethinapandian, Arun Karthik Sundararajan  
**Submitted to:** Journal of Engineering and Applied Science (Springer Nature)  
**Corresponding Author:** yrethi2@uic.edu

---

## Overview

This repository contains the simulation code and generated results supporting the paper "Secure Die-to-Die Communication for Chiplet-Based AI Accelerators: A Lightweight Framework for Trusted Multi-Vendor Integration," submitted to the Journal of Engineering and Applied Science (JEAS), Springer Nature.

The paper proposes a Secure Communication Engine (SCE) framework that provides mutual authentication, confidentiality, integrity, and replay protection for die-to-die chiplet interconnects, with specific optimization for UCIe Gen 2 links under AI accelerator workload patterns.

---

## Repository Contents

| File | Description |
|------|-------------|
| `simulate_sce.py` | Complete discrete-event packet-level simulator (~800 lines, single file) |
| `sensitivity_packet_size.png` | Throughput and latency overhead vs. packet size (64 B to 16 KB) |
| `sensitivity_crypto_throughput.png` | Throughput reduction vs. crypto engine performance ratio |
| `sensitivity_burstiness.png` | Latency overhead vs. traffic burstiness level |
| `summary_table.csv` | Baseline performance metrics: encrypted vs. unencrypted UCIe link |
| `related_work_table.csv` | Security feature comparison across 9 existing hardware systems |

---

## Simulation Methodology

The simulator models a UCIe Gen 2 die-to-die link operating at 2 GHz with a 256-bit data bus, providing 128 GB/s raw bandwidth. Cryptographic operations are parameterized from published hardware implementations of ChaCha20-Poly1305 (Aragon et al., IEEE TCAS-I, 2019): 10 ns initial pipeline fill latency with line-rate steady-state throughput and speculative keystream generation enabled.

Traffic generation reflects realistic AI accelerator communication patterns:
- Small control packets: 64 to 256 B (20% of traffic)
- Medium data transfers: 1 to 4 KB (50% of traffic)
- Large tensor movements: 16 to 64 KB (30% of traffic)

Each simulation run processes 10,000 packets. All results are fully deterministic and reproducible using NumPy random seed 42.

---

## Key Results

**Baseline comparison (10,000 packets, mixed AI workload):**

| Metric | Unencrypted | SCE-Protected | Overhead |
|--------|-------------|---------------|----------|
| Mean Latency | 1,467.86 ns | 3,030.70 ns | +106.47% |
| P95 Latency | 4,699.82 ns | 7,875.26 ns | +67.56% |
| P99 Latency | 7,578.64 ns | 10,517.21 ns | +38.77% |
| Throughput | 279.40 GB/s | 279.40 GB/s | <0.01% |
| Auth Tag Overhead | 0.00% | 0.13% | +0.13% |

Throughput overhead is negligible (below 0.1%) for KB-scale AI tensor transfers. Mean latency overhead of 106% decreases to 38% at the P99 tail owing to burst amortization effects.

---

## Reproducing Results

**Requirements:**

```bash
pip install numpy pandas matplotlib seaborn
```

**Run full simulation:**

```bash
python simulate_sce.py
```

This generates all sensitivity plots, summary tables, and baseline comparison results in a local `sce_results/` directory. Runtime is approximately 30 seconds on a standard laptop.

**Configurable parameters** (top of `simulate_sce.py`):
- `LinkConfig`: clock speed, link width
- `CryptoConfig`: crypto latency, authentication tag size, rekeying interval
- `PacketConfig`: packet size distributions and traffic mix

---

## Simulation Scope and Limitations

The simulator models the cryptographic and protocol-level overhead of the SCE framework. The following are explicitly out of scope:

- Physical layer signal integrity (crosstalk, inter-symbol interference)
- Denial-of-service attacks via malicious packet drops
- Invasive physical attacks requiring package decapsulation

These limitations are discussed in full in Section 8 of the paper.

---

## Citation

If you use this simulation code or results in your research, please cite:

```
Y. Rethinapandian and A. K. Sundararajan, "Secure Die-to-Die Communication 
for Chiplet-Based AI Accelerators: A Lightweight Framework for Trusted 
Multi-Vendor Integration," Journal of Engineering and Applied Science, 
Springer Nature, 2025 (under review).
```

---

## License

This code is made available for academic research and peer review purposes.  
Copyright 2025 Yogesh Rethinapandian. All rights reserved.
