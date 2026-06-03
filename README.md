# A Lightweight Secure Communication Engine for UCIe Die-to-Die Chiplet Interconnects in AI Accelerators

## Publication Status

| Stage | Status |
|-------|--------|
| Submission | ✅ Submitted |
| Peer Review | ✅ Reviewed |
| Decision | ✅ **Accepted** |
| Camera-Ready | ✅ Submitted |
| IEEE Xplore | 🔄 Pending Publication |

**Conference:** 2026 IEEE 69th International Midwest Symposium on Circuits and Systems (MWSCAS)
**Date:** August 9–12, 2026 — Cincinnati, Ohio, USA
**IEEE Xplore DOI:** TBD

---

## About the Conference

MWSCAS is the flagship North American conference of the IEEE Circuits and Systems Society (IEEE CASS), with an unbroken 69-year history making it one of the oldest continuously running IEEE technical conferences in existence. The 2026 edition continues a tradition of bringing together researchers from academia and industry across circuits, systems, AI hardware, and emerging technologies. Accepted papers are published in the IEEE Xplore digital library and indexed in all major academic databases.

---

## Authors

| Name | Affiliation | Role |
|------|-------------|------|
| Yogesh Rethinapandian | Dept. of ECE, University of Illinois Chicago | First Author · Corresponding Author |
| Arun Karthik Sundararajan | IEEE Member | Co-Author |
| Kaushik Kumar | Dept. of Data Science, University of Arizona | Co-Author |

---

## Abstract

Modern AI accelerators based on chiplet architectures, including AMD MI300, Intel Ponte Vecchio, and NVIDIA Grace Hopper, universally operate under a critical implicit assumption: all co-packaged dies form a trusted computing base. Die-to-die interconnects such as UCIe, BoW, and AIB carry AI model weights, activations, and gradients in plaintext, leaving them exposed to supply-chain-injected hardware Trojans, compromised third-party IP, and side-channel attacks. This paper presents **SCE (Secure Communication Engine)**, a lightweight hardware-friendly bump-in-the-wire module that adds ChaCha20-Poly1305 authenticated encryption, mutual HMAC-SHA256 challenge-response authentication, and sliding-window replay protection to UCIe Gen 2 die-to-die links.

Key results:
- **P99 latency overhead: 38.8%** (decreases through burst amortization)
- **Throughput impact: <0.01%** for KB-scale AI tensor transfers
- **Power overhead: ~240 mW/link** (0.25–0.4% of system TDP)
- **Area: ~0.75 mm² per link** (~0.3% of GPU chiplet footprint)

---

## Repository Structure

```
sce-chiplet-security/
├── simulate_sce.py          # Discrete-event packet-level simulator
├── summary_table.csv        # Simulation results summary
├── related_work_table.csv   # Security feature comparison table
├── sensitivity_packet_size.png
├── sensitivity_burstiness.png
├── sensitivity_crypto_throughput.png
├── README.md
└── rtl/
    ├── README.md            # RTL documentation and attribution
    ├── chacha20_core.v      # ChaCha20 keystream core (original)
    ├── sce_top.v            # SCE top-level wrapper (original)
    ├── tb_sce.v             # Testbench with RFC 7539 NIST test vectors
    ├── poly1305.v           # Poly1305 top-level (secworks, see attribution)
    ├── poly1305_core.v      # Poly1305 core (secworks)
    ├── poly1305_pblock.v    # Poly1305 block processing (secworks)
    ├── poly1305_mulacc.v    # Poly1305 multiply-accumulate (secworks)
    ├── poly1305_final.v     # Poly1305 finalization (secworks)
    └── tb_poly1305.v        # Poly1305 testbench (secworks)
```

---

## Simulation

### Requirements
```bash
pip install numpy matplotlib seaborn
```

### Run
```bash
python3 simulate_sce.py
```

Reproduces all results in the paper. Uses **NumPy random seed 42** — all results are fully deterministic and reproducible with no external dependencies beyond standard scientific Python.

### What the simulator models
- UCIe Gen 2 die-to-die link at 2 GHz, 256-bit bus, 128 GB/s raw bandwidth
- ChaCha20-Poly1305 with 10 ns pipeline fill latency (from published silicon data)
- Realistic AI accelerator traffic: 20% control (64–256 B), 50% data (1–4 KB), 30% tensors (16–64 KB)
- 10,000 packets per run, five-dimensional parameter sweeps

---

## RTL Hardware Implementation

### ChaCha20 Core (Original)
The ChaCha20 encryption core is implemented in synthesizable SystemVerilog and functionally verified against **RFC 7539 NIST test vectors** using Icarus Verilog simulation.

```bash
# Install tools
apt-get install iverilog yosys

# Simulate (verify RFC 7539 test vectors)
cd rtl
iverilog -o sim_sce tb_sce.v chacha20_core.v poly1305_core.v sce_top.v
vvp sim_sce

# Synthesize (get gate counts)
yosys -s synth.ys
```

**Synthesis results (Yosys):**
- ChaCha20 core: **795 cells**
- Poly1305 core: **~19,000 cells** (secworks optimized implementation)

### Poly1305 MAC (Attribution)
The Poly1305 authentication core is from the open-source hardware implementation by **Joachim Strömbergson**:

> **secworks/poly1305** — Hardware implementation of the Poly1305 message authentication function
> RFC 8439 compliant · MIT License
> https://github.com/secworks/poly1305

All Poly1305 files in the `rtl/` folder are reproduced from that repository with full attribution. The original copyright and license terms apply to those files. Our contribution is the ChaCha20 core (`chacha20_core.v`), the SCE top-level wrapper (`sce_top.v`), and the integrated testbench (`tb_sce.v`).

---

## Citation

If you use this code or build on this work, please cite:

```bibtex
@inproceedings{rethinapandian2026sce,
  title     = {A Lightweight Secure Communication Engine for {UCIe}
               Die-to-Die Chiplet Interconnects in {AI} Accelerators},
  author    = {Rethinapandian, Yogesh and Sundararajan, Arun Karthik
               and Kumar, Kaushik},
  booktitle = {Proc. 69th IEEE International Midwest Symposium on
               Circuits and Systems (MWSCAS)},
  year      = {2026},
  address   = {Cincinnati, OH, USA},
  note      = {Accepted. IEEE Xplore DOI: TBD. To appear Aug. 2026}
}
```

---

## License

Simulation code and original RTL (`chacha20_core.v`, `sce_top.v`, `tb_sce.v`) are released under the **MIT License**.

Poly1305 RTL files are from [secworks/poly1305](https://github.com/secworks/poly1305) and retain their original MIT license and copyright by Joachim Strömbergson.
