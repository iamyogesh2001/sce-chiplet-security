#!/usr/bin/env python3
"""
Secure Communication Engine (SCE) Performance Simulator
========================================================

Discrete-event packet-level simulator for evaluating cryptographic overhead
on die-to-die UCIe links in chiplet-based AI accelerators.

Paper: "Secure Die-to-Die Communication for Chiplet-Based AI Accelerators:
        A Lightweight Framework for Trusted Multi-Vendor Integration"
Authors: Yogesh Rethinapandian, Arun Karthik Sundararajan
Submitted to: Journal of Engineering and Applied Science, Springer Nature

Simulation Parameters:
    - UCIe Gen 2: 256-bit link @ 2 GHz = 128 GB/s raw bandwidth
    - ChaCha20-Poly1305: 10 ns pipeline fill, line-rate steady-state
    - Poly1305 authentication tag: 16 bytes per packet
    - UCIe packet header: 8 bytes
    - Authentication handshake: 420 ns (one-time per link initialization)
    - Session key rotation: every 10^9 packets, 200 ns fast rekey

Reproducibility:
    All results are deterministic with NumPy random seed 42.
    Runtime: approximately 30 seconds on a standard laptop.
"""

import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
from dataclasses import dataclass
from typing import List
import os

np.random.seed(42)
plt.style.use('seaborn-v0_8-paper')
sns.set_palette("colorblind")


@dataclass
class LinkConfig:
    """UCIe Gen 2 physical link parameters."""
    clock_freq_ghz: float = 2.0
    link_width_bits: int = 256

    @property
    def cycle_time_ns(self) -> float:
        return 1.0 / self.clock_freq_ghz

    @property
    def raw_bandwidth_gbps(self) -> float:
        return (self.link_width_bits * self.clock_freq_ghz) / 8.0


@dataclass
class CryptoConfig:
    """SCE cryptographic engine parameters."""
    initial_fill_latency_ns: float = 10.0
    steady_state_throughput_ratio: float = 1.0
    auth_tag_bytes: int = 16
    auth_handshake_latency_ns: float = 420.0
    rekey_interval_packets: int = int(1e9)
    rekey_latency_ns: float = 200.0
    speculative_keystream_enabled: bool = True


@dataclass
class PacketConfig:
    """Packet generation parameters."""
    header_bytes: int = 8
    payload_size_bytes: int = 256
    packet_size_distribution: str = "mixed"
    small_packet_ratio: float = 0.3
    large_packet_ratio: float = 0.7


class Packet:
    """Represents a single packet in the simulation."""

    def __init__(self, pkt_id: int, payload_bytes: int, arrival_time_ns: float):
        self.pkt_id = pkt_id
        self.payload_bytes = payload_bytes
        self.arrival_time_ns = arrival_time_ns
        self.transmission_start_ns = None
        self.transmission_end_ns = None
        self.encrypted = False

    @property
    def total_bytes(self) -> int:
        return self.payload_bytes + 8

    @property
    def encrypted_bytes(self) -> int:
        return self.total_bytes + 16 if self.encrypted else self.total_bytes

    @property
    def latency_ns(self) -> float:
        if self.transmission_end_ns is None:
            return None
        return self.transmission_end_ns - self.arrival_time_ns


class TrafficGenerator:
    """Generates packet arrival patterns for AI workloads."""

    def __init__(self, config: PacketConfig, burstiness: str = "medium"):
        self.config = config
        self.burstiness = burstiness

    def generate_packet_sizes(self, num_packets: int) -> List[int]:
        if self.config.packet_size_distribution == "fixed":
            return [self.config.payload_size_bytes] * num_packets

        elif self.config.packet_size_distribution == "mixed":
            sizes = []
            for _ in range(num_packets):
                if np.random.random() < self.config.small_packet_ratio:
                    sizes.append(np.random.choice([64, 128, 256]))
                else:
                    sizes.append(np.random.choice([1024, 4096, 16384]))
            return sizes

        elif self.config.packet_size_distribution == "ai_workload":
            # 20% small control (64-256 B), 50% medium (1-4 KB), 30% large tensors (16-64 KB)
            sizes = []
            for _ in range(num_packets):
                r = np.random.random()
                if r < 0.2:
                    sizes.append(np.random.choice([64, 128, 256]))
                elif r < 0.7:
                    sizes.append(np.random.choice([1024, 2048, 4096]))
                else:
                    sizes.append(np.random.choice([16384, 32768, 65536]))
            return sizes

        else:
            raise ValueError(f"Unknown distribution: {self.config.packet_size_distribution}")

    def generate_arrival_times(self, num_packets: int, avg_rate_gbps: float) -> List[float]:
        avg_packet_size_bytes = 4096
        avg_inter_arrival_ns = (avg_packet_size_bytes * 8) / avg_rate_gbps

        arrival_times = [0.0]

        if self.burstiness == "low":
            for _ in range(num_packets - 1):
                iat = np.random.exponential(avg_inter_arrival_ns * 1.1)
                arrival_times.append(arrival_times[-1] + iat)

        elif self.burstiness == "medium":
            in_burst = False
            burst_length = 0
            for _ in range(num_packets - 1):
                if not in_burst:
                    iat = np.random.exponential(avg_inter_arrival_ns * 2.0)
                    in_burst = np.random.random() < 0.3
                    burst_length = np.random.geometric(0.2) if in_burst else 0
                else:
                    iat = np.random.exponential(avg_inter_arrival_ns * 0.1)
                    burst_length -= 1
                    if burst_length <= 0:
                        in_burst = False
                arrival_times.append(arrival_times[-1] + iat)

        elif self.burstiness == "high":
            alpha = 1.5
            for _ in range(num_packets - 1):
                iat = np.random.pareto(alpha) * avg_inter_arrival_ns * 0.5
                arrival_times.append(arrival_times[-1] + iat)

        else:
            raise ValueError(f"Unknown burstiness: {self.burstiness}")

        return arrival_times

    def generate_traffic(self, num_packets: int, avg_rate_gbps: float) -> List[Packet]:
        sizes = self.generate_packet_sizes(num_packets)
        arrivals = self.generate_arrival_times(num_packets, avg_rate_gbps)
        return [Packet(i, s, a) for i, (s, a) in enumerate(zip(sizes, arrivals))]


class SCESimulator:
    """Discrete-event simulator for SCE-protected die-to-die link."""

    def __init__(self, link: LinkConfig, crypto: CryptoConfig, encrypted: bool = True):
        self.link = link
        self.crypto = crypto
        self.encrypted = encrypted
        self.reset()

    def reset(self):
        self.current_time_ns = 0.0
        self.packets_transmitted = 0
        self.packets_since_rekey = 0
        self.crypto_pipeline_busy_until = 0.0
        self.link_busy_until = 0.0
        self.initial_handshake_done = False
        self.total_bytes_transmitted = 0
        self.total_overhead_bytes = 0
        self.rekeying_events = 0

    def _transmission_time(self, num_bytes: int) -> float:
        return (num_bytes * 8 / self.link.link_width_bits) * self.link.cycle_time_ns

    def _process_initial_handshake(self, pkt: Packet):
        if not self.initial_handshake_done and self.encrypted:
            self.current_time_ns = max(self.current_time_ns, pkt.arrival_time_ns)
            self.current_time_ns += self.crypto.auth_handshake_latency_ns
            self.initial_handshake_done = True

    def _check_rekeying(self):
        if self.encrypted and self.packets_since_rekey >= self.crypto.rekey_interval_packets:
            self.current_time_ns += self.crypto.rekey_latency_ns
            self.packets_since_rekey = 0
            self.rekeying_events += 1

    def _process_crypto(self, pkt: Packet, is_first_in_burst: bool):
        if not self.encrypted:
            return
        if is_first_in_burst or self.crypto_pipeline_busy_until < pkt.arrival_time_ns:
            crypto_start = max(self.current_time_ns, pkt.arrival_time_ns)
            if not self.crypto.speculative_keystream_enabled:
                crypto_start += self.crypto.initial_fill_latency_ns
            self.crypto_pipeline_busy_until = crypto_start

        crypto_time = self._transmission_time(pkt.encrypted_bytes)
        crypto_time /= self.crypto.steady_state_throughput_ratio
        self.crypto_pipeline_busy_until += crypto_time

    def _transmit(self, pkt: Packet):
        tx_bytes = pkt.encrypted_bytes if self.encrypted else pkt.total_bytes
        earliest_start = max(pkt.arrival_time_ns,
                             self.crypto_pipeline_busy_until,
                             self.link_busy_until)
        pkt.transmission_start_ns = earliest_start
        tx_time = self._transmission_time(tx_bytes)
        pkt.transmission_end_ns = pkt.transmission_start_ns + tx_time
        self.link_busy_until = pkt.transmission_end_ns
        self.current_time_ns = pkt.transmission_end_ns
        self.total_bytes_transmitted += pkt.total_bytes
        if self.encrypted:
            self.total_overhead_bytes += self.crypto.auth_tag_bytes

    def simulate(self, packets: List[Packet]) -> List[Packet]:
        self.reset()
        if packets:
            self._process_initial_handshake(packets[0])
        prev_arrival = -1e9
        for pkt in packets:
            self._check_rekeying()
            is_first_in_burst = (pkt.arrival_time_ns - prev_arrival) > 1000.0
            prev_arrival = pkt.arrival_time_ns
            self._process_crypto(pkt, is_first_in_burst)
            pkt.encrypted = self.encrypted
            self._transmit(pkt)
            self.packets_transmitted += 1
            self.packets_since_rekey += 1
        return packets

    def compute_metrics(self, packets: List[Packet]) -> dict:
        latencies = [p.latency_ns for p in packets if p.latency_ns is not None]
        if not latencies:
            return {}
        total_time_ns = packets[-1].transmission_end_ns - packets[0].arrival_time_ns
        throughput_gbps = (self.total_bytes_transmitted * 8) / total_time_ns
        tag_overhead_pct = (
            (self.total_overhead_bytes / self.total_bytes_transmitted) * 100
            if self.total_bytes_transmitted > 0 else 0
        )
        return {
            'mean_latency_ns': np.mean(latencies),
            'p50_latency_ns': np.percentile(latencies, 50),
            'p95_latency_ns': np.percentile(latencies, 95),
            'p99_latency_ns': np.percentile(latencies, 99),
            'throughput_gbps': throughput_gbps,
            'total_packets': len(packets),
            'tag_overhead_pct': tag_overhead_pct,
            'rekeying_events': self.rekeying_events,
        }


def run_baseline_comparison(num_packets: int = 10000, output_dir: str = "."):
    """Baseline comparison: encrypted vs unencrypted UCIe link."""
    print("=" * 80)
    print("BASELINE COMPARISON: Encrypted vs Unencrypted UCIe Link")
    print("=" * 80)

    link = LinkConfig()
    crypto = CryptoConfig()
    traffic_gen = TrafficGenerator(PacketConfig(packet_size_distribution="ai_workload"))

    packets_unenc = traffic_gen.generate_traffic(num_packets, avg_rate_gbps=80.0)
    packets_enc = [Packet(p.pkt_id, p.payload_bytes, p.arrival_time_ns) for p in packets_unenc]

    sim_unenc = SCESimulator(link, crypto, encrypted=False)
    sim_unenc.simulate(packets_unenc)
    m_unenc = sim_unenc.compute_metrics(packets_unenc)

    sim_enc = SCESimulator(link, crypto, encrypted=True)
    sim_enc.simulate(packets_enc)
    m_enc = sim_enc.compute_metrics(packets_enc)

    latency_overhead_pct = ((m_enc['mean_latency_ns'] / m_unenc['mean_latency_ns']) - 1) * 100
    p95_overhead_pct = ((m_enc['p95_latency_ns'] / m_unenc['p95_latency_ns']) - 1) * 100
    throughput_reduction_pct = ((m_unenc['throughput_gbps'] / m_enc['throughput_gbps']) - 1) * 100

    print(f"\nConfiguration:")
    print(f"  Link: {link.link_width_bits}-bit @ {link.clock_freq_ghz} GHz = {link.raw_bandwidth_gbps:.1f} GB/s")
    print(f"  Crypto: ChaCha20-Poly1305, {crypto.auth_tag_bytes}B tag, {crypto.initial_fill_latency_ns}ns fill")
    print(f"  Traffic: {num_packets} packets, AI workload pattern\n")

    print(f"{'Metric':<30} {'Unencrypted':<20} {'Encrypted':<20} {'Overhead':>10}")
    print("-" * 85)
    print(f"{'Mean Latency (ns)':<30} {m_unenc['mean_latency_ns']:>18.2f} {m_enc['mean_latency_ns']:>18.2f} {latency_overhead_pct:>9.2f}%")
    print(f"{'P95 Latency (ns)':<30} {m_unenc['p95_latency_ns']:>18.2f} {m_enc['p95_latency_ns']:>18.2f} {p95_overhead_pct:>9.2f}%")
    print(f"{'Throughput (GB/s)':<30} {m_unenc['throughput_gbps']:>18.2f} {m_enc['throughput_gbps']:>18.2f} {-throughput_reduction_pct:>9.2f}%")
    print(f"{'Auth Tag Overhead':<30} {'N/A':>18} {m_enc['tag_overhead_pct']:>17.2f}%")
    print(f"{'Rekeying Events':<30} {'0':>18} {m_enc['rekeying_events']:>18}")

    return {
        'unencrypted': m_unenc,
        'encrypted': m_enc,
        'latency_overhead_pct': latency_overhead_pct,
        'p95_overhead_pct': p95_overhead_pct,
        'throughput_reduction_pct': throughput_reduction_pct,
    }


def sensitivity_packet_size(output_dir: str = "."):
    """Sensitivity analysis: packet size impact on overhead."""
    print("\n" + "=" * 80)
    print("SENSITIVITY ANALYSIS: Packet Size Impact")
    print("=" * 80)

    link = LinkConfig()
    crypto = CryptoConfig()
    packet_sizes = [64, 128, 256, 512, 1024, 2048, 4096, 8192, 16384]
    results = []

    for psize in packet_sizes:
        pkt_config = PacketConfig(payload_size_bytes=psize, packet_size_distribution="fixed")
        tg = TrafficGenerator(pkt_config)
        p_u = tg.generate_traffic(5000, 80.0)
        p_e = [Packet(p.pkt_id, p.payload_bytes, p.arrival_time_ns) for p in p_u]

        s_u = SCESimulator(link, crypto, encrypted=False)
        s_u.simulate(p_u)
        m_u = s_u.compute_metrics(p_u)

        s_e = SCESimulator(link, crypto, encrypted=True)
        s_e.simulate(p_e)
        m_e = s_e.compute_metrics(p_e)

        thr = ((m_u['throughput_gbps'] / m_e['throughput_gbps']) - 1) * 100
        lat = ((m_e['mean_latency_ns'] / m_u['mean_latency_ns']) - 1) * 100
        results.append({'packet_size_bytes': psize, 'throughput_reduction_pct': thr,
                        'latency_overhead_pct': lat, 'tag_overhead_pct': m_e['tag_overhead_pct']})
        print(f"  {psize:>6} bytes: Throughput -{thr:>5.2f}%, Latency +{lat:>5.2f}%, Tag {m_e['tag_overhead_pct']:>5.2f}%")

    df = pd.DataFrame(results)
    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(12, 4))
    ax1.plot(df['packet_size_bytes'], df['throughput_reduction_pct'], marker='o', linewidth=2)
    ax1.set_xlabel('Packet Size (bytes)', fontsize=11)
    ax1.set_ylabel('Throughput Reduction (%)', fontsize=11)
    ax1.set_xscale('log', base=2)
    ax1.grid(True, alpha=0.3)
    ax1.set_title('(a) Throughput Overhead vs Packet Size', fontsize=12)
    ax2.plot(df['packet_size_bytes'], df['latency_overhead_pct'], marker='s', linewidth=2, color='C1')
    ax2.set_xlabel('Packet Size (bytes)', fontsize=11)
    ax2.set_ylabel('Latency Overhead (%)', fontsize=11)
    ax2.set_xscale('log', base=2)
    ax2.grid(True, alpha=0.3)
    ax2.set_title('(b) Latency Overhead vs Packet Size', fontsize=12)
    plt.tight_layout()
    plt.savefig(f'{output_dir}/sensitivity_packet_size.png', dpi=300, bbox_inches='tight')
    print(f"\n  → Saved plot: {output_dir}/sensitivity_packet_size.png")
    return df


def sensitivity_crypto_throughput(output_dir: str = "."):
    """Sensitivity analysis: crypto engine throughput ratio."""
    print("\n" + "=" * 80)
    print("SENSITIVITY ANALYSIS: Crypto Throughput Ratio")
    print("=" * 80)

    link = LinkConfig()
    throughput_ratios = [0.7, 0.8, 0.9, 1.0, 1.1, 1.2]
    packet_sizes = [256, 1024, 4096]
    results = []

    for ratio in throughput_ratios:
        for psize in packet_sizes:
            crypto = CryptoConfig(steady_state_throughput_ratio=ratio)
            tg = TrafficGenerator(PacketConfig(payload_size_bytes=psize, packet_size_distribution="fixed"))
            p_u = tg.generate_traffic(3000, 80.0)
            p_e = [Packet(p.pkt_id, p.payload_bytes, p.arrival_time_ns) for p in p_u]
            s_u = SCESimulator(link, crypto, encrypted=False)
            s_u.simulate(p_u)
            m_u = s_u.compute_metrics(p_u)
            s_e = SCESimulator(link, crypto, encrypted=True)
            s_e.simulate(p_e)
            m_e = s_e.compute_metrics(p_e)
            thr = ((m_u['throughput_gbps'] / m_e['throughput_gbps']) - 1) * 100
            results.append({'crypto_throughput_ratio': ratio, 'packet_size_bytes': psize,
                            'throughput_reduction_pct': thr})

    df = pd.DataFrame(results)
    fig, ax = plt.subplots(figsize=(8, 5))
    for psize in packet_sizes:
        sub = df[df['packet_size_bytes'] == psize]
        ax.plot(sub['crypto_throughput_ratio'], sub['throughput_reduction_pct'],
                marker='o', linewidth=2, label=f'{psize}B packets')
    ax.axvline(x=1.0, color='red', linestyle='--', alpha=0.5)
    ax.set_xlabel('Crypto Throughput Ratio (× line rate)', fontsize=11)
    ax.set_ylabel('Throughput Reduction (%)', fontsize=11)
    ax.legend(fontsize=10)
    ax.grid(True, alpha=0.3)
    ax.set_title('Throughput Reduction vs Crypto Engine Performance', fontsize=12)
    plt.tight_layout()
    plt.savefig(f'{output_dir}/sensitivity_crypto_throughput.png', dpi=300, bbox_inches='tight')
    print(f"\n  → Saved plot: {output_dir}/sensitivity_crypto_throughput.png")
    for ratio in throughput_ratios:
        avg = df[df['crypto_throughput_ratio'] == ratio]['throughput_reduction_pct'].mean()
        print(f"  Ratio {ratio:.1f}×: Avg throughput reduction {avg:.2f}%")
    return df


def sensitivity_burstiness(output_dir: str = "."):
    """Sensitivity analysis: traffic burstiness impact on latency."""
    print("\n" + "=" * 80)
    print("SENSITIVITY ANALYSIS: Traffic Burstiness")
    print("=" * 80)

    link = LinkConfig()
    crypto = CryptoConfig()
    burstiness_levels = ['low', 'medium', 'high']
    packet_sizes = [256, 1024, 4096]
    results = []

    for burst in burstiness_levels:
        for psize in packet_sizes:
            tg = TrafficGenerator(PacketConfig(payload_size_bytes=psize, packet_size_distribution="fixed"),
                                  burstiness=burst)
            p_u = tg.generate_traffic(5000, 80.0)
            p_e = [Packet(p.pkt_id, p.payload_bytes, p.arrival_time_ns) for p in p_u]
            s_u = SCESimulator(link, crypto, encrypted=False)
            s_u.simulate(p_u)
            m_u = s_u.compute_metrics(p_u)
            s_e = SCESimulator(link, crypto, encrypted=True)
            s_e.simulate(p_e)
            m_e = s_e.compute_metrics(p_e)
            lat = ((m_e['mean_latency_ns'] / m_u['mean_latency_ns']) - 1) * 100
            p95 = ((m_e['p95_latency_ns'] / m_u['p95_latency_ns']) - 1) * 100
            results.append({'burstiness': burst, 'packet_size_bytes': psize,
                            'mean_latency_overhead_pct': lat, 'p95_latency_overhead_pct': p95})

    df = pd.DataFrame(results)
    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(12, 4))
    x = np.arange(len(burstiness_levels))
    width = 0.25
    mean_vals = {ps: [] for ps in packet_sizes}
    p95_vals = {ps: [] for ps in packet_sizes}
    for burst in burstiness_levels:
        for ps in packet_sizes:
            sub = df[(df['burstiness'] == burst) & (df['packet_size_bytes'] == ps)]
            mean_vals[ps].append(sub['mean_latency_overhead_pct'].values[0])
            p95_vals[ps].append(sub['p95_latency_overhead_pct'].values[0])
    for i, ps in enumerate(packet_sizes):
        ax1.bar(x + i * width, mean_vals[ps], width, label=f'{ps}B')
        ax2.bar(x + i * width, p95_vals[ps], width, label=f'{ps}B')
    for ax, title in [(ax1, '(a) Mean Latency Overhead'), (ax2, '(b) P95 Latency Overhead')]:
        ax.set_xlabel('Traffic Burstiness', fontsize=11)
        ax.set_ylabel('Latency Overhead (%)', fontsize=11)
        ax.set_xticks(x + width)
        ax.set_xticklabels([b.capitalize() for b in burstiness_levels])
        ax.legend(fontsize=9)
        ax.grid(True, alpha=0.3, axis='y')
        ax.set_title(title, fontsize=12)
    plt.tight_layout()
    plt.savefig(f'{output_dir}/sensitivity_burstiness.png', dpi=300, bbox_inches='tight')
    print(f"\n  → Saved plot: {output_dir}/sensitivity_burstiness.png")
    for burst in burstiness_levels:
        sub = df[df['burstiness'] == burst]
        print(f"  {burst.capitalize():<8}: Mean overhead {sub['mean_latency_overhead_pct'].mean():.2f}%, "
              f"P95 overhead {sub['p95_latency_overhead_pct'].mean():.2f}%")
    return df


def sensitivity_rekey_interval(output_dir: str = "."):
    """Sensitivity analysis: session key rotation interval."""
    print("\n" + "=" * 80)
    print("SENSITIVITY ANALYSIS: Rekeying Interval")
    print("=" * 80)

    link = LinkConfig()
    rekey_intervals = [int(1e6), int(1e7), int(1e8), int(1e9)]
    results = []

    for interval in rekey_intervals:
        crypto = CryptoConfig(rekey_interval_packets=interval)
        tg = TrafficGenerator(PacketConfig(payload_size_bytes=1024, packet_size_distribution="fixed"))
        num_packets = min(20000, interval // 10)
        p_u = tg.generate_traffic(num_packets, 80.0)
        p_e = [Packet(p.pkt_id, p.payload_bytes, p.arrival_time_ns) for p in p_u]
        s_u = SCESimulator(link, crypto, encrypted=False)
        s_u.simulate(p_u)
        m_u = s_u.compute_metrics(p_u)
        s_e = SCESimulator(link, crypto, encrypted=True)
        s_e.simulate(p_e)
        m_e = s_e.compute_metrics(p_e)
        lat = ((m_e['mean_latency_ns'] / m_u['mean_latency_ns']) - 1) * 100
        results.append({'rekey_interval': interval, 'rekeying_events': m_e['rekeying_events'],
                        'latency_overhead_pct': lat})
        print(f"  Interval {interval:>10}: {m_e['rekeying_events']:>3} rekeys, Latency +{lat:.3f}%")

    df = pd.DataFrame(results)
    df.to_csv(f'{output_dir}/sensitivity_rekey.csv', index=False)
    print(f"\n  → Saved data: {output_dir}/sensitivity_rekey.csv")
    return df


def generate_summary_table(baseline_results: dict, output_dir: str = "."):
    """Generate performance summary table."""
    print("\n" + "=" * 80)
    print("SUMMARY TABLE: Performance Overhead")
    print("=" * 80)

    unenc = baseline_results['unencrypted']
    enc = baseline_results['encrypted']

    p99_overhead = ((enc['p99_latency_ns'] / unenc['p99_latency_ns']) - 1) * 100

    table_data = {
        'Metric': ['Mean Latency (ns)', 'P95 Latency (ns)', 'P99 Latency (ns)',
                   'Throughput (GB/s)', 'Auth Tag Overhead (%)', 'Rekeying Events'],
        'Unencrypted': [f"{unenc['mean_latency_ns']:.2f}", f"{unenc['p95_latency_ns']:.2f}",
                        f"{unenc['p99_latency_ns']:.2f}", f"{unenc['throughput_gbps']:.2f}", "0.00", "0"],
        'Encrypted (SCE)': [f"{enc['mean_latency_ns']:.2f}", f"{enc['p95_latency_ns']:.2f}",
                            f"{enc['p99_latency_ns']:.2f}", f"{enc['throughput_gbps']:.2f}",
                            f"{enc['tag_overhead_pct']:.2f}", f"{enc['rekeying_events']}"],
        'Overhead': [f"+{baseline_results['latency_overhead_pct']:.2f}%",
                     f"+{baseline_results['p95_overhead_pct']:.2f}%",
                     f"+{p99_overhead:.2f}%",
                     f"-{baseline_results['throughput_reduction_pct']:.2f}%",
                     f"+{enc['tag_overhead_pct']:.2f}%", "N/A"],
    }

    df = pd.DataFrame(table_data)
    df.to_csv(f'{output_dir}/summary_table.csv', index=False)
    print("\n" + df.to_string(index=False))
    print(f"\n  → Saved table: {output_dir}/summary_table.csv")
    return df


def generate_related_work_table(output_dir: str = "."):
    """Generate security feature comparison table."""
    print("\n" + "=" * 80)
    print("RELATED WORK COMPARISON TABLE")
    print("=" * 80)

    data = {
        'System': ['Intel TME/MKTME', 'AMD SEV/SEV-SNP', 'NoC [Fiorin 2008]',
                   'SecNoC [Sajeesh 2011]', 'UCIe Standard', 'AMD MI300',
                   'Intel Ponte Vecchio', 'NVIDIA Grace Hopper', 'Proposed SCE'],
        'Intra-Package': ['No (DRAM only)', 'No (DRAM only)', 'Yes (on-die)', 'Yes (on-die)',
                          'No', 'No', 'No', 'No', 'Yes'],
        'Authentication': ['No', 'Yes', 'No', 'Yes', 'No', 'No', 'No', 'No', 'Yes'],
        'Integrity': ['Yes (XTS)', 'Yes (GHASH)', 'No', 'Yes (HMAC)', 'No',
                      'CRC only', 'CRC only', 'CRC only', 'Yes (Poly1305)'],
        'Replay Protection': ['No', 'Yes', 'No', 'No', 'No', 'No', 'No', 'No', 'Yes'],
        'D2D Optimized': ['No', 'No', 'No', 'No', 'N/A', 'No', 'No', 'No', 'Yes'],
        'Multi-Vendor': ['No', 'No', 'No', 'No', 'Yes', 'Limited', 'Yes', 'Yes', 'Yes'],
    }

    df = pd.DataFrame(data)
    df.to_csv(f'{output_dir}/related_work_table.csv', index=False)
    print("\n" + df.to_string(index=False))
    print(f"\n  → Saved table: {output_dir}/related_work_table.csv")
    return df


def main():
    output_dir = "sce_results"
    os.makedirs(output_dir, exist_ok=True)

    print("\n[1/7] Running baseline comparison...")
    baseline = run_baseline_comparison(num_packets=10000, output_dir=output_dir)

    print("\n[2/7] Running packet size sensitivity...")
    sensitivity_packet_size(output_dir=output_dir)

    print("\n[3/7] Running crypto throughput sensitivity...")
    sensitivity_crypto_throughput(output_dir=output_dir)

    print("\n[4/7] Running burstiness sensitivity...")
    sensitivity_burstiness(output_dir=output_dir)

    print("\n[5/7] Running rekeying sensitivity...")
    sensitivity_rekey_interval(output_dir=output_dir)

    print("\n[6/7] Generating summary table...")
    generate_summary_table(baseline, output_dir=output_dir)

    print("\n[7/7] Generating related work comparison...")
    generate_related_work_table(output_dir=output_dir)

    print("\n" + "=" * 80)
    print("SIMULATION COMPLETE")
    print("=" * 80)
    print(f"\nAll results saved to: {output_dir}/")
    print("  - sensitivity_packet_size.png")
    print("  - sensitivity_crypto_throughput.png")
    print("  - sensitivity_burstiness.png")
    print("  - sensitivity_rekey.csv")
    print("  - summary_table.csv")
    print("  - related_work_table.csv")
    print("=" * 80)


if __name__ == "__main__":
    main()
