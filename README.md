<div align="center">

# 🌪️ DesertStorm — High-Performance Network Scanner & Port Scanner

<!-- ===== Banner Start ===== -->

| <img src="./assets/desertstorm.png" width="90" alt="DesertDemons Logo"> | **DesertStorm**  <br> DesertStorm is a high-performance, stateless TCP SYN scanner written in Rust. <br> It crafts raw packets and can optionally grab async service banners for quick identification. <br><br> ⚠️ **Authorized use only.** Scan only systems you own or have explicit permission to test. |
|---|---|

<!-- ===== Banner End ===== -->

<hr />

<!-- ===== Banner Start ===== -->

| <img src="./assets/desertstorm.png" width="80" alt="DesertDemons Logo"> | <div align="left"><h3>DesertStorm</h3><p>High-performance stateless TCP SYN scanner in Rust, with optional async banner grabbing.</p><p>⚠️ <b>Authorized use only.</b> Scan only systems you own or have permission to test.</p></div> |
|---|---|

<!-- ===== Banner End ===== -->



### Fast, Stealthy, Asynchronous Network Reconnaissance Tool Written in Rust

[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](https://www.gnu.org/licenses/gpl-3.0)
[![Rust](https://img.shields.io/badge/Language-Rust-orange.svg)](https://www.rust-lang.org/)
[![Platform](https://img.shields.io/badge/Platform-Linux-lightgrey.svg)](https://github.com/DesertDemons/DesertStorm)
[![Version](https://img.shields.io/badge/Version-5.1.0-green.svg)](https://github.com/DesertDemons/DesertStorm/releases)
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg)](https://github.com/DesertDemons/DesertStorm/pulls)

**DesertStorm** is an open-source, high-performance **SYN port scanner** and **network reconnaissance tool** built in Rust. It performs **stateless TCP SYN scanning** with raw packet crafting, SYN-cookie validation, randomized host permutation, service banner grabbing, and OS fingerprinting — delivering enterprise-grade scanning speed with penetration testing precision.

[Installation](#-installation) · [Quick Start](#-quick-start) · [Documentation](#-full-command-reference) · [Examples](#-usage-examples) · [Architecture](#-architecture--technical-deep-dive) · [FAQ](#-frequently-asked-questions)

</div>

---

## 📋 Table of Contents

- [Why DesertStorm?](#-why-desertstorm)
- [Key Features](#-key-features)
- [Performance Benchmarks](#-performance-benchmarks)
- [Comparison with Other Scanners](#-comparison-with-other-port-scanners)
- [Installation](#-installation)
- [Quick Start](#-quick-start)
- [Full Command Reference](#-full-command-reference)
- [Usage Examples](#-usage-examples)
- [Output Formats](#-output-formats)
- [Architecture & Technical Deep Dive](#-architecture--technical-deep-dive)
- [Port Intelligence Database](#-port-intelligence-database)
- [Security Considerations](#-security-considerations)
- [Use Cases](#-use-cases)
- [Troubleshooting](#-troubleshooting)
- [Contributing](#-contributing)
- [FAQ](#-frequently-asked-questions)
- [Legal Disclaimer](#%EF%B8%8F-legal-disclaimer)
- [License](#-license)

---

## 🎯 Why DesertStorm?

Network scanning is a critical first step in penetration testing, vulnerability assessment, and security auditing. Existing tools like Nmap and Masscan are powerful but come with trade-offs — Nmap prioritizes accuracy over speed, while Masscan prioritizes speed over intelligence. **DesertStorm bridges this gap** by combining:

- **Masscan-class speed** through stateless SYN scanning and raw packet crafting
- **Nmap-class intelligence** through service detection, banner grabbing, and OS fingerprinting
- **Rust's memory safety** and zero-cost abstractions for reliability without garbage collection pauses
- **Built-in security context** with CVSS scores and risk assessments for every detected service

Whether you're a **penetration tester** running authorized engagements, a **security engineer** auditing your perimeter, a **bug bounty hunter** mapping attack surface, or a **network administrator** inventorying assets — DesertStorm gives you the speed, accuracy, and context you need in a single binary.

---

## ✨ Key Features

### Stateless SYN Scanning Engine
DesertStorm uses **SYN-cookie encoded sequence numbers** to validate responses without maintaining per-connection state. This enables scanning millions of host:port combinations with constant memory usage regardless of scan size — the same technique used by production load balancers to handle SYN floods.

### Raw Packet Crafting
Packets are constructed at the **Ethernet → IPv4 → TCP** layer using `libpnet`, completely bypassing the kernel's TCP/IP stack. This eliminates socket overhead, avoids kernel rate limiting, and gives full control over every header field including TTL, IP ID, TCP window size, and flags.

### Randomized Scan Order
A **multiplicative-group permutation generator** over a prime field produces a pseudo-random traversal of the entire IPv4 target space. Every IP in the range is visited exactly once in a non-sequential order, making the scan pattern indistinguishable from random noise to intrusion detection systems.

### Intelligent Rate Limiting
Precise **packets-per-second (PPS)** control using wall-clock timing allows operators to tune scan speed from ultra-stealth (1 pps) to full-throttle (100k+ pps). The rate limiter accounts for processing overhead to maintain accurate throughput regardless of system load.

### Asynchronous Banner Grabbing
After the SYN scan phase, DesertStorm performs **async TCP connections** to all discovered open ports using Tokio. Protocol-aware probes are sent for SSH, HTTP, FTP, SMTP, POP3, and IMAP to extract service versions, software identifiers, and OS information from response banners.

### OS Fingerprinting
DesertStorm uses two complementary techniques for operating system detection:
- **TTL Analysis** — Initial TTL values in SYN-ACK responses identify OS families (Linux/Unix = 64, Windows = 128, Cisco = 255)
- **Banner Analysis** — Service banners are parsed for OS-specific strings (Ubuntu, Debian, RHEL, Windows, FreeBSD)

### Port Intelligence Database
A built-in database of **20+ common services** provides instant security context for every open port, including service descriptions, typical uses, known vulnerability classes, and **CVSS v3 base scores** — turning raw scan data into actionable intelligence.

### Network Topology Analysis
The `--discover` flag performs **CIDR subnet analysis** before scanning, displaying network address, broadcast address, netmask, usable host range, and total host count — essential context for understanding scan scope in large engagements.

### Multiple Output Formats
Results can be exported as **human-readable tables**, **JSON** for programmatic consumption, **CSV** for spreadsheet analysis, or **grepable** one-liner format for shell pipeline integration. All formats support direct file output via `-o`.

---

## 📊 Performance Benchmarks

| Scan Type | Target Scope | Rate | Time | Packets |
|-----------|-------------|------|------|---------|
| Single host, 1 port | 1 host × 1 port | 10k pps | < 1s | 1 |
| Top 1000 ports | 1 host × 1000 ports | 10k pps | ~0.1s | 1,000 |
| Class C subnet | 254 hosts × 100 ports | 50k pps | ~0.5s | 25,400 |
| Full port scan | 1 host × 65535 ports | 50k pps | ~1.3s | 65,535 |
| Class B subnet | 65,534 hosts × 10 ports | 100k pps | ~6.5s | 655,340 |

> Benchmarks measured on Linux 6.x with a 1Gbps NIC. Actual performance depends on network conditions, target responsiveness, and system resources.

---

## ⚔️ Comparison with Other Port Scanners

| Feature | DesertStorm | Nmap | Masscan | Zmap | RustScan |
|---------|:-----------:|:----:|:-------:|:----:|:--------:|
| **Language** | Rust | C/Lua | C | C | Rust |
| **Scan Method** | Stateless SYN | Stateful multi | Stateless SYN | Stateless SYN | Nmap wrapper |
| **Raw Packets** | ✅ | ✅ | ✅ | ✅ | ❌ |
| **Memory Safety** | ✅ | ❌ | ❌ | ❌ | ✅ |
| **Banner Grabbing** | ✅ Built-in | ✅ Advanced | ❌ | ❌ | ✅ Via Nmap |
| **OS Detection** | ✅ TTL + Banner | ✅ Advanced | ❌ | ❌ | ✅ Via Nmap |
| **CVSS Risk Scores** | ✅ Built-in | ❌ | ❌ | ❌ | ❌ |
| **Port Intelligence** | ✅ Built-in | ✅ Scripts | ❌ | ❌ | ❌ |
| **Rate Control** | ✅ PPS | ✅ Timing | ✅ PPS | ✅ PPS | ✅ Batch |
| **Randomized Order** | ✅ Permutation | ✅ | ✅ | ✅ Cyclic | ❌ |
| **JSON Output** | ✅ | ✅ | ✅ | ✅ | ✅ |
| **Single Binary** | ✅ | ❌ | ✅ | ✅ | ✅ |
| **Dependencies** | Minimal | Heavy | Minimal | Minimal | Requires Nmap |
| **Ideal For** | Fast recon + context | Deep analysis | Internet-scale | Research | Quick scans |

---

## 🚀 Installation

### System Requirements

| Requirement | Minimum | Recommended |
|-------------|---------|-------------|
| **OS** | Linux (kernel 4.x+) | Linux 6.x (Ubuntu 22.04+, Kali 2023+) |
| **Rust** | 1.70+ | Latest stable |
| **Privileges** | `CAP_NET_RAW` | Root (sudo) |
| **Memory** | 32 MB | 128 MB |
| **NIC** | Any Ethernet | 1 Gbps+ |

### Method 1: Build from Source (Recommended)

```bash
# Clone the repository
git clone https://github.com/DesertDemons/DesertStorm.git
cd DesertStorm

# Build optimized release binary
cargo build --release

# Install system-wide
sudo cp target/release/desertstorm /usr/local/bin/
sudo chmod +x /usr/local/bin/desertstorm

# Verify installation
desertstorm --version
```

### Method 2: Cargo Install

```bash
cargo install --path .
```

### Method 3: One-Liner Install

```bash
git clone https://github.com/DesertDemons/DesertStorm.git && cd DesertStorm && cargo build --release && sudo cp target/release/desertstorm /usr/local/bin/
```

### Post-Install: Grant Raw Socket Capability (Optional)

Instead of running with `sudo` every time, you can grant the binary raw socket capability:

```bash
sudo setcap cap_net_raw+ep /usr/local/bin/desertstorm
```

### Verify Installation

```bash
desertstorm --version
# desertstorm 5.1.0

sudo desertstorm --examples
# Shows all usage examples
```

---

## ⚡ Quick Start

```bash
# Scan a single host on port 80
sudo desertstorm -t 192.168.1.1 -p 80

# Scan common ports with banner grabbing
sudo desertstorm -t 192.168.1.1 -p 22,80,443,3306,8080 --banner

# Scan an entire /24 subnet with full intelligence
sudo desertstorm -t 192.168.1.0/24 -p 1-1024 --discover --info --banner

# Fast scan with JSON output
sudo desertstorm -t 10.0.0.0/24 -p 80,443 -r 50000 --format json -o results.json
```

---

## 📖 Full Command Reference

```
desertstorm [OPTIONS] -t <TARGET>
```

### Required Arguments

| Argument | Description |
|----------|-------------|
| `-t, --target <IP\|CIDR>` | Target IP address (`192.168.1.1`) or CIDR range (`10.0.0.0/24`) |

### Scan Configuration

| Flag | Description | Default |
|------|-------------|---------|
| `-p, --port <PORTS>` | Port specification: single (`80`), comma-separated (`22,80,443`), range (`1-1024`), or combined (`22,80,1000-2000`) | `80` |
| `-r, --rate <PPS>` | Maximum packets per second. Use `0` for unlimited. Lower values = stealthier. | `10000` |
| `-i, --interface <NAME>` | Network interface to use (e.g., `eth0`, `ens33`, `wlan0`). Auto-detected if omitted. | Auto |
| `--source-ip <IP>` | Override source IP address in outgoing packets | Interface IP |
| `--randomize` | Randomize host scan order using permutation generator | `true` |
| `--cooldown <SECS>` | Time to wait for late responses after all probes are sent | `10` |

### Intelligence & Detection

| Flag | Description | Default |
|------|-------------|---------|
| `--banner` | Perform TCP banner grabbing on all discovered open ports | Off |
| `--banner-timeout <MS>` | Timeout for each banner grab connection | `3000` |
| `--discover` | Display CIDR network topology analysis before scanning | Off |
| `--info` | Show port intelligence (description, risk, CVSS) in results | Off |

### Output Control

| Flag | Description | Default |
|------|-------------|---------|
| `-o, --output <FILE>` | Write results to file instead of stdout. Use `-` for stdout. | `-` |
| `--format <FORMAT>` | Output format: `normal`, `json`, `csv`, `grepable` | `normal` |
| `-v, --verbose` | Enable verbose output (shows each open port as discovered) | Off |
| `--examples` | Print detailed usage examples and exit | — |

---

## 💡 Usage Examples

### Basic Port Scanning

```bash
# Scan a single port on a single host
sudo desertstorm -t 192.168.1.1 -p 80

# Scan multiple specific ports
sudo desertstorm -t 192.168.1.1 -p 22,80,443,3306,5432,8080

# Scan a port range
sudo desertstorm -t 192.168.1.1 -p 1-1024

# Full 65535 port scan
sudo desertstorm -t 192.168.1.1 -p 1-65535

# Mixed port specification
sudo desertstorm -t 192.168.1.1 -p 22,80,443,8000-9000
```

### Subnet & Network Scanning

```bash
# Scan a /24 subnet (254 hosts)
sudo desertstorm -t 192.168.1.0/24 -p 80,443

# Scan a /16 subnet (65,534 hosts) — use higher rate for speed
sudo desertstorm -t 10.0.0.0/16 -p 80 -r 100000

# Network topology analysis + scan
sudo desertstorm -t 172.16.0.0/20 -p 22,80,443 --discover

# Scan with port intelligence context
sudo desertstorm -t 192.168.1.0/24 -p 22,80,445,3389 --info
```

### Service Detection & Banner Grabbing

```bash
# Grab banners from open ports
sudo desertstorm -t 192.168.1.1 -p 21,22,80,443,3306 --banner

# Banner grabbing with extended timeout for slow services
sudo desertstorm -t 192.168.1.1 -p 1-1024 --banner --banner-timeout 5000

# Full intelligence scan (discovery + banners + port info)
sudo desertstorm -t 192.168.1.0/24 -p 1-1024 --discover --banner --info
```

### Stealth & Evasion Scanning

```bash
# Ultra-slow stealth scan (1 packet per second)
sudo desertstorm -t target.example.com -p 22,80,443 -r 1

# Low-and-slow full port scan
sudo desertstorm -t target.example.com -p 1-65535 -r 100

# Stealth scan with custom source IP
sudo desertstorm -t 192.168.1.0/24 -p 80 --source-ip 192.168.1.250 -r 50
```

### Output & Reporting

```bash
# JSON output to stdout
sudo desertstorm -t 192.168.1.0/24 -p 80,443 --format json

# JSON output saved to file
sudo desertstorm -t 192.168.1.0/24 -p 1-1024 --format json -o scan_results.json

# CSV output for spreadsheet import
sudo desertstorm -t 10.0.0.0/24 -p 22,80,443 --format csv -o report.csv

# Grepable output piped to filter
sudo desertstorm -t 192.168.1.0/24 -p 1-1024 --format grepable | grep "open"

# Grepable output with downstream processing
sudo desertstorm -t 10.0.0.0/24 -p 80 --format grepable | awk '{print $2}' | sort -u
```

### Penetration Testing Workflows

```bash
# Step 1: Quick discovery scan
sudo desertstorm -t 10.0.0.0/24 -p 22,80,443,445,3389 --discover -o discovery.json --format json

# Step 2: Deep scan on discovered hosts
sudo desertstorm -t 10.0.0.15 -p 1-65535 --banner --info -o deep_scan.json --format json

# Step 3: Targeted service enumeration
sudo desertstorm -t 10.0.0.0/24 -p 21,22,23,3306,5432,6379,27017 --banner --info
```

---

## 📤 Output Formats

### Normal (Default)

Human-readable table format with status indicators, TTL, OS fingerprint, and optional port intelligence:

```
╔══════════════════════════════════════════════════════════╗
║                     SCAN RESULTS                        ║
╚══════════════════════════════════════════════════════════╝
[+] 192.168.1.1       22/tcp  OPEN      ssh
    TTL: 64 (Linux/Unix)
    Version: OpenSSH 8.9
[+] 192.168.1.1       80/tcp  OPEN      http
    TTL: 64 (Linux/Unix)
    Version: nginx/1.24.0
    Banner: HTTP/1.1 200 OK..Server: nginx/1.24.0
[-] 192.168.1.1      443/tcp  CLOSED    https
    TTL: 64 (Linux/Unix)
```

### JSON

Structured output for programmatic consumption, SIEM ingestion, or custom tooling:

```json
[
  {
    "ip": "192.168.1.1",
    "port": 22,
    "status": "open",
    "service": "ssh",
    "version": "OpenSSH 8.9",
    "banner": "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6",
    "ttl": 64,
    "timestamp": 0.234,
    "os_guess": "Linux (Ubuntu)"
  }
]
```

### CSV

Spreadsheet-compatible format with headers for import into Excel, Google Sheets, or data analysis tools:

```csv
ip,port,status,service,ttl,os,version,timestamp
192.168.1.1,22,open,ssh,64,Linux (Ubuntu),OpenSSH 8.9,0.234
192.168.1.1,80,open,http,64,Linux (Ubuntu),nginx/1.24.0,0.312
```

### Grepable

One-line-per-host format designed for `grep`, `awk`, `sed`, and shell pipeline integration:

```
Host: 192.168.1.1	Ports: 22/ssh/open/OpenSSH 8.9/Linux (Ubuntu)/
Host: 192.168.1.1	Ports: 80/http/open/nginx 1.24.0/Linux (Ubuntu)/
```

---

## 🔬 Architecture & Technical Deep Dive

### System Architecture

```
┌──────────────────────────────────────────────────────────────┐
│                        CLI Interface                          │
│                     (clap argument parser)                     │
└───────────────────────────┬──────────────────────────────────┘
                            │
                            ▼
┌──────────────────────────────────────────────────────────────┐
│                     Scan Orchestrator                          │
│              (async main thread — Tokio runtime)               │
│                                                                │
│  ┌─────────────┐    ┌──────────────┐    ┌──────────────────┐  │
│  │ Target Parser│    │ Port Parser  │    │ Interface Resolver│  │
│  │ IP / CIDR    │    │ Range / List │    │ Auto-detect NIC  │  │
│  └──────┬──────┘    └──────┬───────┘    └────────┬─────────┘  │
│         └──────────────────┴─────────────────────┘            │
└──────────────────────┬───────────────────┬───────────────────┘
                       │                   │
              ┌────────┴───────┐  ┌────────┴────────┐
              ▼                ▼  ▼                  ▼
     ┌────────────────┐  ┌────────────────┐  ┌──────────────┐
     │   TX Thread     │  │   RX Thread     │  │Banner Grabber│
     │                 │  │                 │  │  (Phase 2)   │
     │ • Perm Generator│  │ • Packet Capture│  │              │
     │ • Pkt Template  │  │ • Cookie Verify │  │ • Async TCP  │
     │ • Rate Limiter  │  │ • TTL Analysis  │  │ • Proto Probe│
     │ • SYN Cookie    │  │ • OS Detection  │  │ • Version ID │
     └───────┬────────┘  └───────┬────────┘  └──────┬───────┘
             │                   │                   │
             ▼                   ▼                   ▼
     ┌──────────────────────────────────────────────────────┐
     │              Raw Socket Layer (libpnet)                │
     │         Ethernet Frame → IPv4 Header → TCP Header     │
     └──────────────────────────────────────────────────────┘
             │                   │                   │
             ▼                   ▼                   ▼
     ┌──────────────────────────────────────────────────────┐
     │                  Results Collector                     │
     │     Dedup → Sort → Format → Output (file/stdout)      │
     └──────────────────────────────────────────────────────┘
```

### How Stateless SYN Cookie Scanning Works

Traditional port scanners maintain a table of "pending" connections — every SYN sent creates state that must be tracked until the response arrives or times out. This limits concurrency to available memory.

DesertStorm eliminates this entirely using **SYN cookies**:

1. **Encode**: For each probe, a keyed hash is computed: `H = HASH(src_ip, dst_ip, src_port, dst_port, secret_key)`. This hash is embedded as the TCP sequence number in the outgoing SYN packet.

2. **Transmit**: The SYN packet is sent via raw socket. **No state is stored.** The TX thread immediately moves to the next target.

3. **Validate**: When a SYN-ACK arrives, the RX thread extracts the acknowledgement number (`ack = seq + 1`), recomputes the expected hash from the packet's IP/port fields, and verifies `ack == expected + 1`.

4. **Classify**: Validated SYN-ACK → **Open**. Validated RST → **Closed**. No response → **Filtered** (inferred by absence).

This approach provides **O(1) memory** regardless of scan size, enabling scans of millions of targets on minimal hardware.

### Randomized IP Permutation Generator

Sequential scanning (192.168.1.1, 192.168.1.2, 192.168.1.3...) creates obvious patterns that IDS/IPS systems can detect and block. DesertStorm uses a **multiplicative group over a prime field** to generate a permutation that:

- Visits every IP in the target range **exactly once**
- Produces a scan order that is **cryptographically non-sequential**
- Requires **no storage** (constant O(1) memory) — the next IP is computed from the current one
- Is seeded with randomness so each scan produces a **different permutation**

### Packet Construction Pipeline

Each probe packet is built from pre-computed templates for maximum throughput:

```
1. Ethernet Header (14 bytes)
   └─ src_mac, dst_mac, EtherType=IPv4

2. IPv4 Header (20 bytes)
   └─ version=4, IHL=5, TTL=64, proto=TCP, DF=1
   └─ src_ip (fixed), dst_ip (per-target)
   └─ IP checksum (recomputed per-packet)

3. TCP Header (20 bytes)
   └─ src_port (random ephemeral), dst_port (target)
   └─ seq=cookie_hash, flags=SYN, window=65535
   └─ TCP checksum with pseudo-header (recomputed per-packet)
```

The template pattern means only 3 fields change per packet (dst_ip, dst_port, src_port), minimizing per-packet computation to checksum updates.

---

## 🛡️ Port Intelligence Database

DesertStorm includes a built-in database of 20+ commonly scanned ports with actionable security context. Use `--info` to display this intelligence alongside scan results.

| Port | Service | Risk Level | CVSS | Description |
|------|---------|-----------|------|-------------|
| 21 | FTP | High | 7.5 | File Transfer Protocol — cleartext credentials |
| 22 | SSH | Medium | 5.3 | Secure Shell — brute force target |
| 23 | Telnet | **CRITICAL** | 9.8 | Unencrypted remote access (obsolete) |
| 25 | SMTP | Medium | 5.0 | Email delivery — open relay, spoofing |
| 53 | DNS | Medium | 5.0 | Name resolution — zone transfer, amplification |
| 80 | HTTP | Medium | 5.0 | Web server — application vulnerabilities |
| 110 | POP3 | High | 7.5 | Email retrieval — cleartext auth |
| 143 | IMAP | Medium | 5.0 | Email access — cleartext without STARTTLS |
| 443 | HTTPS | Medium | 4.0 | TLS web — app attacks persist |
| 445 | SMB | **CRITICAL** | 10.0 | Windows sharing — EternalBlue, worms |
| 1433 | MSSQL | High | 8.0 | SQL Server — injection, xp_cmdshell |
| 3306 | MySQL | High | 8.0 | MySQL — injection, ransomware target |
| 3389 | RDP | **CRITICAL** | 9.8 | Remote Desktop — BlueKeep, brute force |
| 5432 | PostgreSQL | High | 8.0 | PostgreSQL — injection, misconfiguration |
| 5900 | VNC | **CRITICAL** | 9.8 | Remote desktop — weak auth, no encryption |
| 6379 | Redis | **CRITICAL** | 10.0 | Key-value store — often unauthenticated |
| 8080 | HTTP Proxy | Medium | 5.0 | Alternate HTTP — dev exposure |
| 8443 | HTTPS Alt | Medium | 5.0 | Alternate HTTPS — management panels |
| 27017 | MongoDB | **CRITICAL** | 10.0 | NoSQL database — often unauthenticated |

---

## 🔒 Security Considerations

### Responsible Use

DesertStorm is a professional security tool. Please observe the following guidelines:

- **Always obtain written authorization** before scanning any network you do not own
- **Understand your local laws** — unauthorized port scanning may violate computer fraud statutes (CFAA in the US, Computer Misuse Act in the UK, etc.)
- **Use rate limiting** (`-r`) to avoid disrupting production services
- **Respect scope boundaries** — only scan IP ranges and ports explicitly authorized
- **Secure your output files** — scan results contain sensitive network topology data

### Detection Profile

| Scan Configuration | IDS Detection Risk | Notes |
|-------------------|-------------------|-------|
| `-r 1` (1 pps) | Very Low | Below most IDS thresholds |
| `-r 100` (100 pps) | Low | Blends with normal traffic |
| `-r 10000` (10k pps) | Medium | May trigger rate-based alerts |
| `-r 0` (unlimited) | High | Obvious scan pattern |
| `--randomize` (default) | Reduces risk | Non-sequential order evades pattern detection |
| Sequential mode | Increases risk | Easy for IDS to detect sweep |

---

## 🏢 Use Cases

### Penetration Testing
Run DesertStorm during the **reconnaissance phase** of authorized penetration tests to rapidly enumerate open services across target scope. The built-in CVSS scores and port intelligence help prioritize which services to investigate first.

### Vulnerability Assessment
Security teams use DesertStorm to **audit network perimeters** and identify exposed services. The JSON output integrates with vulnerability management platforms, SIEMs, and custom dashboards for continuous monitoring.

### Bug Bounty Hunting
Bug bounty hunters leverage DesertStorm's speed to **map attack surface** across large target scopes. Banner grabbing identifies specific software versions that can be cross-referenced with CVE databases.

### Network Administration
System administrators use DesertStorm to **inventory network services**, detect unauthorized services, verify firewall rules, and audit segmentation between network zones.

### Security Research
Researchers use DesertStorm to **study internet-wide service deployment** patterns, measure protocol adoption, and analyze network security posture at scale.

### Compliance Auditing
DesertStorm helps compliance teams **verify that only authorized services** are exposed, supporting PCI-DSS, HIPAA, SOC 2, and ISO 27001 requirements for regular vulnerability scanning.

---

## 🔧 Troubleshooting

### Common Issues

**"Root privileges required"**
```bash
# Solution: Run with sudo
sudo desertstorm -t 192.168.1.1 -p 80

# Or grant capabilities permanently
sudo setcap cap_net_raw+ep /usr/local/bin/desertstorm
```

**"No suitable network interface found"**
```bash
# List available interfaces
ip link show

# Specify interface manually
sudo desertstorm -t 192.168.1.1 -p 80 -i eth0
```

**"Interface 'X' not found"**
```bash
# Check your interface names (modern Linux uses predictable names)
ip addr show
# Look for names like ens33, enp0s3, wlp2s0 instead of eth0
sudo desertstorm -t 192.168.1.1 -p 80 -i ens33
```

**No results / all filtered**
- Verify target is reachable: `ping <target>`
- Check firewall isn't blocking outbound SYN: `sudo iptables -L OUTPUT`
- Increase cooldown for high-latency targets: `--cooldown 30`
- Ensure no local firewall is sending RSTs: `sudo iptables -A OUTPUT -p tcp --tcp-flags RST RST -j DROP`

**Build errors**
```bash
# Ensure Rust is up to date
rustup update stable

# Install required system dependencies (Debian/Ubuntu)
sudo apt install build-essential libpcap-dev

# Clean and rebuild
cargo clean && cargo build --release
```

---

## 🤝 Contributing

Contributions are welcome! Here's how to get involved:

1. **Fork** the repository
2. **Create** a feature branch: `git checkout -b feature/my-feature`
3. **Commit** your changes: `git commit -am 'Add new feature'`
4. **Push** to the branch: `git push origin feature/my-feature`
5. **Open** a Pull Request

### Development Setup

```bash
git clone https://github.com/DesertDemons/DesertStorm.git
cd DesertStorm
cargo build
cargo test
cargo clippy -- -D warnings
```

### Areas for Contribution

- Additional protocol probes for banner grabbing (DNS, SNMP, SIP, etc.)
- UDP scanning support
- IPv6 support
- PCAP output format
- Service version database expansion
- NSE-style scripting engine
- Windows and macOS portability
- Integration tests and CI/CD pipeline

---

## ❓ Frequently Asked Questions

### What is DesertStorm?
DesertStorm is an open-source, high-performance network port scanner and reconnaissance tool written in Rust. It uses stateless SYN scanning with raw packet crafting to discover open ports, grab service banners, fingerprint operating systems, and provide security intelligence — all in a single, fast, memory-safe binary.

### How is DesertStorm different from Nmap?
Nmap is a comprehensive, stateful scanner with deep service detection and a scripting engine (NSE). DesertStorm is a specialized stateless SYN scanner optimized for speed and simplicity, with built-in CVSS risk scoring that Nmap lacks out of the box. DesertStorm is ideal for fast reconnaissance phases, while Nmap excels at deep service enumeration. They complement each other well in penetration testing workflows.

### How is DesertStorm different from Masscan?
Masscan is the fastest internet-scale scanner but produces minimal output — just open or closed status with no service context. DesertStorm matches Masscan's stateless architecture while adding banner grabbing, OS fingerprinting, port intelligence, and CVSS scoring — bridging the gap between raw speed and actionable intelligence.

### How is DesertStorm different from RustScan?
RustScan is a Rust-based port scanner that uses standard sockets (not raw packets) and relies on Nmap for service detection. DesertStorm crafts raw SYN packets for true stateless scanning, includes its own banner grabber and port intelligence database, and has no external dependencies at runtime.

### Is port scanning legal?
Port scanning tools are legal to possess and use on networks you own or have explicit written authorization to test. Unauthorized scanning of networks without permission may violate computer fraud laws such as the CFAA (US), Computer Misuse Act (UK), or equivalent laws in your jurisdiction. Always obtain proper authorization before scanning any target.

### Does DesertStorm require root privileges?
Yes. Crafting raw SYN packets requires root (`sudo`) or the `CAP_NET_RAW` Linux capability. This is a kernel security requirement for raw socket access, not a DesertStorm-specific limitation. You can avoid using sudo every time by running `sudo setcap cap_net_raw+ep /usr/local/bin/desertstorm`.

### What operating systems does DesertStorm support?
DesertStorm currently supports Linux distributions including Ubuntu, Debian, Kali Linux, Fedora, Arch Linux, and others with kernel 4.x or later. It requires raw socket support via `libpnet`. macOS and Windows support are planned for future releases.

### How fast can DesertStorm scan?
With rate limiting disabled (`-r 0`) on a modern Linux system with a 1Gbps NIC, DesertStorm can sustain over 100,000 packets per second. A full 65,535-port scan of a single host completes in approximately 1-2 seconds at 50k pps. Network conditions, target responsiveness, and system resources affect actual throughput.

### Can DesertStorm scan entire subnets and large networks?
Yes. DesertStorm's stateless architecture uses constant O(1) memory regardless of scan size. It can scan anything from a single host to a /8 subnet. The randomized permutation generator ensures efficient, non-sequential coverage of the entire target space.

### What output formats are supported?
DesertStorm supports four output formats: **normal** (human-readable tables), **JSON** (structured data for tools and SIEMs), **CSV** (spreadsheet-compatible), and **grepable** (shell pipeline-friendly). All formats support file output via the `-o` flag.

### Can I integrate DesertStorm results with other security tools?
Yes. JSON output can be consumed by `jq`, Python scripts, SIEM platforms (Splunk, ELK, QRadar), and vulnerability management tools (Nessus, OpenVAS). Grepable output works natively with standard Unix tools (`grep`, `awk`, `sed`, `cut`). CSV output imports directly into Excel, Google Sheets, and data analysis frameworks like pandas.

### Does DesertStorm support UDP scanning?
Not yet. DesertStorm currently focuses on TCP SYN scanning. UDP scanning is on the development roadmap and will be added in a future release.

### Can DesertStorm evade intrusion detection systems?
DesertStorm includes several features that reduce detection: randomized scan order via permutation generator, configurable rate limiting (down to 1 pps), and source IP override. However, no scanner can guarantee complete evasion. Always scan with authorization and be transparent about your testing methodology.

---

## ⚠️ Legal Disclaimer

> **AUTHORIZED USE ONLY**
>
> DesertStorm is designed exclusively for **security professionals** conducting **authorized penetration testing**, **vulnerability assessments**, and **network auditing**. Unauthorized scanning of computer networks you do not own or have explicit written permission to test is **illegal** in most jurisdictions and may violate:
>
> - **United States**: Computer Fraud and Abuse Act (CFAA), 18 U.S.C. § 1030
> - **United Kingdom**: Computer Misuse Act 1990
> - **European Union**: Directive 2013/40/EU on attacks against information systems
> - **Other jurisdictions**: Local computer crime and unauthorized access laws
>
> The developers and contributors of DesertStorm accept **no liability** for any damage, legal consequences, or misuse arising from the use of this tool. **You are solely responsible** for ensuring you have proper written authorization before scanning any target network.
>
> By downloading, installing, or using DesertStorm, you agree to use it only for lawful, authorized purposes.

---

## 📄 License

This project is licensed under the **GNU General Public License v3.0** — see the [LICENSE](LICENSE) file for details.

**GPL-3.0** © [DesertDemons](https://github.com/DesertDemons)

---

<div align="center">

**Built with 🦀 Rust by [DesertDemons](https://github.com/DesertDemons)**

⭐ **Star this repo** if DesertStorm helps your security work!

[Report Bug](https://github.com/DesertDemons/DesertStorm/issues) · [Request Feature](https://github.com/DesertDemons/DesertStorm/issues) · [Contribute](https://github.com/DesertDemons/DesertStorm/pulls)

</div>
