# DesertStorm

**High-Performance Asynchronous Network Reconnaissance Tool**

DesertStorm is a stateless SYN scanner written in Rust, designed for speed, accuracy, and stealth. It uses raw packet crafting with SYN-cookie validation, randomized IP permutation scanning, and asynchronous banner grabbing to deliver fast network reconnaissance with minimal footprint.

## Features

- **Stateless SYN Scanning** — Cookie-based sequence number validation eliminates the need to track connection state, enabling massive concurrency
- **Raw Packet Engine** — Crafts Ethernet/IP/TCP packets directly via `libpnet`, bypassing kernel TCP stack overhead
- **Randomized Scan Order** — Multiplicative-group permutation generator distributes probes across the target space to avoid sequential detection
- **Configurable Rate Limiting** — Precise packets-per-second control from stealth (1 pps) to full-speed (unlimited)
- **Service Banner Grabbing** — Async TCP connections to open ports with protocol-aware probes (SSH, HTTP, FTP, SMTP, etc.)
- **OS Fingerprinting** — TTL-based and banner-based operating system detection
- **Port Intelligence** — Built-in database with service descriptions, CVSS risk scores, and security context for common ports
- **Network Topology Analysis** — CIDR breakdown showing network/broadcast addresses, host ranges, and subnet details
- **Multiple Output Formats** — Normal, JSON, CSV, and grepable output with file export

## Installation

### Prerequisites

- Rust toolchain (1.70+)
- Linux with raw socket support
- Root privileges or `CAP_NET_RAW` capability

### Build from Source

```bash
git clone https://github.com/DesertDemons/DesertStorm.git
cd DesertStorm
cargo build --release
sudo cp target/release/desertstorm /usr/local/bin/
```

### Quick Install

```bash
cargo install --path .
```

## Usage

DesertStorm requires root privileges for raw socket access.

```
sudo desertstorm -t <TARGET> -p <PORTS> [OPTIONS]
```

### Options

| Flag | Description | Default |
|------|-------------|---------|
| `-t, --target` | Target IP or CIDR range | *required* |
| `-p, --port` | Ports: single, list, or range | `80` |
| `-r, --rate` | Packets per second (0 = unlimited) | `10000` |
| `-i, --interface` | Network interface | auto-detect |
| `-o, --output` | Output file (`-` for stdout) | `-` |
| `--format` | Output format: `normal`, `json`, `csv`, `grepable` | `normal` |
| `--banner` | Grab service banners from open ports | off |
| `--discover` | Show network topology before scan | off |
| `--info` | Show port intelligence in results | off |
| `--cooldown` | Seconds to wait after TX completes | `10` |
| `--randomize` | Randomize scan order | `true` |
| `--banner-timeout` | Banner grab timeout (ms) | `3000` |
| `-v, --verbose` | Verbose output | off |
| `--source-ip` | Source IP override | interface IP |
| `--examples` | Show usage examples | — |

### Examples

**Single host scan:**
```bash
sudo desertstorm -t 192.168.1.1 -p 80
```

**Multi-port scan with banner grabbing:**
```bash
sudo desertstorm -t 192.168.1.1 -p 22,80,443,8080 --banner
```

**Subnet sweep with network discovery:**
```bash
sudo desertstorm -t 10.0.0.0/24 -p 22,80,443 --discover --info
```

**Stealth scan (low rate, full port range):**
```bash
sudo desertstorm -t target.com -p 1-65535 -r 100
```

**Fast scan with JSON output to file:**
```bash
sudo desertstorm -t 192.168.1.0/24 -p 1-1024 -r 50000 --format json -o results.json
```

**Grepable output for scripting:**
```bash
sudo desertstorm -t 10.0.0.0/24 -p 22,80,443 --format grepable | grep "open"
```

## Architecture

```
┌─────────────┐     ┌──────────────────┐     ┌─────────────┐
│  CLI Parser  │────▶│  Scan Orchestrator│────▶│   Output    │
│   (clap)     │     │   (main thread)   │     │  Formatter  │
└─────────────┘     └────────┬─────────┘     └─────────────┘
                             │
                    ┌────────┴────────┐
                    ▼                 ▼
             ┌────────────┐   ┌────────────┐
             │  TX Thread  │   │  RX Thread  │
             │ Raw SYN PKT │   │ SYN-ACK/RST│
             │  + Rate Lim │   │  + Cookie   │
             └──────┬─────┘   └──────┬─────┘
                    │                │
                    ▼                ▼
             ┌────────────────────────────┐
             │     Raw Socket (pnet)      │
             │   Ethernet → IPv4 → TCP    │
             └────────────────────────────┘
```

**TX Thread** generates SYN packets with cookie-encoded sequence numbers using a randomized IP permutation generator, rate-limited to the configured PPS.

**RX Thread** captures responses and validates SYN-ACK/RST packets against the expected cookie value. It waits for a configurable cooldown period after TX completes to capture late responses.

**Banner Grabber** (optional) performs async TCP connections to open ports with protocol-specific probes to extract service versions and OS information.

## How SYN Cookie Validation Works

DesertStorm encodes a keyed hash of `(src_ip, dst_ip, src_port, dst_port, secret)` into each SYN packet's sequence number. When a SYN-ACK arrives, the acknowledgement number (`seq + 1`) is validated against the expected hash — confirming the response is genuine without maintaining any per-connection state.

## Port Intelligence Database

DesertStorm includes a built-in database covering 20+ common ports with:

- Service name and protocol
- Description and common uses  
- Security risk assessment with CVSS base scores
- Relevant vulnerability context

Use `--info` to display port intelligence alongside scan results.

## Output Formats

**Normal** — Human-readable table with status icons, TTL, OS guess, and optional port intelligence.

**JSON** — Structured array of result objects for programmatic consumption.

**CSV** — Comma-separated with headers: `ip,port,status,service,ttl,os,version,timestamp`.

**Grepable** — One-line-per-host format compatible with `grep`, `awk`, and pipeline tools.

## Legal Disclaimer

> **⚠️ AUTHORIZED USE ONLY**
>
> DesertStorm is designed for security professionals conducting authorized penetration testing and network auditing. Unauthorized scanning of networks you do not own or have explicit written permission to test is illegal in most jurisdictions and may violate computer fraud and abuse laws.
>
> The authors accept no liability for misuse of this tool. **You are solely responsible for ensuring you have proper authorization before scanning any target.**

## License

[GPL-3.0](LICENSE) © DesertDemons
