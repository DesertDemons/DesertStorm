// DesertStorm v5.1.0 - High-Performance Asynchronous Network Reconnaissance
// Copyright (c) DesertDemons - Licensed under GPL-3.0
//
// AUTHORIZED USE ONLY. This tool is designed for security professionals
// with explicit permission to test target networks.

use std::collections::HashMap;
use std::fs::File;
use std::io::Write as IoWrite;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use chrono::Utc;
use clap::Parser;
use crossbeam::channel::{unbounded, Sender};
use lazy_static::lazy_static;
use pnet::datalink::{self, Channel, MacAddr, NetworkInterface};
use pnet::packet::ethernet::{EtherTypes, MutableEthernetPacket};
use pnet::packet::ipv4::{Ipv4Packet, MutableIpv4Packet};
use pnet::packet::tcp::{MutableTcpPacket, TcpFlags, TcpPacket};
use pnet::packet::Packet;
use rand::Rng;
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const VERSION: &str = "5.1.0";
const SIP_KEY: u64 = 0xDEADBEEF_C0FFEEEE;
const EPHEMERAL_LOW: u16 = 40000;
const EPHEMERAL_HIGH: u16 = 65000;
const PRIME_32: u64 = (1u64 << 32) + 15;

// ─── CLI Arguments ───────────────────────────────────────────────────────────

#[derive(Parser, Debug, Clone)]
#[command(name = "desertstorm", version = VERSION, about = "High-Performance Asynchronous Network Reconnaissance Tool")]
struct Args {
    /// Target IP address or CIDR range (e.g. 192.168.1.0/24)
    #[arg(short, long, required = true)]
    target: String,

    /// Ports to scan: single (80), list (22,80,443), or range (1-1024)
    #[arg(short, long, default_value = "80")]
    port: String,

    /// Packets per second (0 = unlimited)
    #[arg(short, long, default_value_t = 10000)]
    rate: u64,

    /// Source IP override
    #[arg(long)]
    source_ip: Option<String>,

    /// Network interface to use
    #[arg(short, long)]
    interface: Option<String>,

    /// Output file path (- for stdout)
    #[arg(short, long, default_value = "-")]
    output: String,

    /// Output format: normal, json, csv, grepable
    #[arg(long, default_value = "normal")]
    format: String,

    /// Seconds to wait for responses after TX completes
    #[arg(long, default_value_t = 10)]
    cooldown: u64,

    /// Randomize scan order (default: true)
    #[arg(long, default_value_t = true)]
    randomize: bool,

    /// Verbose output
    #[arg(short, long)]
    verbose: bool,

    /// Grab service banners from open ports
    #[arg(long)]
    banner: bool,

    /// Show network topology info before scanning
    #[arg(long)]
    discover: bool,

    /// Show port intelligence alongside results
    #[arg(long)]
    info: bool,

    /// Print usage examples and exit
    #[arg(long)]
    examples: bool,

    /// Banner grab timeout in milliseconds
    #[arg(long, default_value_t = 3000)]
    banner_timeout: u64,
}

// ─── Data Structures ─────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ScanResult {
    ip: String,
    port: u16,
    status: PortStatus,
    service: String,
    version: Option<String>,
    banner: Option<String>,
    ttl: Option<u8>,
    timestamp: f64,
    os_guess: Option<String>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
enum PortStatus {
    Open,
    Closed,
    Filtered,
}

impl std::fmt::Display for PortStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PortStatus::Open => write!(f, "open"),
            PortStatus::Closed => write!(f, "closed"),
            PortStatus::Filtered => write!(f, "filtered"),
        }
    }
}

#[derive(Debug, Clone)]
struct PortInfo {
    name: &'static str,
    protocol: &'static str,
    description: &'static str,
    security_risk: &'static str,
    common_uses: &'static str,
    cvss_score: Option<f32>,
}

#[derive(Debug, Clone)]
struct NetworkInfo {
    network_address: String,
    broadcast_address: String,
    netmask: String,
    cidr_prefix: u8,
    total_hosts: u64,
    host_range: (String, String),
}

// ─── Port Intelligence Database ──────────────────────────────────────────────

lazy_static! {
    static ref PORT_DB: HashMap<u16, PortInfo> = {
        let mut m = HashMap::new();
        let entries: Vec<(u16, PortInfo)> = vec![
            (21, PortInfo {
                name: "ftp", protocol: "TCP",
                description: "File Transfer Protocol",
                security_risk: "High - Cleartext credentials, bounce attacks",
                common_uses: "File transfers, firmware updates",
                cvss_score: Some(7.5),
            }),
            (22, PortInfo {
                name: "ssh", protocol: "TCP",
                description: "Secure Shell - Encrypted remote administration",
                security_risk: "Medium - Brute force target",
                common_uses: "Remote management, SFTP, Git, tunneling",
                cvss_score: Some(5.3),
            }),
            (23, PortInfo {
                name: "telnet", protocol: "TCP",
                description: "Telnet - Unencrypted remote access (OBSOLETE)",
                security_risk: "CRITICAL - Cleartext passwords",
                common_uses: "Legacy devices (replace with SSH)",
                cvss_score: Some(9.8),
            }),
            (25, PortInfo {
                name: "smtp", protocol: "TCP",
                description: "Simple Mail Transfer Protocol",
                security_risk: "Medium - Open relay, spoofing",
                common_uses: "Email delivery",
                cvss_score: Some(5.0),
            }),
            (53, PortInfo {
                name: "dns", protocol: "TCP/UDP",
                description: "Domain Name System",
                security_risk: "Medium - Zone transfer, amplification",
                common_uses: "Name resolution, service discovery",
                cvss_score: Some(5.0),
            }),
            (80, PortInfo {
                name: "http", protocol: "TCP",
                description: "HyperText Transfer Protocol",
                security_risk: "Medium - Web app vulnerabilities",
                common_uses: "Web browsing, APIs, redirects",
                cvss_score: Some(5.0),
            }),
            (110, PortInfo {
                name: "pop3", protocol: "TCP",
                description: "Post Office Protocol v3",
                security_risk: "High - Cleartext authentication",
                common_uses: "Email retrieval",
                cvss_score: Some(7.5),
            }),
            (143, PortInfo {
                name: "imap", protocol: "TCP",
                description: "Internet Message Access Protocol",
                security_risk: "Medium - Cleartext without STARTTLS",
                common_uses: "Email access",
                cvss_score: Some(5.0),
            }),
            (443, PortInfo {
                name: "https", protocol: "TCP",
                description: "HTTP Secure (TLS)",
                security_risk: "Medium - Encrypted but app attacks persist",
                common_uses: "Secure web, e-commerce, APIs",
                cvss_score: Some(4.0),
            }),
            (445, PortInfo {
                name: "smb", protocol: "TCP",
                description: "Server Message Block (Windows sharing)",
                security_risk: "CRITICAL - EternalBlue, worms",
                common_uses: "Windows file sharing, AD",
                cvss_score: Some(10.0),
            }),
            (1433, PortInfo {
                name: "mssql", protocol: "TCP",
                description: "Microsoft SQL Server",
                security_risk: "High - SQL injection, xp_cmdshell",
                common_uses: "Enterprise databases",
                cvss_score: Some(8.0),
            }),
            (3306, PortInfo {
                name: "mysql", protocol: "TCP",
                description: "MySQL Database",
                security_risk: "High - SQL injection, ransomware",
                common_uses: "Web applications, CMS",
                cvss_score: Some(8.0),
            }),
            (3389, PortInfo {
                name: "rdp", protocol: "TCP",
                description: "Remote Desktop Protocol",
                security_risk: "CRITICAL - BlueKeep, brute force",
                common_uses: "Windows remote desktop",
                cvss_score: Some(9.8),
            }),
            (5432, PortInfo {
                name: "postgresql", protocol: "TCP",
                description: "PostgreSQL Database",
                security_risk: "High - SQL injection, misconfigs",
                common_uses: "Enterprise databases, web apps",
                cvss_score: Some(8.0),
            }),
            (5900, PortInfo {
                name: "vnc", protocol: "TCP",
                description: "Virtual Network Computing",
                security_risk: "CRITICAL - Weak auth, no encryption",
                common_uses: "Remote desktop (cross-platform)",
                cvss_score: Some(9.8),
            }),
            (6379, PortInfo {
                name: "redis", protocol: "TCP",
                description: "Redis Key-Value Store",
                security_risk: "CRITICAL - Often unauthenticated",
                common_uses: "Caching, session storage, message broker",
                cvss_score: Some(10.0),
            }),
            (8080, PortInfo {
                name: "http-proxy", protocol: "TCP",
                description: "HTTP Alternate/Proxy",
                security_risk: "Medium - Dev exposure, proxy attacks",
                common_uses: "Proxies, Tomcat, dev servers",
                cvss_score: Some(5.0),
            }),
            (8443, PortInfo {
                name: "https-alt", protocol: "TCP",
                description: "HTTPS Alternate",
                security_risk: "Medium - Often management interfaces",
                common_uses: "Admin panels, alternative HTTPS",
                cvss_score: Some(5.0),
            }),
            (27017, PortInfo {
                name: "mongodb", protocol: "TCP",
                description: "MongoDB NoSQL Database",
                security_risk: "CRITICAL - Often unauthenticated",
                common_uses: "NoSQL databases, web apps",
                cvss_score: Some(10.0),
            }),
        ];
        for (port, info) in entries {
            m.insert(port, info);
        }
        m
    };

    static ref SERVICE_NAMES: HashMap<u16, &'static str> = {
        let mut m = HashMap::new();
        for (port, info) in PORT_DB.iter() {
            m.insert(*port, info.name);
        }
        m
    };
}

// ─── Sequence Number Encoding (Cookie-based SYN validation) ──────────────────

fn encode_seq(src_ip: Ipv4Addr, dst_ip: Ipv4Addr, src_port: u16, dst_port: u16) -> u32 {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};

    let mut hasher = DefaultHasher::new();
    src_ip.hash(&mut hasher);
    dst_ip.hash(&mut hasher);
    src_port.hash(&mut hasher);
    dst_port.hash(&mut hasher);
    SIP_KEY.hash(&mut hasher);

    let hash = hasher.finish();
    ((hash >> 32) as u32).wrapping_add(hash as u32)
}

// ─── Parsers ─────────────────────────────────────────────────────────────────

fn parse_ports(s: &str) -> Vec<u16> {
    let mut ports = Vec::new();
    for part in s.split(',') {
        let part = part.trim();
        if part.contains('-') {
            let bounds: Vec<&str> = part.splitn(2, '-').collect();
            if bounds.len() == 2 {
                if let (Ok(lo), Ok(hi)) = (bounds[0].parse::<u16>(), bounds[1].parse::<u16>()) {
                    if lo > 0 && lo <= hi {
                        ports.extend(lo..=hi);
                    }
                }
            }
        } else if let Ok(port) = part.parse::<u16>() {
            if port > 0 {
                ports.push(port);
            }
        }
    }
    ports.sort_unstable();
    ports.dedup();
    ports
}

fn parse_target(target: &str) -> Result<(u32, u32), String> {
    if let Some(idx) = target.find('/') {
        let ip_part = &target[..idx];
        let prefix: u32 = target[idx + 1..]
            .parse()
            .map_err(|_| format!("Invalid prefix length in '{}'", target))?;
        if prefix > 32 {
            return Err(format!("Prefix length {} exceeds 32", prefix));
        }
        let base: Ipv4Addr = ip_part
            .parse()
            .map_err(|_| format!("Invalid IP address '{}'", ip_part))?;
        let base_u32 = u32::from(base);
        let mask = if prefix == 0 { 0 } else { !((1u32 << (32 - prefix)) - 1) };
        let network = base_u32 & mask;
        let broadcast = network | !mask;
        Ok((network, broadcast))
    } else {
        let ip: Ipv4Addr = target
            .parse()
            .map_err(|_| format!("Invalid IP address '{}'", target))?;
        let v = u32::from(ip);
        Ok((v, v))
    }
}

fn analyze_network(target: &str) -> Result<NetworkInfo, String> {
    if let Some(idx) = target.find('/') {
        let ip_part = &target[..idx];
        let prefix: u8 = target[idx + 1..]
            .parse()
            .map_err(|_| "Invalid prefix".to_string())?;
        let base: Ipv4Addr = ip_part.parse().map_err(|e| e.to_string())?;
        let base_u32 = u32::from(base);
        let mask = if prefix == 0 { 0u32 } else { !((1u32 << (32 - prefix)) - 1) };
        let network = base_u32 & mask;
        let broadcast = network | !mask;
        let total_hosts = match prefix {
            32 => 1,
            31 => 2,
            _ => (1u64 << (32 - prefix)) - 2,
        };
        let first = if prefix >= 31 { network } else { network + 1 };
        let last = if prefix >= 31 { broadcast } else { broadcast - 1 };

        Ok(NetworkInfo {
            network_address: Ipv4Addr::from(network).to_string(),
            broadcast_address: Ipv4Addr::from(broadcast).to_string(),
            netmask: Ipv4Addr::from(mask).to_string(),
            cidr_prefix: prefix,
            total_hosts,
            host_range: (
                Ipv4Addr::from(first).to_string(),
                Ipv4Addr::from(last).to_string(),
            ),
        })
    } else {
        Ok(NetworkInfo {
            network_address: target.to_string(),
            broadcast_address: target.to_string(),
            netmask: "255.255.255.255".to_string(),
            cidr_prefix: 32,
            total_hosts: 1,
            host_range: (target.to_string(), target.to_string()),
        })
    }
}

// ─── Randomized IP Permutation Generator ─────────────────────────────────────

struct PermutationGen {
    prime: u64,
    root: u64,
    current: u64,
    start: u64,
    count: u64,
}

impl PermutationGen {
    fn new(seed: u64) -> Self {
        let roots = [3u64, 5, 7, 11, 13, 17];
        let root = roots[(seed as usize) % roots.len()];
        let current = (seed % PRIME_32).max(1);
        Self {
            prime: PRIME_32,
            root,
            current,
            start: current,
            count: 0,
        }
    }

    fn next(&mut self) -> Option<Ipv4Addr> {
        loop {
            self.current = (self.current.wrapping_mul(self.root)) % self.prime;
            self.count += 1;
            if self.count > self.prime {
                return None;
            }
            if self.current == self.start {
                return None;
            }
            if self.current == 0 || self.current > u32::MAX as u64 {
                continue;
            }
            return Some(Ipv4Addr::from(self.current as u32));
        }
    }
}

// ─── Raw Packet Construction ─────────────────────────────────────────────────

struct PacketTemplate {
    eth_hdr: Vec<u8>,
    ip_tmpl: Vec<u8>,
    tcp_tmpl: Vec<u8>,
    src_ip: Ipv4Addr,
}

impl PacketTemplate {
    fn new(iface: &NetworkInterface, src_ip: Ipv4Addr, dst_mac: MacAddr) -> Self {
        let src_mac = iface.mac.expect("Interface requires a MAC address");

        let mut eth = vec![0u8; 14];
        {
            let mut pkt = MutableEthernetPacket::new(&mut eth).unwrap();
            pkt.set_destination(dst_mac);
            pkt.set_source(src_mac);
            pkt.set_ethertype(EtherTypes::Ipv4);
        }

        let mut ip = vec![0u8; 20];
        {
            let mut pkt = MutableIpv4Packet::new(&mut ip).unwrap();
            pkt.set_version(4);
            pkt.set_header_length(5);
            pkt.set_total_length(40);
            pkt.set_ttl(64);
            pkt.set_flags(pnet::packet::ipv4::Ipv4Flags::DontFragment);
            pkt.set_next_level_protocol(pnet::packet::ip::IpNextHeaderProtocols::Tcp);
            pkt.set_source(src_ip);
        }

        let mut tcp = vec![0u8; 20];
        {
            let mut pkt = MutableTcpPacket::new(&mut tcp).unwrap();
            pkt.set_data_offset(5);
            pkt.set_flags(TcpFlags::SYN);
            pkt.set_window(65535);
        }

        Self { eth_hdr: eth, ip_tmpl: ip, tcp_tmpl: tcp, src_ip }
    }

    fn generate(&self, dst_ip: Ipv4Addr, dst_port: u16, seq: u32, src_port: u16) -> Vec<u8> {
        let mut pkt = Vec::with_capacity(54);
        pkt.extend_from_slice(&self.eth_hdr);

        let mut ip = self.ip_tmpl.clone();
        {
            let mut p = MutableIpv4Packet::new(&mut ip).unwrap();
            p.set_destination(dst_ip);
            p.set_identification(rand::thread_rng().gen());
            // Zero checksum before computing
            p.set_checksum(0);
            let cksum = Self::ip_checksum(&ip);
            p.set_checksum(cksum);
        }
        pkt.extend_from_slice(&ip);

        let mut tcp = self.tcp_tmpl.clone();
        {
            let mut p = MutableTcpPacket::new(&mut tcp).unwrap();
            p.set_destination(dst_port);
            p.set_source(src_port);
            p.set_sequence(seq);
            // Zero checksum before computing
            p.set_checksum(0);
            let cksum = Self::tcp_checksum(&self.src_ip, &dst_ip, &tcp);
            p.set_checksum(cksum);
        }
        pkt.extend_from_slice(&tcp);
        pkt
    }

    fn ip_checksum(hdr: &[u8]) -> u16 {
        let mut sum = 0u32;
        for i in (0..hdr.len()).step_by(2) {
            let word = if i + 1 < hdr.len() {
                ((hdr[i] as u16) << 8) | (hdr[i + 1] as u16)
            } else {
                (hdr[i] as u16) << 8
            };
            sum += word as u32;
        }
        while (sum >> 16) != 0 {
            sum = (sum & 0xFFFF) + (sum >> 16);
        }
        !(sum as u16)
    }

    fn tcp_checksum(src: &Ipv4Addr, dst: &Ipv4Addr, tcp: &[u8]) -> u16 {
        let mut sum = 0u32;
        // Pseudo-header: src ip, dst ip as 16-bit words
        let src_oct = src.octets();
        let dst_oct = dst.octets();
        sum += ((src_oct[0] as u32) << 8) | (src_oct[1] as u32);
        sum += ((src_oct[2] as u32) << 8) | (src_oct[3] as u32);
        sum += ((dst_oct[0] as u32) << 8) | (dst_oct[1] as u32);
        sum += ((dst_oct[2] as u32) << 8) | (dst_oct[3] as u32);
        sum += 6u32; // TCP protocol number
        sum += tcp.len() as u32;

        for i in (0..tcp.len()).step_by(2) {
            let word = if i + 1 < tcp.len() {
                ((tcp[i] as u16) << 8) | (tcp[i + 1] as u16)
            } else {
                (tcp[i] as u16) << 8
            };
            sum += word as u32;
        }
        while (sum >> 16) != 0 {
            sum = (sum & 0xFFFF) + (sum >> 16);
        }
        !(sum as u16)
    }
}

// ─── TX Thread (Packet Transmitter) ──────────────────────────────────────────

fn tx_thread(
    iface: NetworkInterface,
    target_range: (u32, u32),
    ports: Vec<u16>,
    rate: u64,
    src_ip: Ipv4Addr,
    randomize: bool,
    tx_done: Arc<AtomicBool>,
    sent_count: Arc<AtomicU64>,
    verbose: bool,
) {
    let (mut tx, _) = match datalink::channel(&iface, Default::default()) {
        Ok(Channel::Ethernet(tx, _)) => (tx, ()),
        Ok(_) => { eprintln!("[-] Unsupported channel type"); return; }
        Err(e) => { eprintln!("[-] TX channel error: {}", e); return; }
    };

    let gw_mac = MacAddr::new(0xff, 0xff, 0xff, 0xff, 0xff, 0xff);
    let tmpl = PacketTemplate::new(&iface, src_ip, gw_mac);
    let mut rng = rand::thread_rng();

    let mut count: u64 = 0;
    let start = Instant::now();
    let mut last_report = Instant::now();

    if verbose {
        eprintln!("[*] TX thread started (rate: {} pps)", if rate == 0 { "unlimited".into() } else { rate.to_string() });
    }

    if randomize {
        // Randomized scan using multiplicative-group permutation
        let mut perm = PermutationGen::new(rng.gen());
        while let Some(dst_ip) = perm.next() {
            let ip_u32 = u32::from(dst_ip);
            if ip_u32 < target_range.0 || ip_u32 > target_range.1 {
                continue;
            }
            for &port in &ports {
                let src_port = rng.gen_range(EPHEMERAL_LOW..EPHEMERAL_HIGH);
                let seq = encode_seq(src_ip, dst_ip, src_port, port);
                let pkt = tmpl.generate(dst_ip, port, seq, src_port);
                let _ = tx.send_to(&pkt, None);
                count += 1;
                rate_limit(rate, count, &start);
                report_progress(&mut last_report, count, &start, &sent_count);
            }
        }
    } else {
        // Sequential scan
        let mut ip_u32 = target_range.0;
        while ip_u32 <= target_range.1 {
            let dst_ip = Ipv4Addr::from(ip_u32);
            for &port in &ports {
                let src_port = rng.gen_range(EPHEMERAL_LOW..EPHEMERAL_HIGH);
                let seq = encode_seq(src_ip, dst_ip, src_port, port);
                let pkt = tmpl.generate(dst_ip, port, seq, src_port);
                let _ = tx.send_to(&pkt, None);
                count += 1;
                rate_limit(rate, count, &start);
                report_progress(&mut last_report, count, &start, &sent_count);
            }
            ip_u32 = ip_u32.saturating_add(1);
            if ip_u32 == 0 { break; }
        }
    }

    sent_count.store(count, Ordering::SeqCst);
    tx_done.store(true, Ordering::SeqCst);

    let elapsed = start.elapsed().as_secs_f64();
    let pps = if elapsed > 0.0 { count as f64 / elapsed } else { 0.0 };
    eprintln!("\n[+] TX complete: {} packets sent in {:.2}s ({:.0} pps)", count, elapsed, pps);
}

fn rate_limit(rate: u64, count: u64, start: &Instant) {
    if rate > 0 {
        let elapsed = start.elapsed().as_secs_f64();
        let expected = count as f64 / rate as f64;
        if elapsed < expected {
            std::thread::sleep(Duration::from_secs_f64(expected - elapsed));
        }
    }
}

fn report_progress(last_report: &mut Instant, count: u64, start: &Instant, sent_count: &Arc<AtomicU64>) {
    if last_report.elapsed() > Duration::from_secs(1) {
        let pps = count as f64 / start.elapsed().as_secs_f64();
        eprint!("\r[*] TX: {:>10} pkts | {:>8.0} pps", count, pps);
        let _ = std::io::stderr().flush();
        sent_count.store(count, Ordering::Relaxed);
        *last_report = Instant::now();
    }
}

// ─── RX Thread (Response Receiver) ───────────────────────────────────────────

fn rx_thread(
    iface: NetworkInterface,
    src_ip: Ipv4Addr,
    results_tx: Sender<ScanResult>,
    cooldown: u64,
    tx_done: Arc<AtomicBool>,
    verbose: bool,
) {
    let (_, mut rx) = match datalink::channel(&iface, Default::default()) {
        Ok(Channel::Ethernet(_, rx)) => ((), rx),
        Ok(_) => { eprintln!("[-] Unsupported channel type"); return; }
        Err(e) => { eprintln!("[-] RX channel error: {}", e); return; }
    };

    if verbose {
        eprintln!("[*] RX thread listening (cooldown: {}s after TX)", cooldown);
    }

    let mut count: u64 = 0;
    let start = Instant::now();
    let mut cooldown_start: Option<Instant> = None;

    loop {
        // Once TX is done, start the cooldown timer
        if tx_done.load(Ordering::SeqCst) {
            if cooldown_start.is_none() {
                cooldown_start = Some(Instant::now());
                if verbose {
                    eprintln!("[*] TX complete, waiting {}s for remaining responses...", cooldown);
                }
            }
            if let Some(cs) = cooldown_start {
                if cs.elapsed() >= Duration::from_secs(cooldown) {
                    break;
                }
            }
        }

        // Safety timeout: don't run forever even if TX hangs
        if start.elapsed() > Duration::from_secs(3600) {
            eprintln!("[-] RX safety timeout reached (1 hour)");
            break;
        }

        match rx.next() {
            Ok(packet) => {
                let eth = match pnet::packet::ethernet::EthernetPacket::new(packet) {
                    Some(e) => e,
                    None => continue,
                };
                if eth.get_ethertype() != EtherTypes::Ipv4 {
                    continue;
                }
                let ip = match Ipv4Packet::new(eth.payload()) {
                    Some(i) => i,
                    None => continue,
                };
                if ip.get_next_level_protocol() != pnet::packet::ip::IpNextHeaderProtocols::Tcp {
                    continue;
                }
                let tcp = match TcpPacket::new(ip.payload()) {
                    Some(t) => t,
                    None => continue,
                };

                let (src_ip_pkt, _dst_ip_pkt) = (ip.get_source(), ip.get_destination());
                let (remote_port, local_port) = (tcp.get_source(), tcp.get_destination());

                // Validate ephemeral port range
                if !(EPHEMERAL_LOW..EPHEMERAL_HIGH).contains(&local_port) {
                    continue;
                }

                // Validate SYN cookie
                let ack = tcp.get_acknowledgement();
                let expected = encode_seq(src_ip, src_ip_pkt, local_port, remote_port);
                if ack != expected.wrapping_add(1) {
                    continue;
                }

                let flags = tcp.get_flags();
                let status = if (flags & TcpFlags::SYN != 0) && (flags & TcpFlags::ACK != 0) {
                    PortStatus::Open
                } else if flags & TcpFlags::RST != 0 {
                    PortStatus::Closed
                } else {
                    continue;
                };

                let ttl = ip.get_ttl();
                let os_guess = guess_os_from_ttl(ttl);

                let result = ScanResult {
                    ip: src_ip_pkt.to_string(),
                    port: remote_port,
                    status,
                    service: SERVICE_NAMES
                        .get(&remote_port)
                        .copied()
                        .unwrap_or("unknown")
                        .to_string(),
                    version: None,
                    banner: None,
                    ttl: Some(ttl),
                    timestamp: start.elapsed().as_secs_f64(),
                    os_guess,
                };

                if results_tx.send(result).is_err() {
                    break;
                }
                count += 1;
            }
            Err(_) => {
                std::thread::sleep(Duration::from_millis(1));
                continue;
            }
        }
    }

    eprintln!("[+] RX complete: {} responses captured", count);
}

fn guess_os_from_ttl(ttl: u8) -> Option<String> {
    if ttl <= 64 {
        Some("Linux/Unix".to_string())
    } else if ttl <= 128 {
        Some("Windows".to_string())
    } else {
        Some("Cisco/Network".to_string())
    }
}

// ─── Banner Grabbing ─────────────────────────────────────────────────────────

async fn grab_banner(
    ip: &str,
    port: u16,
    timeout_ms: u64,
) -> Option<(String, String, Option<String>)> {
    let addr: SocketAddr = format!("{}:{}", ip, port).parse().ok()?;
    let timeout = Duration::from_millis(timeout_ms);

    match tokio::time::timeout(timeout, tokio::net::TcpStream::connect(addr)).await {
        Ok(Ok(mut stream)) => {
            let probe: &[u8] = match port {
                21 => b"",  // FTP sends banner on connect
                22 => b"SSH-2.0-DesertStorm_5.1\r\n",
                25 | 587 => b"EHLO desertstorm\r\n",
                80 | 8080 | 8443 => b"HEAD / HTTP/1.0\r\nHost: target\r\nUser-Agent: DesertStorm/5.1\r\n\r\n",
                110 => b"",  // POP3 sends banner on connect
                143 => b"",  // IMAP sends banner on connect
                _ => b"\r\n",
            };

            if !probe.is_empty() {
                let _ = stream.write_all(probe).await;
            }

            let mut buf = vec![0u8; 4096];
            match tokio::time::timeout(Duration::from_millis(2000), stream.read(&mut buf)).await {
                Ok(Ok(n)) if n > 0 => {
                    let raw = &buf[..n];
                    // Sanitize: strip non-printable chars but keep newlines
                    let banner: String = raw
                        .iter()
                        .map(|&b| if b == b'\n' || b == b'\r' || (b >= 0x20 && b < 0x7f) { b as char } else { '.' })
                        .collect::<String>()
                        .trim()
                        .to_string();

                    let version = extract_version(&banner, port);
                    let os = detect_os_from_banner(&banner);
                    Some((banner, version, os))
                }
                _ => None,
            }
        }
        _ => None,
    }
}

fn extract_version(banner: &str, port: u16) -> String {
    let lower = banner.to_lowercase();
    match port {
        22 if lower.contains("openssh") => {
            lower
                .split("openssh_")
                .nth(1)
                .and_then(|s| s.split(|c: char| !c.is_ascii_digit() && c != '.').next())
                .map(|v| format!("OpenSSH {}", v))
                .unwrap_or_else(|| "OpenSSH".to_string())
        }
        80 | 443 | 8080 | 8443 if lower.contains("server:") => banner
            .lines()
            .find(|l| l.to_lowercase().starts_with("server:"))
            .map(|l| l.trim_start_matches(|c: char| c != ':').trim_start_matches(':').trim().to_string())
            .unwrap_or_else(|| "unknown".to_string()),
        21 if lower.contains("ftpd") || lower.contains("ftp") => {
            banner.split_whitespace().take(3).collect::<Vec<_>>().join(" ")
        }
        _ => "unknown".to_string(),
    }
}

fn detect_os_from_banner(banner: &str) -> Option<String> {
    let lower = banner.to_lowercase();
    if lower.contains("ubuntu") {
        Some("Linux (Ubuntu)".to_string())
    } else if lower.contains("debian") {
        Some("Linux (Debian)".to_string())
    } else if lower.contains("centos") || lower.contains("red hat") || lower.contains("rhel") {
        Some("Linux (RHEL/CentOS)".to_string())
    } else if lower.contains("windows") || lower.contains("microsoft") {
        Some("Windows".to_string())
    } else if lower.contains("freebsd") {
        Some("FreeBSD".to_string())
    } else {
        None
    }
}

// ─── Output Formatting ──────────────────────────────────────────────────────

fn format_results(results: &[ScanResult], format: &str, show_info: bool) -> String {
    let mut out = String::new();
    match format {
        "json" => {
            out.push_str(&serde_json::to_string_pretty(results).unwrap_or_default());
        }
        "csv" => {
            out.push_str("ip,port,status,service,ttl,os,version,timestamp\n");
            for r in results {
                out.push_str(&format!(
                    "{},{},{},{},{},{},{},{:.3}\n",
                    r.ip,
                    r.port,
                    r.status,
                    r.service,
                    r.ttl.map(|t| t.to_string()).unwrap_or_default(),
                    r.os_guess.as_deref().unwrap_or(""),
                    r.version.as_deref().unwrap_or(""),
                    r.timestamp
                ));
            }
        }
        "grepable" => {
            for r in results {
                if r.status == PortStatus::Open {
                    out.push_str(&format!(
                        "Host: {}\tPorts: {}/{}/open/{}/{}/\n",
                        r.ip,
                        r.port,
                        r.service,
                        r.version.as_deref().unwrap_or(""),
                        r.os_guess.as_deref().unwrap_or("")
                    ));
                }
            }
        }
        _ => {
            out.push_str("╔══════════════════════════════════════════════════════════╗\n");
            out.push_str("║                     SCAN RESULTS                        ║\n");
            out.push_str("╚══════════════════════════════════════════════════════════╝\n");

            for r in results {
                let icon = match r.status {
                    PortStatus::Open => "+",
                    PortStatus::Closed => "-",
                    PortStatus::Filtered => "?",
                };
                out.push_str(&format!(
                    "[{}] {:15} {:>5}/tcp  {:8}  {}\n",
                    icon,
                    r.ip,
                    r.port,
                    r.status.to_string().to_uppercase(),
                    r.service
                ));

                if let Some(ttl) = r.ttl {
                    out.push_str(&format!("    TTL: {}", ttl));
                    if let Some(os) = &r.os_guess {
                        out.push_str(&format!(" ({})", os));
                    }
                    out.push('\n');
                }

                if let Some(ver) = &r.version {
                    if ver != "unknown" {
                        out.push_str(&format!("    Version: {}\n", ver));
                    }
                }

                if let Some(banner) = &r.banner {
                    // Truncate long banners for display
                    let display = if banner.len() > 120 {
                        format!("{}...", &banner[..120])
                    } else {
                        banner.clone()
                    };
                    out.push_str(&format!("    Banner: {}\n", display));
                }

                if show_info && r.status == PortStatus::Open {
                    if let Some(info) = PORT_DB.get(&r.port) {
                        out.push_str(&format!(
                            "    Info: {} | Risk: {} | CVSS: {:.1}\n",
                            info.description,
                            info.security_risk,
                            info.cvss_score.unwrap_or(0.0)
                        ));
                    }
                }
            }
        }
    }
    out
}

fn write_output(content: &str, path: &str) -> std::io::Result<()> {
    if path == "-" {
        print!("{}", content);
    } else {
        let mut f = File::create(path)?;
        f.write_all(content.as_bytes())?;
        eprintln!("[+] Results saved to: {}", path);
    }
    Ok(())
}

// ─── Display Helpers ─────────────────────────────────────────────────────────

fn print_banner_art() {
    eprintln!(
        r#"
 ____                      _   ____  _
|  _ \  ___  ___  ___ _ __| |_/ ___|| |_ ___  _ __ _ __ ___
| | | |/ _ \/ __|/ _ \ '__| __\___ \| __/ _ \| '__| '_ ` _ \
| |_| |  __/\__ \  __/ |  | |_ ___) | || (_) | |  | | | | | |
|____/ \___||___/\___|_|   \__|____/ \__\___/|_|  |_| |_| |_|

   DesertStorm v{} - By DesertDemons
   High-Performance Asynchronous Network Reconnaissance
"#,
        VERSION
    );
}

fn print_network_info(info: &NetworkInfo) {
    eprintln!("╔══════════════════════════════════════════════════════════╗");
    eprintln!("║              NETWORK TOPOLOGY ANALYSIS                  ║");
    eprintln!("╚══════════════════════════════════════════════════════════╝");
    eprintln!("  Network:     {}/{}", info.network_address, info.cidr_prefix);
    eprintln!("  Broadcast:   {}", info.broadcast_address);
    eprintln!("  Netmask:     {}", info.netmask);
    eprintln!("  Host Range:  {} - {}", info.host_range.0, info.host_range.1);
    eprintln!("  Total Hosts: {}", info.total_hosts);
    eprintln!();
}

fn print_port_info(port: u16) {
    if let Some(info) = PORT_DB.get(&port) {
        eprintln!("╔══════════════════════════════════════════════════════════╗");
        eprintln!(
            "║  PORT {} - {} ({})",
            port,
            info.name.to_uppercase(),
            info.protocol
        );
        eprintln!("╚══════════════════════════════════════════════════════════╝");
        eprintln!("  {}", info.description);
        eprintln!(
            "  Risk: {} (CVSS: {:.1})",
            info.security_risk,
            info.cvss_score.unwrap_or(0.0)
        );
        eprintln!("  Uses: {}", info.common_uses);
        eprintln!();
    }
}

fn print_examples() {
    eprintln!(
        r#"
╔══════════════════════════════════════════════════════════════════╗
║                     DESERTSTORM EXAMPLES                        ║
╚══════════════════════════════════════════════════════════════════╝

BASIC SCANS:
  sudo desertstorm -t 192.168.1.1 -p 80                 Single host
  sudo desertstorm -t 192.168.1.1 -p 22,80,443          Multiple ports
  sudo desertstorm -t 192.168.1.0/24 -p 80              Subnet sweep

NETWORK INTELLIGENCE:
  sudo desertstorm -t 10.0.0.0/16 --discover            Topology analysis
  sudo desertstorm -t 192.168.1.1 -p 22 --info          Port intelligence
  sudo desertstorm -t 192.168.1.1 -p 80 --banner        Banner grabbing

PERFORMANCE TUNING:
  sudo desertstorm -t 10.0.0.0/24 -p 1-1024 -r 100     Slow/stealth
  sudo desertstorm -t 10.0.0.0/24 -p 80 -r 50000       Fast scan
  sudo desertstorm -t 10.0.0.0/24 --no-randomize        Sequential order

OUTPUT FORMATS:
  sudo desertstorm -t 192.168.1.0/24 --format json      JSON output
  sudo desertstorm -t 192.168.1.0/24 --format csv       CSV output
  sudo desertstorm -t 192.168.1.0/24 --format grepable  Grepable output
  sudo desertstorm -t 192.168.1.0/24 -o results.json    Save to file
"#
    );
}

// ─── Main Entry Point ────────────────────────────────────────────────────────

#[tokio::main]
async fn main() {
    let args = Args::parse();

    if args.examples {
        print_banner_art();
        print_examples();
        return;
    }

    print_banner_art();

    // Root check (raw sockets require CAP_NET_RAW or root)
    if unsafe { libc::getuid() } != 0 {
        eprintln!("[-] ERROR: Root privileges required for raw socket access");
        eprintln!("    Run with: sudo desertstorm ...");
        std::process::exit(1);
    }

    // Network discovery info
    if args.discover {
        match analyze_network(&args.target) {
            Ok(info) => print_network_info(&info),
            Err(e) => {
                eprintln!("[-] Network analysis failed: {}", e);
                std::process::exit(1);
            }
        }
    }

    // Port intelligence
    if args.info && !args.port.contains(',') && !args.port.contains('-') {
        if let Ok(port) = args.port.parse::<u16>() {
            print_port_info(port);
        }
    }

    // Resolve interface
    let iface_name = args.interface.clone().unwrap_or_else(|| {
        datalink::interfaces()
            .into_iter()
            .find(|i| i.is_up() && !i.is_loopback() && !i.ips.is_empty())
            .expect("No suitable network interface found")
            .name
    });

    let interfaces = datalink::interfaces();
    let iface = interfaces
        .into_iter()
        .find(|i| i.name == iface_name)
        .unwrap_or_else(|| panic!("Interface '{}' not found", iface_name));

    // Parse targets and ports
    let target_range = match parse_target(&args.target) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("[-] Target parse error: {}", e);
            std::process::exit(1);
        }
    };

    let ports = parse_ports(&args.port);
    if ports.is_empty() {
        eprintln!("[-] No valid ports specified");
        std::process::exit(1);
    }

    let src_ip = args
        .source_ip
        .as_ref()
        .map(|s| s.parse().expect("Invalid source IP"))
        .unwrap_or_else(|| {
            iface
                .ips
                .iter()
                .find_map(|ip| match ip.ip() {
                    IpAddr::V4(ip) => Some(ip),
                    _ => None,
                })
                .expect("No IPv4 address on interface")
        });

    // Calculate scan scope
    let host_count = (target_range.1 as u64) - (target_range.0 as u64) + 1;
    let total_probes = host_count * ports.len() as u64;

    eprintln!("  Target:    {}", args.target);
    eprintln!("  Ports:     {} port(s)", ports.len());
    eprintln!("  Interface: {} ({})", iface.name, src_ip);
    eprintln!("  Rate:      {} pps", if args.rate == 0 { "unlimited".into() } else { args.rate.to_string() });
    eprintln!("  Probes:    ~{}", total_probes);
    eprintln!("  Started:   {}", Utc::now().format("%Y-%m-%d %H:%M:%S UTC"));
    eprintln!();

    // Shared state
    let tx_done = Arc::new(AtomicBool::new(false));
    let sent_count = Arc::new(AtomicU64::new(0));
    let (results_tx, results_rx) = unbounded::<ScanResult>();

    // Launch TX thread
    let tx_iface = iface.clone();
    let tx_done_clone = tx_done.clone();
    let sent_count_clone = sent_count.clone();
    let randomize = args.randomize;
    let rate = args.rate;
    let verbose = args.verbose;
    let ports_clone = ports.clone();

    let tx_handle = std::thread::spawn(move || {
        tx_thread(
            tx_iface,
            target_range,
            ports_clone,
            rate,
            src_ip,
            randomize,
            tx_done_clone,
            sent_count_clone,
            verbose,
        );
    });

    // Launch RX thread
    let rx_iface = iface.clone();
    let tx_done_rx = tx_done.clone();
    let cooldown = args.cooldown;

    let rx_handle = std::thread::spawn(move || {
        rx_thread(rx_iface, src_ip, results_tx, cooldown, tx_done_rx, verbose);
    });

    // Collect results
    let mut results = Vec::new();
    while let Ok(r) = results_rx.recv() {
        if args.verbose && r.status == PortStatus::Open {
            eprintln!("[+] OPEN {}:{}", r.ip, r.port);
        }
        results.push(r);
    }

    tx_handle.join().unwrap();
    rx_handle.join().unwrap();

    // Banner grabbing phase
    if args.banner {
        let open_results: Vec<(String, u16)> = results
            .iter()
            .filter(|r| r.status == PortStatus::Open)
            .map(|r| (r.ip.clone(), r.port))
            .collect();

        if !open_results.is_empty() {
            eprintln!("\n[*] Grabbing banners from {} open port(s)...", open_results.len());
            for (i, (ip, port)) in open_results.iter().enumerate() {
                eprint!("\r[*] Banner {}/{}...", i + 1, open_results.len());
                let _ = std::io::stderr().flush();

                if let Some((banner, version, os)) = grab_banner(ip, *port, args.banner_timeout).await
                {
                    if let Some(r) = results
                        .iter_mut()
                        .find(|x| x.ip == *ip && x.port == *port)
                    {
                        r.banner = Some(banner);
                        r.version = Some(version);
                        if os.is_some() {
                            r.os_guess = os;
                        }
                    }
                }
            }
            eprintln!();
        }
    }

    // Deduplicate (prefer Open over Closed/Filtered)
    let mut unique: HashMap<(String, u16), ScanResult> = HashMap::new();
    for r in results {
        let key = (r.ip.clone(), r.port);
        match unique.get(&key) {
            Some(existing) if r.status == PortStatus::Open && existing.status != PortStatus::Open => {
                unique.insert(key, r);
            }
            None => {
                unique.insert(key, r);
            }
            _ => {}
        }
    }

    let mut final_results: Vec<_> = unique.into_values().collect();
    final_results.sort_by(|a, b| {
        a.ip.parse::<Ipv4Addr>()
            .unwrap_or(Ipv4Addr::UNSPECIFIED)
            .cmp(&b.ip.parse::<Ipv4Addr>().unwrap_or(Ipv4Addr::UNSPECIFIED))
            .then(a.port.cmp(&b.port))
    });

    // Statistics
    let open = final_results.iter().filter(|r| r.status == PortStatus::Open).count();
    let closed = final_results.iter().filter(|r| r.status == PortStatus::Closed).count();
    let filtered = final_results.iter().filter(|r| r.status == PortStatus::Filtered).count();

    eprintln!("╔══════════════════════════════════════════════════════════╗");
    eprintln!("║                    SCAN STATISTICS                      ║");
    eprintln!("╚══════════════════════════════════════════════════════════╝");
    eprintln!("  Open:     {}", open);
    eprintln!("  Closed:   {}", closed);
    eprintln!("  Filtered: {}", filtered);
    eprintln!("  Total:    {}", final_results.len());
    eprintln!();

    // Output results
    let output = format_results(&final_results, &args.format, args.info);
    if let Err(e) = write_output(&output, &args.output) {
        eprintln!("[-] Output error: {}", e);
        std::process::exit(1);
    }

    eprintln!("[+] DesertStorm complete");
}
