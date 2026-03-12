# Port Scanner

A fast multithreaded port scanner written in Python. Built for network reconnaissance and penetration testing practice. No external dependencies, just the Python standard library.

Tested against scanme.nmap.org, which is a host maintained by the Nmap project specifically for this purpose.

---

## Features

- Multithreaded scanning with up to 1000 concurrent threads
- Banner grabbing to identify what is running on each open port
- Risk assessment for each open port (critical, high, medium, low)
- Color-coded terminal output with a live progress bar
- Export results to JSON or TXT report files
- Port range presets: common (1-1024), all (1-65535), web (80-8443)
- Resolves hostnames to IP automatically
- Quiet mode for clean output or piping into other tools

---

## Requirements

Python 3.10 or higher. No third-party packages needed.

---

## Getting Started

```bash
git clone https://github.com/AnassElhamri/port-scanner.git
cd port-scanner
python port_scanner.py --help
```

---

## Usage

```bash
# Scan common ports (1-1024) on a target
python port_scanner.py scanme.nmap.org

# Scan a custom port range
python port_scanner.py scanme.nmap.org -p 1-65535

# Use a preset
python port_scanner.py scanme.nmap.org -p all

# Faster scan with more threads and lower timeout
python port_scanner.py scanme.nmap.org -p common -w 1000 -t 0.5

# Save report to JSON
python port_scanner.py scanme.nmap.org -o report.json

# Save report to text file
python port_scanner.py scanme.nmap.org -o report.txt

# Skip banner grabbing (faster)
python port_scanner.py scanme.nmap.org --no-banner

# Quiet mode, only prints open ports
python port_scanner.py scanme.nmap.org -q
```

---

## Options

| Option | Description |
|--------|-------------|
| target | Hostname or IP address to scan |
| -p, --ports | Port range: 1-1024, common, all, web (default: common) |
| -t, --timeout | Connection timeout in seconds (default: 1.0) |
| -w, --workers | Number of threads (default: 500) |
| --no-banner | Skip banner grabbing |
| -o, --output | Save report to file (.json or .txt) |
| -q, --quiet | Suppress banner and progress, print raw results |

---

## Port Range Presets

| Preset | Range | Use case |
|--------|-------|----------|
| common | 1-1024 | Standard well-known ports |
| all | 1-65535 | Full scan |
| web | 80-8443 | Web services only |

---

## Risk Levels

Each open port is assigned a risk level based on common attack vectors.

| Level | Examples |
|-------|---------|
| Critical | Telnet (23), SMB (445), RDP (3389), Metasploit (4444) |
| High | FTP (21), MS-RPC (135), MySQL (3306), Redis (6379) |
| Medium | SSH (22), SMTP (25), IMAP (143) |
| Low | HTTP (80), HTTPS (443), DNS (53) |

---

## Legal Notice

Only scan targets you own or have explicit permission to scan. The default test target scanme.nmap.org is provided by the Nmap project for exactly this purpose. Unauthorized port scanning may be illegal in your jurisdiction.

---

## License

ANASS EL HAMRI