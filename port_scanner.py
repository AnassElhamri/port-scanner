#!/usr/bin/env python3
"""
port_scanner.py — A fast multithreaded port scanner for network reconnaissance.

Usage:
    python port_scanner.py <target> [options]

Examples:
    python port_scanner.py scanme.nmap.org
    python port_scanner.py scanme.nmap.org -p 1-1024
    python port_scanner.py 192.168.1.1 -p 1-65535 -t 0.5 -w 1000
    python port_scanner.py scanme.nmap.org --no-banner -o report.json
"""

import argparse
import json
import sys
import os
import socket
import time
import threading
from datetime import datetime

from scanner import PortScanner, RISK_LEVEL

# ── Colors ────────────────────────────────────────────────────────────────────
class C:
    RESET   = "\033[0m"
    BOLD    = "\033[1m"
    DIM     = "\033[2m"
    RED     = "\033[91m"
    GREEN   = "\033[92m"
    YELLOW  = "\033[93m"
    BLUE    = "\033[94m"
    MAGENTA = "\033[95m"
    CYAN    = "\033[96m"
    WHITE   = "\033[97m"
    GRAY    = "\033[90m"
    BG_RED  = "\033[41m"
    BG_YEL  = "\033[43m"

RISK_COLOR = {
    "critical": f"{C.BOLD}{C.BG_RED}{C.WHITE}",
    "high":     f"{C.BOLD}{C.RED}",
    "medium":   f"{C.YELLOW}",
    "low":      f"{C.GREEN}",
    "info":     f"{C.CYAN}",
}

# ── Progress bar ──────────────────────────────────────────────────────────────

_progress_lock = threading.Lock()

def print_progress(scanned: int, total: int):
    pct   = scanned / total
    width = 40
    filled = int(width * pct)
    bar   = f"{C.CYAN}{'█' * filled}{C.GRAY}{'░' * (width - filled)}{C.RESET}"
    sys.stdout.write(f"\r  {bar} {C.BOLD}{pct*100:5.1f}%{C.RESET}  {C.GRAY}{scanned}/{total} ports{C.RESET}   ")
    sys.stdout.flush()

# ── Banner ────────────────────────────────────────────────────────────────────

def print_banner():
    print(f"""
{C.CYAN}{C.BOLD}
  ██████╗  ██████╗ ██████╗ ████████╗    ███████╗ ██████╗ █████╗ ███╗   ██╗
  ██╔══██╗██╔═══██╗██╔══██╗╚══██╔══╝    ██╔════╝██╔════╝██╔══██╗████╗  ██║
  ██████╔╝██║   ██║██████╔╝   ██║       ███████╗██║     ███████║██╔██╗ ██║
  ██╔═══╝ ██║   ██║██╔══██╗   ██║       ╚════██║██║     ██╔══██║██║╚██╗██║
  ██║     ╚██████╔╝██║  ██║   ██║       ███████║╚██████╗██║  ██║██║ ╚████║
  ╚═╝      ╚═════╝ ╚═╝  ╚═╝   ╚═╝       ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝
{C.RESET}{C.GRAY}  Multithreaded Network Port Scanner  |  For authorized use only{C.RESET}
""")

# ── Report helpers ────────────────────────────────────────────────────────────

def print_summary(result: dict):
    open_ports = result["open_ports"]
    risks      = {"critical": [], "high": [], "medium": [], "low": [], "info": []}
    for r in open_ports:
        risks[r.risk].append(r.port)

    print(f"\n\n  {C.BOLD}{'─'*72}{C.RESET}")
    print(f"  {C.BOLD}TARGET     {C.RESET}{C.CYAN}{result['target']}{C.RESET}  {C.GRAY}({result['resolved_ip']}){C.RESET}")
    print(f"  {C.BOLD}SCANNED    {C.RESET}{result['port_range'][0]}–{result['port_range'][1]}  {C.GRAY}({result['total_ports']} ports){C.RESET}")
    print(f"  {C.BOLD}DURATION   {C.RESET}{result['duration']}s")
    print(f"  {C.BOLD}TIMESTAMP  {C.RESET}{result['scanned_at']}")
    print(f"  {C.BOLD}{'─'*72}{C.RESET}\n")

    if not open_ports:
        print(f"  {C.YELLOW}No open ports found.{C.RESET}\n")
        return

    # Table header
    print(f"  {C.BOLD}{'PORT':<8} {'SERVICE':<22} {'RISK':<12} {'RESPONSE':<12} BANNER{C.RESET}")
    print(f"  {'─'*72}")

    for r in open_ports:
        rc      = RISK_COLOR.get(r.risk, C.GRAY)
        risk_lbl = f"{rc}{r.risk.upper():<10}{C.RESET}"
        banner  = (r.banner[:35] + "…") if len(r.banner) > 36 else r.banner
        print(f"  {C.GREEN}{r.port:<8}{C.RESET} {r.service:<22} {risk_lbl} {C.GRAY}{r.response_ms:>6}ms{C.RESET}    {C.DIM}{banner}{C.RESET}")

    # Risk summary
    print(f"\n  {C.BOLD}{'─'*72}{C.RESET}")
    print(f"  {C.BOLD}OPEN PORTS: {C.GREEN}{len(open_ports)}{C.RESET}  ", end="")
    for level in ["critical", "high", "medium", "low"]:
        if risks[level]:
            rc = RISK_COLOR[level]
            print(f" {rc}{level.upper()}: {len(risks[level])}{C.RESET}", end="")
    print(f"\n  {C.BOLD}{'─'*72}{C.RESET}\n")

    # Warnings
    if risks["critical"] or risks["high"]:
        print(f"  {C.BOLD}{C.YELLOW}Attention:{C.RESET}")
        for port in risks["critical"]:
            svc = next(r.service for r in open_ports if r.port == port)
            print(f"  {RISK_COLOR['critical']} CRITICAL {C.RESET} Port {C.BOLD}{port}{C.RESET} ({svc}) is exposed — high exploitation risk.")
        for port in risks["high"]:
            svc = next(r.service for r in open_ports if r.port == port)
            print(f"  {RISK_COLOR['high']}   HIGH    {C.RESET} Port {C.BOLD}{port}{C.RESET} ({svc}) may expose sensitive data or services.")
        print()


def save_json(result: dict, path: str):
    output = {
        "target":      result["target"],
        "resolved_ip": result["resolved_ip"],
        "port_range":  list(result["port_range"]),
        "total_ports": result["total_ports"],
        "duration":    result["duration"],
        "scanned_at":  result["scanned_at"],
        "open_ports": [
            {
                "port":        r.port,
                "service":     r.service,
                "risk":        r.risk,
                "banner":      r.banner,
                "response_ms": r.response_ms,
            }
            for r in result["open_ports"]
        ],
    }
    with open(path, "w") as f:
        json.dump(output, f, indent=2)
    print(f"  {C.GREEN}Report saved to:{C.RESET} {path}\n")


def save_txt(result: dict, path: str):
    with open(path, "w") as f:
        f.write(f"PORT SCAN REPORT\n{'='*60}\n")
        f.write(f"Target      : {result['target']} ({result['resolved_ip']})\n")
        f.write(f"Port range  : {result['port_range'][0]}-{result['port_range'][1]}\n")
        f.write(f"Total ports : {result['total_ports']}\n")
        f.write(f"Duration    : {result['duration']}s\n")
        f.write(f"Scanned at  : {result['scanned_at']}\n")
        f.write(f"{'='*60}\n\n")
        f.write(f"{'PORT':<8} {'SERVICE':<22} {'RISK':<10} {'RESPONSE':<10} BANNER\n")
        f.write(f"{'-'*72}\n")
        for r in result["open_ports"]:
            f.write(f"{r.port:<8} {r.service:<22} {r.risk:<10} {r.response_ms:>6}ms    {r.banner}\n")
    print(f"  {C.GREEN}Report saved to:{C.RESET} {path}\n")

# ── CLI ───────────────────────────────────────────────────────────────────────

def parse_port_range(value: str) -> tuple[int, int]:
    presets = {
        "common": (1, 1024),
        "all":    (1, 65535),
        "web":    (80, 8443),
    }
    if value in presets:
        return presets[value]
    if "-" in value:
        parts = value.split("-")
        return int(parts[0]), int(parts[1])
    p = int(value)
    return p, p


def main():
    parser = argparse.ArgumentParser(
        prog="port_scanner",
        description="A fast multithreaded port scanner for network reconnaissance.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Port range presets:
  common   Ports 1-1024 (default)
  all      Ports 1-65535
  web      Ports 80-8443

Examples:
  python port_scanner.py scanme.nmap.org
  python port_scanner.py scanme.nmap.org -p 1-65535
  python port_scanner.py 192.168.1.1 -p common -w 1000 -o report.json
        """
    )
    parser.add_argument("target",                    help="Target hostname or IP address")
    parser.add_argument("-p", "--ports",  default="common", help="Port range: 1-1024, common, all, web (default: common)")
    parser.add_argument("-t", "--timeout", type=float, default=1.0, help="Connection timeout in seconds (default: 1.0)")
    parser.add_argument("-w", "--workers", type=int,   default=500,  help="Number of threads (default: 500)")
    parser.add_argument("--no-banner",    action="store_true",        help="Skip banner grabbing")
    parser.add_argument("-o", "--output",                             help="Save report to file (.json or .txt)")
    parser.add_argument("-q", "--quiet",  action="store_true",        help="Suppress banner and progress bar")

    args = parser.parse_args()

    if not args.quiet:
        print_banner()

    try:
        port_range = parse_port_range(args.ports)
    except ValueError:
        print(f"{C.RED}Invalid port range: {args.ports}{C.RESET}")
        sys.exit(1)

    if not args.quiet:
        print(f"  {C.BOLD}Target   {C.RESET}: {C.CYAN}{args.target}{C.RESET}")
        print(f"  {C.BOLD}Ports    {C.RESET}: {port_range[0]}–{port_range[1]}  ({port_range[1]-port_range[0]+1} ports)")
        print(f"  {C.BOLD}Threads  {C.RESET}: {args.workers}")
        print(f"  {C.BOLD}Timeout  {C.RESET}: {args.timeout}s")
        print(f"  {C.BOLD}Banners  {C.RESET}: {'no' if args.no_banner else 'yes'}")
        print(f"\n  {C.GRAY}Resolving target...{C.RESET}")

    try:
        scanner = PortScanner(
            target        = args.target,
            port_range    = port_range,
            timeout       = args.timeout,
            max_workers   = args.workers,
            grab_banner   = not args.no_banner,
            progress_callback = (None if args.quiet else print_progress),
        )
        result = scanner.run()
    except socket.gaierror:
        print(f"\n  {C.RED}Could not resolve host: {args.target}{C.RESET}\n")
        sys.exit(1)
    except KeyboardInterrupt:
        print(f"\n\n  {C.YELLOW}Scan cancelled.{C.RESET}\n")
        sys.exit(0)

    if not args.quiet:
        print_summary(result)

    if args.output:
        if args.output.endswith(".json"):
            save_json(result, args.output)
        else:
            save_txt(result, args.output)
    elif args.quiet:
        for r in result["open_ports"]:
            print(f"{r.port}\t{r.service}\t{r.risk}\t{r.response_ms}ms")


if __name__ == "__main__":
    main()