#!/usr/bin/env python3
"""
Port Scanner Engine - Core scanning logic
"""

import socket
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from typing import Callable

# ── Well-known service map ────────────────────────────────────────────────────
SERVICES = {
    20: "FTP (Data)",        21: "FTP (Control)",     22: "SSH",
    23: "Telnet",            25: "SMTP",               53: "DNS",
    67: "DHCP (Server)",     68: "DHCP (Client)",      69: "TFTP",
    80: "HTTP",              110: "POP3",              119: "NNTP",
    123: "NTP",              135: "MS-RPC",            137: "NetBIOS-NS",
    138: "NetBIOS-DGM",      139: "NetBIOS-SSN",       143: "IMAP",
    161: "SNMP",             194: "IRC",               389: "LDAP",
    443: "HTTPS",            445: "SMB",               465: "SMTPS",
    514: "Syslog",           515: "LPD/LPR",           587: "SMTP (Submit)",
    631: "IPP",              636: "LDAPS",             993: "IMAPS",
    995: "POP3S",            1080: "SOCKS Proxy",      1194: "OpenVPN",
    1433: "MSSQL",           1521: "Oracle DB",        1723: "PPTP",
    2049: "NFS",             2082: "cPanel",           2083: "cPanel SSL",
    2222: "SSH (alt)",       3000: "Dev Server",       3306: "MySQL",
    3389: "RDP",             4444: "Metasploit",       5432: "PostgreSQL",
    5900: "VNC",             5985: "WinRM (HTTP)",     5986: "WinRM (HTTPS)",
    6379: "Redis",           6667: "IRC",              7070: "RealAudio",
    8080: "HTTP Proxy",      8443: "HTTPS (alt)",      8888: "HTTP (alt)",
    9200: "Elasticsearch",   9300: "Elasticsearch",    27017: "MongoDB",
}

RISK_LEVEL = {
    21: "high", 22: "medium", 23: "critical", 25: "medium",
    53: "low",  80: "low",    110: "medium",  135: "high",
    137: "high", 138: "high", 139: "high",    143: "medium",
    389: "high", 443: "low",  445: "critical", 514: "high",
    1433: "high", 1521: "high", 3306: "high",  3389: "critical",
    4444: "critical", 5432: "high", 5900: "high", 6379: "high",
    27017: "high",
}

# ── Scanner ───────────────────────────────────────────────────────────────────

class ScanResult:
    def __init__(self, port: int, open: bool, service: str, banner: str, response_ms: float):
        self.port        = port
        self.open        = open
        self.service     = service
        self.banner      = banner
        self.response_ms = response_ms
        self.risk        = RISK_LEVEL.get(port, "info") if open else "none"


class PortScanner:
    def __init__(self, target: str, port_range: tuple[int, int],
                 timeout: float = 1.0, max_workers: int = 500,
                 grab_banner: bool = True,
                 progress_callback: Callable[[int, int], None] = None):
        self.target            = target
        self.port_range        = port_range
        self.timeout           = timeout
        self.max_workers       = max_workers
        self.grab_banner       = grab_banner
        self.progress_callback = progress_callback
        self._lock             = threading.Lock()
        self._scanned          = 0

    def resolve(self) -> str:
        return socket.gethostbyname(self.target)

    def _scan_port(self, port: int) -> ScanResult:
        try:
            start = datetime.now()
            sock  = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            result = sock.connect_ex((self.resolved_ip, port))
            elapsed = (datetime.now() - start).total_seconds() * 1000

            if result == 0:
                banner = ""
                if self.grab_banner:
                    try:
                        sock.settimeout(0.5)
                        sock.send(b"HEAD / HTTP/1.0\r\n\r\n")
                        raw = sock.recv(256).decode("utf-8", errors="ignore").strip()
                        banner = raw.split("\n")[0][:80] if raw else ""
                    except Exception:
                        pass
                sock.close()
                service = SERVICES.get(port, socket.getservbyport(port, "tcp") if self._try_getservice(port) else "unknown")
                res = ScanResult(port, True, service, banner, round(elapsed, 2))
            else:
                sock.close()
                res = ScanResult(port, False, "", "", 0)

        except Exception:
            res = ScanResult(port, False, "", "", 0)

        with self._lock:
            self._scanned += 1
            if self.progress_callback:
                self.progress_callback(self._scanned, self.total_ports)

        return res

    def _try_getservice(self, port: int) -> bool:
        try:
            socket.getservbyport(port, "tcp")
            return True
        except Exception:
            return False

    def run(self) -> dict:
        self.resolved_ip  = self.resolve()
        ports             = list(range(self.port_range[0], self.port_range[1] + 1))
        self.total_ports  = len(ports)
        self._scanned     = 0
        start_time        = datetime.now()
        open_ports        = []

        with ThreadPoolExecutor(max_workers=min(self.max_workers, self.total_ports)) as ex:
            futures = {ex.submit(self._scan_port, p): p for p in ports}
            for future in as_completed(futures):
                result = future.result()
                if result.open:
                    open_ports.append(result)

        open_ports.sort(key=lambda r: r.port)
        duration = (datetime.now() - start_time).total_seconds()

        return {
            "target":      self.target,
            "resolved_ip": self.resolved_ip,
            "port_range":  self.port_range,
            "total_ports": self.total_ports,
            "open_ports":  open_ports,
            "duration":    round(duration, 2),
            "scanned_at":  datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        }