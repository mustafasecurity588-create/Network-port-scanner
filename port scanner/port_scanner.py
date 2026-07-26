import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import socket
import threading
import time
import os
import sys
import re
import csv
import json
import struct
import select
import queue
import webbrowser
import subprocess
import ipaddress
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed

DEPS: dict[str, bool] = {}

try:
    import requests as _req
    DEPS["requests"] = True
except ImportError:
    DEPS["requests"] = False

try:
    import whois as _whois_lib
    DEPS["whois"] = True
except ImportError:
    DEPS["whois"] = False

try:
    from reportlab.lib.pagesizes import A4
    from reportlab.lib import colors as rl_colors
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.units import cm
    from reportlab.lib.enums import TA_CENTER
    from reportlab.platypus import (
        SimpleDocTemplate, Table, TableStyle,
        Paragraph, Spacer, HRFlowable,
    )
    DEPS["reportlab"] = True
except ImportError:
    DEPS["reportlab"] = False

try:
    import scapy.all as _scapy
    DEPS["scapy"] = True
except Exception:
    DEPS["scapy"] = False

SERVICE_MAP: dict[int, str] = {
    20: "FTP-Data",
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    37: "Time",
    53: "DNS",
    67: "DHCP",
    68: "DHCP",
    69: "TFTP",
    79: "Finger",
    80: "HTTP",
    88: "Kerberos",
    110: "POP3",
    111: "RPCBind",
    119: "NNTP",
    123: "NTP",
    135: "MSRPC",
    137: "NetBIOS-NS",
    138: "NetBIOS-DGM",
    139: "NetBIOS-SSN",
    143: "IMAP",
    161: "SNMP",
    162: "SNMP-Trap",
    179: "BGP",
    194: "IRC",
    389: "LDAP",
    443: "HTTPS",
    445: "SMB",
    465: "SMTPS",
    500: "IPSec",
    514: "Syslog",
    515: "LPD",
    520: "RIP",
    543: "Klogin",
    544: "Kshell",
    587: "SMTP-Submit",
    631: "IPP",
    636: "LDAPS",
    902: "VMware",
    993: "IMAPS",
    995: "POP3S",
    1080: "SOCKS",
    1194: "OpenVPN",
    1433: "MSSQL",
    1521: "Oracle-DB",
    1723: "PPTP",
    2049: "NFS",
    2181: "Zookeeper",
    2375: "Docker",
    2376: "Docker-TLS",
    3000: "HTTP-Alt",
    3306: "MySQL",
    3389: "RDP",
    3690: "SVN",
    4000: "HTTP-Alt",
    4444: "MSF/NC",
    4500: "IPSec-NAT",
    5000: "Flask/UPnP",
    5432: "PostgreSQL",
    5601: "Kibana",
    5900: "VNC",
    5985: "WinRM-HTTP",
    5986: "WinRM-HTTPS",
    6379: "Redis",
    6443: "K8s-API",
    7001: "WebLogic",
    7180: "Cloudera",
    8080: "HTTP-Proxy",
    8443: "HTTPS-Alt",
    8888: "Jupyter",
    9000: "SonarQube",
    9092: "Kafka",
    9200: "Elasticsearch",
    9300: "ES-Cluster",
    10250: "kubelet",
    11211: "Memcached",
    27017: "MongoDB",
    27018: "MongoDB",
    50000: "SAP",
}

HIGH_RISK = {
    23,
    21,
    135,
    137,
    138,
    139,
    445,
    1433,
    3389,
    4444,
    5900,
    6379,
    11211,
    27017,
}
MEDIUM_RISK = {
    22,
    25,
    80,
    110,
    143,
    389,
    636,
    2375,
    3306,
    5432,
    8080,
    9200,
}

QUICK_PORTS = sorted({
    20,
    21,
    22,
    23,
    25,
    37,
    53,
    67,
    69,
    79,
    80,
    88,
    110,
    111,
    123,
    135,
    137,
    138,
    139,
    143,
    161,
    179,
    194,
    389,
    443,
    445,
    465,
    500,
    514,
    515,
    520,
    587,
    631,
    636,
    902,
    993,
    995,
    1080,
    1194,
    1433,
    1521,
    1723,
    2049,
    2375,
    3000,
    3306,
    3389,
    3690,
    4444,
    5000,
    5432,
    5601,
    5900,
    5985,
    6379,
    6443,
    7001,
    8080,
    8443,
    8888,
    9000,
    9200,
    9300,
    10250,
    11211,
    27017,
    50000,
})

OS_TTL_RANGES = {
    (59, 70): "Linux / Android (TTL≈64)",
    (110, 130): "Windows (TTL≈128)",
    (250, 256): "Cisco / Solaris (TTL≈255)",
    (28, 34): "Network Device (TTL≈32)",
}

class ScanResult:
    __slots__ = (
        "port", "protocol", "status", "service",
        "banner", "version", "risk", "timestamp",
    )

    def __init__(
        self,
        port: int,
        protocol: str,
        status: str,
        service: str = "",
        banner: str = "",
        version: str = "",
    ):
        self.port = port
        self.protocol = protocol
        self.status = status
        self.service = service
        self.banner = banner
        self.version = version
        self.risk = self._risk()
        self.timestamp = datetime.now()

    def _risk(self) -> str:
        if self.status != "open":
            return "INFO"
        if self.port in HIGH_RISK:
            return "HIGH"
        if self.port in MEDIUM_RISK:
            return "MEDIUM"
        return "LOW"

class NetworkScanner:
    def __init__(
        self,
        target,
        ports,
        timeout=1.0,
        retries=1,
        grab_banners=True,
        scan_udp=False,
        scan_mode="full",
        max_threads=100,
        callback=None,
        progress_cb=None,
        log_cb=None,
    ):
        self.target = target
        self.ports = ports
        self.timeout = timeout
        self.retries = retries
        self.grab_banners = grab_banners
        self.scan_udp = scan_udp
        self.scan_mode = scan_mode
        self.max_threads = max_threads
        self.callback = callback
        self.progress_cb = progress_cb
        self.log_cb = log_cb
        self.results: list[ScanResult] = []
        self.stop_event = threading.Event()
        self.target_ip: str | None = None
        self.os_info = "Unknown"

    def _log(self, msg: str):
        if self.log_cb:
            self.log_cb(msg)

    def resolve(self) -> bool:
        try:
            self.target_ip = socket.gethostbyname(self.target)
            self._log(f"[*] Resolved  {self.target} → {self.target_ip}")
            return True
        except socket.gaierror as e:
            self._log(f"[!] Cannot resolve {self.target}: {e}")
            return False

    def _grab_banner(self, sock: socket.socket, port: int) -> tuple[str, str]:
        banner, version = "", ""
        try:
            sock.settimeout(min(self.timeout * 2, 3))
            if port in (21, 22, 25, 110, 119, 143, 194, 515):
                raw = sock.recv(1024)
                banner = raw.decode("utf-8", errors="replace").strip()
            elif port in (80, 8080, 8000, 3000, 4000, 5000, 8888, 8181):
                probe = (f"GET / HTTP/1.1\r\nHost: {self.target}\r\n"
                         "User-Agent: NetScanPro/1.0\r\nConnection: close\r\n\r\n")
                sock.sendall(probe.encode())
                raw = b""
                while len(raw) < 4096:
                    chunk = sock.recv(2048)
                    if not chunk:
                        break
                    raw += chunk
                text = raw.decode("utf-8", errors="replace")
                header_part = text.split("\r\n\r\n")[0]
                banner = header_part[:500]
                m = re.search(r"[Ss]erver:\s*(.+)", banner)
                if m:
                    version = m.group(1).strip()[:80]
            else:
                sock.sendall(b"\r\n")
                raw = sock.recv(1024)
                banner = raw.decode("utf-8", errors="replace").strip()
        except Exception:
            pass

        if not version and banner:
            version = self._extract_version(banner)
        return banner[:600], version[:100]

    @staticmethod
    def _extract_version(banner: str) -> str:
        patterns = [
            r"OpenSSH[_\s/]([\d\.p\w-]+)",
            r"Apache[/\s]([\d\.]+)",
            r"nginx[/\s]([\d\.]+)",
            r"vsftpd\s([\d\.]+)",
            r"ProFTPD[/\s]([\d\.]+)",
            r"Microsoft-IIS[/\s]([\d\.]+)",
            r"Postfix\s+([A-Za-z\d\._-]+)",
            r"Dovecot[/\s]([\d\.]+)",
            r"MySQL[/\s]([\d\.]+)",
            r"MariaDB[/\s]([\d\.]+)",
        ]
        for p in patterns:
            m = re.search(p, banner, re.IGNORECASE)
            if m:
                return m.group(0)[:60]
        return ""

    def _tcp_scan(self, port: int) -> ScanResult:
        svc = SERVICE_MAP.get(port, "unknown")
        for attempt in range(self.retries + 1):
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(self.timeout)
                rc = sock.connect_ex((self.target_ip, port))
                if rc == 0:
                    banner, version = ("", "")
                    if self.grab_banners:
                        banner, version = self._grab_banner(sock, port)
                    sock.close()
                    return ScanResult(port, "TCP", "open", svc,
                                      banner, version)
                sock.close()
                if rc in (111, 10061, 61):
                    return ScanResult(port, "TCP", "closed", svc)
                return ScanResult(port, "TCP", "filtered", svc)
            except socket.timeout:
                if attempt == self.retries:
                    return ScanResult(port, "TCP", "filtered", svc)
            except OSError:
                if attempt == self.retries:
                    return ScanResult(port, "TCP", "closed", svc)
        return ScanResult(port, "TCP", "unknown", svc)

    def _udp_scan(self, port: int) -> ScanResult | None:
        svc = SERVICE_MAP.get(port, "unknown")
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(self.timeout)
            sock.sendto(b"\x00" * 8, (self.target_ip, port))
            try:
                data, _ = sock.recvfrom(1024)
                banner = data.decode("utf-8", errors="replace").strip()[:200]
                sock.close()
                return ScanResult(port, "UDP", "open", svc, banner)
            except socket.timeout:
                sock.close()
                return ScanResult(port, "UDP", "open|filtered", svc)
        except Exception:
            return None

    def _syn_scan(self, port: int) -> ScanResult:
        if not DEPS["scapy"]:
            return self._tcp_scan(port)
        try:
            scapy = _scapy
            ip_pkt  = scapy.IP(dst=self.target_ip)
            tcp_pkt = scapy.TCP(dport=port, flags="S",
                                seq=int(time.time()) & 0xFFFFFFFF)
            resp = scapy.sr1(ip_pkt / tcp_pkt,
                             timeout=self.timeout, verbose=0)
            svc = SERVICE_MAP.get(port, "unknown")
            if resp is None:
                return ScanResult(port, "TCP-SYN", "filtered", svc)
            if resp.haslayer(scapy.TCP):
                flags = resp[scapy.TCP].flags
                if flags == 0x12:   
                    rst = ip_pkt / scapy.TCP(
                        dport=port, flags="R",
                        seq=resp[scapy.TCP].ack)
                    scapy.send(rst, verbose=0)
                    return ScanResult(port, "TCP-SYN", "open", svc)
                if flags & 0x04:    
                    return ScanResult(port, "TCP-SYN", "closed", svc)
            return ScanResult(port, "TCP-SYN", "filtered", svc)
        except Exception:
            return self._tcp_scan(port)

    def fingerprint_os(self) -> str:
        if DEPS["scapy"]:
            try:
                scapy = _scapy
                pkt  = scapy.IP(dst=self.target_ip) / scapy.ICMP()
                resp = scapy.sr1(pkt, timeout=2, verbose=0)
                if resp and hasattr(resp, "ttl"):
                    ttl = resp.ttl
                    for (lo, hi), name in OS_TTL_RANGES.items():
                        if lo <= ttl <= hi:
                            self.os_info = name
                            return name
                    self.os_info = f"Unknown (ICMP TTL={ttl})"
                    return self.os_info
            except Exception:
                pass

        try:
            cmd = (["ping", "-n", "1", "-w", "2000", self.target_ip]
                   if sys.platform == "win32"
                   else ["ping", "-c", "1", "-W", "2", self.target_ip])
            out = subprocess.run(cmd, capture_output=True,
                                 text=True, timeout=5).stdout
            m = re.search(r"[Tt][Tt][Ll]=(\d+)", out)
            if m:
                ttl = int(m.group(1))
                for (lo, hi), name in OS_TTL_RANGES.items():
                    if lo <= ttl <= hi:
                        self.os_info = name
                        return name
                self.os_info = f"Unknown (Ping TTL={ttl})"
                return self.os_info
        except Exception:
            pass

        known_windows_services = {"MSRPC", "SMB", "NetBIOS-SSN", "WinRM-HTTP"}
        known_linux_services   = {"SSH", "NFS", "Syslog"}
        for r in self.results:
            if r.service in known_windows_services and r.status == "open":
                self.os_info = "Likely Windows (service profile)"
                return self.os_info
            if r.service in known_linux_services and r.status == "open":
                if "ubuntu" in r.banner.lower() or "debian" in r.banner.lower():
                    self.os_info = "Linux — Debian/Ubuntu (banner)"
                    return self.os_info
                if r.service == "SSH":
                    self.os_info = "Likely Linux/Unix (SSH open)"
                    return self.os_info

        self.os_info = "Could not determine"
        return self.os_info

    def scan(self) -> list[ScanResult]:
        if not self.resolve():
            return []

        total = len(self.ports)
        self._log(f"[*] Scan mode  : {self.scan_mode.upper()}")
        self._log(f"[*] Ports      : {total}")
        self._log(f"[*] Timeout    : {self.timeout}s | Retries: {self.retries}")
        self._log(f"[*] Threads    : {self.max_threads}")
        self._log(f"[*] Banners    : {'ON' if self.grab_banners else 'OFF'} | "
                  f"UDP: {'ON' if self.scan_udp else 'OFF'}")
        self._log("─" * 52)

        scanned = 0

        def _scan_port(port: int):
            if self.stop_event.is_set():
                return None
            if self.scan_mode == "stealth":
                result = self._syn_scan(port)
            else:
                result = self._tcp_scan(port)
            if self.scan_udp and not self.stop_event.is_set():
                udp = self._udp_scan(port)
                if udp and udp.status in ("open", "open|filtered"):
                    self.results.append(udp)
                    if self.callback:
                        self.callback(udp)
            return result

        t0 = time.time()
        with ThreadPoolExecutor(max_workers=self.max_threads) as ex:
            futs = {ex.submit(_scan_port, p): p for p in self.ports}
            for fut in as_completed(futs):
                if self.stop_event.is_set():
                    break
                scanned += 1
                r = fut.result()
                if r:
                    self.results.append(r)
                    if r.status in ("open", "open|filtered"):
                        banner_hint = (f"  banner: {r.banner[:70].replace(chr(10),' ')}"
                                      if r.banner else "")
                        self._log(f"[+] {r.port:5}/TCP  OPEN  {r.service}"
                                  + (f"  [{r.version}]" if r.version else "")
                                  + ("\n" + banner_hint if banner_hint else ""))
                    if self.callback:
                        self.callback(r)
                if self.progress_cb:
                    self.progress_cb(scanned, total)

        elapsed = time.time() - t0
        open_n  = sum(1 for r in self.results if r.status == "open")
        self._log("─" * 52)
        self._log(f"[*] Completed in {elapsed:.2f}s  —  {open_n} open port(s)")

        self._log("[*] Fingerprinting OS…")
        self._log(f"[*] OS Guess  : {self.fingerprint_os()}")

        return self.results

def whois_lookup(target: str) -> dict:
    if DEPS["whois"]:
        try:
            w = _whois_lib.whois(target)
            return {
                "registrar":        str(getattr(w, "registrar", "") or ""),
                "creation_date":    str(getattr(w, "creation_date", "") or ""),
                "expiration_date":  str(getattr(w, "expiration_date", "") or ""),
                "name_servers":     str(getattr(w, "name_servers", "") or ""),
                "emails":           str(getattr(w, "emails", "") or ""),
                "org":              str(getattr(w, "org", "") or ""),
                "country":          str(getattr(w, "country", "") or ""),
                "raw":              str(w),
            }
        except Exception as e:
            pass

    try:
        try:
            ipaddress.ip_address(target)
            server = "whois.arin.net"
        except ValueError:
            tld = target.rsplit(".", 1)[-1].lower()
            server = f"whois.nic.{tld}"

        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(10)
        sock.connect((server, 43))
        sock.sendall(f"{target}\r\n".encode())
        data = b""
        while True:
            chunk = sock.recv(4096)
            if not chunk:
                break
            data += chunk
        sock.close()
        raw = data.decode("utf-8", errors="replace")
        result: dict = {"raw": raw}
        for line in raw.splitlines():
            if ":" in line:
                k, _, v = line.partition(":")
                k, v = k.strip().lower(), v.strip()
                if "registrar" in k and "registrar" not in result:
                    result["registrar"] = v
                elif "creat" in k and "creation_date" not in result:
                    result["creation_date"] = v
                elif "expir" in k and "expiration_date" not in result:
                    result["expiration_date"] = v
                elif "name server" in k and "name_servers" not in result:
                    result["name_servers"] = v
                elif k == "org" and "org" not in result:
                    result["org"] = v
        return result
    except Exception as e:
        return {"error": str(e), "raw": ""}

def geoip_lookup(ip: str) -> dict:
    url = f"http://ip-api.com/json/{ip}?fields=66846719"
    if DEPS["requests"]:
        try:
            r = _req.get(url, timeout=8)
            return r.json()
        except Exception as e:
            return {"error": str(e)}
    try:
        import urllib.request
        with urllib.request.urlopen(url, timeout=8) as resp:
            return json.loads(resp.read().decode())
    except Exception as e:
        return {"error": str(e)}

def export_pdf(path: str, target: str, target_ip: str,
               results: list[ScanResult], os_info: str,
               geo: dict, whois_data: dict,
               scan_info: dict) -> tuple[bool, str]:
    if not DEPS["reportlab"]:
        return False, "ReportLab not installed"
    try:
        doc = SimpleDocTemplate(path, pagesize=A4,
                                rightMargin=2*cm, leftMargin=2*cm,
                                topMargin=2*cm, bottomMargin=2*cm)
        styles  = getSampleStyleSheet()
        NAVY    = rl_colors.HexColor("#0f3460")
        ACCENT  = rl_colors.HexColor("#58a6ff")
        GREEN   = rl_colors.HexColor("#2da44e")
        ORANGE  = rl_colors.HexColor("#e65100")
        RED_C   = rl_colors.HexColor("#c62828")
        LIGHT   = rl_colors.HexColor("#f6f8fa")
        DIM     = rl_colors.HexColor("#555555")

        title_sty = ParagraphStyle("T", parent=styles["Title"],
                                   fontSize=22, textColor=NAVY,
                                   spaceAfter=4, alignment=TA_CENTER)
        sub_sty   = ParagraphStyle("S", parent=styles["Normal"],
                                   fontSize=10, textColor=DIM,
                                   spaceAfter=14, alignment=TA_CENTER)
        sec_sty   = ParagraphStyle("H", parent=styles["Heading2"],
                                   fontSize=13, textColor=NAVY,
                                   spaceBefore=14, spaceAfter=6)
        norm_sty  = ParagraphStyle("N", parent=styles["Normal"],
                                   fontSize=9, textColor=rl_colors.black)
        code_sty  = ParagraphStyle("C", parent=styles["Code"],
                                   fontSize=7, fontName="Courier",
                                   textColor=DIM, leading=10)

        elems = []
        elems.append(Paragraph("NetScan Pro — Scan Report", title_sty))
        ts = datetime.now().strftime("%Y-%m-%d  %H:%M:%S")
        elems.append(Paragraph(f"Generated: {ts}", sub_sty))
        elems.append(HRFlowable(width="100%", thickness=2, color=NAVY))
        elems.append(Spacer(1, 0.4*cm))

        open_r  = [r for r in results if r.status == "open"]
        filt_r  = [r for r in results if r.status == "filtered"]
        elems.append(Paragraph("Scan Summary", sec_sty))

        summary_rows = [
            ["Target",              target],
            ["IP Address",          target_ip or "N/A"],
            ["OS Fingerprint",      os_info],
            ["Scan Mode",           scan_info.get("mode","").upper()],
            ["Ports Scanned",       str(scan_info.get("total","0"))],
            ["Open Ports",          str(len(open_r))],
            ["Filtered Ports",      str(len(filt_r))],
            ["Duration",            scan_info.get("duration","N/A")],
            ["Report Date",         ts],
        ]
        st = _pdf_table(summary_rows, [4.5*cm, 11.5*cm], LIGHT, NAVY)
        elems.append(st); elems.append(Spacer(1, 0.4*cm))

        if open_r:
            elems.append(Paragraph(f"Open Ports  ({len(open_r)} found)", sec_sty))
            hdr = [["Port","Proto","Service","Status","Risk","Version / Banner"]]
            rows = []
            for r in sorted(open_r, key=lambda x: x.port):
                hint = r.version or (r.banner.replace("\n"," ")[:60] if r.banner else "")
                rows.append([str(r.port), r.protocol, r.service or "unknown",
                             r.status, r.risk, hint[:60]])
            table_data = hdr + rows
            cw = [1.5*cm, 2*cm, 3.5*cm, 2*cm, 2*cm, 5*cm]
            tbl = Table(table_data, colWidths=cw)
            ts_style = [
                ("BACKGROUND",  (0,0), (-1,0), NAVY),
                ("TEXTCOLOR",   (0,0), (-1,0), rl_colors.white),
                ("FONTNAME",    (0,0), (-1,0), "Helvetica-Bold"),
                ("FONTSIZE",    (0,0), (-1,-1), 8),
                ("GRID",        (0,0), (-1,-1), 0.4, rl_colors.HexColor("#cccccc")),
                ("VALIGN",      (0,0), (-1,-1), "MIDDLE"),
                ("LEFTPADDING", (0,0), (-1,-1), 5),
                ("RIGHTPADDING",(0,0), (-1,-1), 5),
                ("TOPPADDING",  (0,0), (-1,-1), 3),
                ("BOTTOMPADDING",(0,0), (-1,-1), 3),
            ]
            for i, row in enumerate(rows, 1):
                bg = LIGHT if i % 2 else rl_colors.white
                ts_style.append(("BACKGROUND", (0,i), (-1,i), bg))
                risk = row[4]
                col  = (RED_C if risk=="HIGH" else
                        ORANGE if risk=="MEDIUM" else
                        GREEN)
                ts_style.append(("TEXTCOLOR", (4,i), (4,i), col))
                ts_style.append(("FONTNAME",  (4,i), (4,i), "Helvetica-Bold"))
            tbl.setStyle(TableStyle(ts_style))
            elems.append(tbl); elems.append(Spacer(1, 0.4*cm))

        if geo and geo.get("status") == "success":
            elems.append(Paragraph("Geographic & Network Information", sec_sty))
            fields = [
                ("Country",      "country"), ("Region",   "regionName"),
                ("City",         "city"),    ("ZIP",      "zip"),
                ("Latitude",     "lat"),     ("Longitude","lon"),
                ("ISP",          "isp"),     ("Org",      "org"),
                ("AS",           "as"),      ("Timezone", "timezone"),
                ("Proxy/VPN",    "proxy"),   ("Hosting",  "hosting"),
            ]
            geo_rows = [[lbl, str(geo[k])]
                        for lbl, k in fields if k in geo and geo[k] not in ("", None, False)]
            if geo_rows:
                elems.append(_pdf_table(geo_rows, [4.5*cm, 11.5*cm], LIGHT, NAVY))
                elems.append(Spacer(1, 0.4*cm))

        raw_whois = whois_data.get("raw", "")
        if raw_whois:
            elems.append(Paragraph("WHOIS Information", sec_sty))
            safe = raw_whois[:3000].replace("&","&amp;").replace("<","&lt;")
            elems.append(Paragraph(safe.replace("\n","<br/>"), code_sty))

        doc.build(elems)
        return True, path
    except Exception as e:
        return False, str(e)

def _pdf_table(rows, col_widths, bg_color, header_color):
    tbl = Table(rows, colWidths=col_widths)
    tbl.setStyle(TableStyle([
        ("BACKGROUND",   (0,0), (0,-1), bg_color),
        ("FONTNAME",     (0,0), (0,-1), "Helvetica-Bold"),
        ("FONTSIZE",     (0,0), (-1,-1), 9),
        ("GRID",         (0,0), (-1,-1), 0.4, rl_colors.HexColor("#cccccc")),
        ("ROWBACKGROUNDS",(0,0), (-1,-1),
         [rl_colors.white, rl_colors.HexColor("#f6f8fa")]),
        ("LEFTPADDING",  (0,0), (-1,-1), 7),
        ("RIGHTPADDING", (0,0), (-1,-1), 7),
        ("TOPPADDING",   (0,0), (-1,-1), 4),
        ("BOTTOMPADDING",(0,0), (-1,-1), 4),
    ]))
    return tbl

def parse_ports(s: str) -> list[int]:
    ports: set[int] = set()
    for part in s.split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            lo, _, hi = part.partition("-")
            ports.update(range(max(1, int(lo)), min(65535, int(hi)) + 1))
        else:
            n = int(part)
            if 1 <= n <= 65535:
                ports.add(n)
    return sorted(ports)

class NetScanGUI:
    BG     = "#0d1117"
    BG2    = "#161b22"
    BG3    = "#21262d"
    BORDER = "#30363d"
    TEXT   = "#e6edf3"
    DIM    = "#8b949e"
    ACCENT = "#58a6ff"
    ACC2   = "#1f6feb"
    GREEN  = "#3fb950"
    RED    = "#f85149"
    YELLOW = "#d29922"
    ORANGE = "#db6d28"
    CYAN   = "#39d353"
    PURPLE = "#bc8cff"

    def __init__(self, root: tk.Tk):
        self.root = root
        self.root.title("NetScan Pro — Advanced Port Scanner")
        self.root.geometry("1260x820")
        self.root.minsize(1050, 700)
        self.root.configure(bg=self.BG)

        self.scanner: NetworkScanner | None = None
        self.scan_thread: threading.Thread | None = None
        self.all_results: list[ScanResult] = []
        self.geo_data:   dict = {}
        self.whois_data: dict = {}
        self.t_start: float | None = None
        self.rq: queue.Queue = queue.Queue()
        self.lq: queue.Queue = queue.Queue()
        self._sort_rev: dict[str, bool] = {}

        self._styles()
        self._build()
        self._poll()

    def _styles(self):
        s = ttk.Style(); s.theme_use("clam")

        s.configure("Dark.TNotebook", background=self.BG, borderwidth=0)
        s.configure("Dark.TNotebook.Tab",
                    background=self.BG3, foreground=self.DIM,
                    padding=[18, 9], font=("Segoe UI", 10))
        s.map("Dark.TNotebook.Tab",
              background=[("selected", self.BG2)],
              foreground=[("selected", self.ACCENT)])

        s.configure("Results.Treeview",
                    background=self.BG2, foreground=self.TEXT,
                    fieldbackground=self.BG2, rowheight=26,
                    borderwidth=0, font=("Consolas", 9))
        s.configure("Results.Treeview.Heading",
                    background=self.BG3, foreground=self.ACCENT,
                    font=("Segoe UI", 9, "bold"), relief="flat")
        s.map("Results.Treeview",
              background=[("selected", self.ACC2)],
              foreground=[("selected", "white")])

        s.configure("H.Horizontal.TProgressbar",
                    background=self.ACCENT, troughcolor=self.BG3,
                    borderwidth=0, thickness=5)

    def _build(self):
        self._header()
        tk.Frame(self.root, height=1, bg=self.BORDER).pack(fill="x")
        body = tk.Frame(self.root, bg=self.BG)
        body.pack(fill="both", expand=True, padx=20, pady=14)
        left = tk.Frame(body, bg=self.BG, width=310)
        left.pack(side="left", fill="y", padx=(0, 14))
        left.pack_propagate(False)
        self._left_panel(left)
        right = tk.Frame(body, bg=self.BG)
        right.pack(side="left", fill="both", expand=True)
        self._right_panel(right)
        self._statusbar()

    def _header(self):
        h = tk.Frame(self.root, bg=self.BG, pady=14)
        h.pack(fill="x", padx=20)

        lf = tk.Frame(h, bg=self.BG)
        lf.pack(side="left")
        tk.Label(lf, text="🔍", font=("Segoe UI", 22),
                 bg=self.BG, fg=self.ACCENT).pack(side="left", padx=(0,8))
        tf = tk.Frame(lf, bg=self.BG)
        tf.pack(side="left")
        tk.Label(tf, text="NetScan Pro",
                 font=("Segoe UI", 21, "bold"),
                 bg=self.BG, fg=self.TEXT).pack(anchor="w")
        tk.Label(tf, text="Advanced Network Port Scanner",
                 font=("Segoe UI", 9),
                 bg=self.BG, fg=self.DIM).pack(anchor="w")

        bf = tk.Frame(h, bg=self.BG)
        bf.pack(side="right")
        for label, key in [("Scapy","scapy"),("ReportLab","reportlab"),
                           ("Whois","whois"),("Requests","requests")]:
            ok = DEPS.get(key, False)
            tk.Label(bf, text=("✓ " if ok else "✗ ") + label,
                     font=("Segoe UI", 8, "bold"),
                     bg=self.BG3,
                     fg=self.GREEN if ok else self.RED,
                     padx=7, pady=3).pack(side="left", padx=2)

    def _left_panel(self, parent):
        canvas  = tk.Canvas(parent, bg=self.BG, highlightthickness=0)
        vsb     = ttk.Scrollbar(parent, orient="vertical", command=canvas.yview)
        frame   = tk.Frame(canvas, bg=self.BG)
        frame.bind("<Configure>",
                   lambda e: canvas.configure(
                       scrollregion=canvas.bbox("all")))
        canvas.create_window((0,0), window=frame, anchor="nw")
        canvas.configure(yscrollcommand=vsb.set)
        canvas.pack(side="left", fill="both", expand=True)
        vsb.pack(side="right", fill="y")
        canvas.bind("<MouseWheel>",
                    lambda e: canvas.yview_scroll(-1*(e.delta//120), "units"))

        c = self._card(frame, "🎯 Target")
        self._lbl(c, "Host / IP")
        self.v_target = tk.StringVar(value="scanme.nmap.org")
        self._entry(c, self.v_target)

        c = self._card(frame, "🔌 Ports")
        self._lbl(c, "Scan Mode")
        mf = tk.Frame(c, bg=self.BG2); mf.pack(fill="x", pady=(4,8))
        self.v_mode = tk.StringVar(value="quick")
        for txt, val in [("⚡ Quick","quick"),("🔍 Full","full"),("🥷 Stealth","stealth")]:
            tk.Radiobutton(mf, text=txt, value=val, variable=self.v_mode,
                           command=self._on_mode,
                           bg=self.BG2, fg=self.TEXT, selectcolor=self.BG3,
                           activebackground=self.BG2, activeforeground=self.ACCENT,
                           font=("Segoe UI",9)).pack(side="left", padx=(0,6))

        self._lbl(c, "Port Range  (e.g. 22,80,443,8000-9000)")
        self.v_ports = tk.StringVar(value=",".join(str(p) for p in QUICK_PORTS))
        self._entry(c, self.v_ports)

        pf = tk.Frame(c, bg=self.BG2); pf.pack(fill="x", pady=(6,0))
        tk.Label(pf, text="Presets:", font=("Segoe UI",8),
                 bg=self.BG2, fg=self.DIM).pack(side="left")
        for name, val in [("Web","80,443,8080,8443"),
                          ("DB","1433,3306,5432,27017,6379"),
                          ("1-1024","1-1024"),("All","1-65535")]:
            tk.Button(pf, text=name, font=("Segoe UI",8),
                      bg=self.BG3, fg=self.DIM,
                      activebackground=self.ACC2, activeforeground="white",
                      relief="flat", padx=5, pady=1, cursor="hand2",
                      command=lambda v=val: self.v_ports.set(v)
                      ).pack(side="left", padx=2)

        c = self._card(frame, "⚙️ Options")
        for label, var_name, lo, hi, inc, default in [
            ("Timeout (s)",  "v_timeout",  0.1, 30.0, 0.1,  1.0),
            ("Retries",      "v_retries",  0,   5,    1,     1),
            ("Max Threads",  "v_threads",  1,   500,  10,    100),
        ]:
            row = tk.Frame(c, bg=self.BG2); row.pack(fill="x", pady=2)
            tk.Label(row, text=label, font=("Segoe UI",9),
                     bg=self.BG2, fg=self.DIM, width=14, anchor="w"
                     ).pack(side="left")
            v = tk.DoubleVar(value=default) if "." in str(default) else tk.IntVar(value=default)
            setattr(self, var_name, v)
            tk.Spinbox(row, from_=lo, to=hi, increment=inc,
                       textvariable=v, width=7,
                       bg=self.BG3, fg=self.TEXT,
                       insertbackground=self.TEXT,
                       buttonbackground=self.BG3, relief="flat",
                       font=("Segoe UI",10)).pack(side="left")

        tk.Frame(c, height=8, bg=self.BG2).pack()
        for txt, var_name, default in [
            ("🏷️  Banner Grabbing",   "v_banners",     True),
            ("📡  UDP Scan",           "v_udp",         False),
            ("🌍  WHOIS Lookup",       "v_whois",       True),
            ("📍  GeoIP Lookup",       "v_geo",         True),
            ("🔴  Show Closed Ports",  "v_show_closed", False),
        ]:
            v = tk.BooleanVar(value=default)
            setattr(self, var_name, v)
            tk.Checkbutton(c, text=txt, variable=v,
                           bg=self.BG2, fg=self.TEXT, selectcolor=self.BG3,
                           activebackground=self.BG2, activeforeground=self.ACCENT,
                           font=("Segoe UI",9)).pack(anchor="w", pady=1)

        bf = tk.Frame(frame, bg=self.BG); bf.pack(fill="x", pady=(6,0))
        self.btn_start = tk.Button(bf, text="▶  START SCAN",
            font=("Segoe UI",12,"bold"),
            bg=self.ACC2, fg="white",
            activebackground="#388bfd", activeforeground="white",
            relief="flat", pady=11, cursor="hand2",
            command=self._start)
        self.btn_start.pack(fill="x", pady=(0,6))

        self.btn_stop = tk.Button(bf, text="⏹  STOP SCAN",
            font=("Segoe UI",12,"bold"),
            bg="#b91c1c", fg="white",
            activebackground="#dc2626", activeforeground="white",
            relief="flat", pady=11, cursor="hand2",
            state="disabled", command=self._stop)
        self.btn_stop.pack(fill="x", pady=(0,6))

        ef = tk.Frame(bf, bg=self.BG); ef.pack(fill="x")
        for txt, cmd in [("📄 Export PDF", self._export_pdf),
                         ("📊 Export CSV", self._export_csv)]:
            tk.Button(ef, text=txt, font=("Segoe UI",9,"bold"),
                      bg=self.BG3, fg=self.TEXT,
                      activebackground=self.BORDER, activeforeground=self.TEXT,
                      relief="flat", pady=7, cursor="hand2",
                      command=cmd).pack(side="left", fill="x", expand=True, padx=2)

    def _right_panel(self, parent):
        nb = ttk.Notebook(parent, style="Dark.TNotebook")
        nb.pack(fill="both", expand=True)

        for title, builder in [
            ("  🔌 Ports  ",     self._tab_ports),
            ("  🌍 WHOIS/GeoIP  ", self._tab_info),
            ("  📋 Log  ",        self._tab_log),
            ("  💻 Summary  ",    self._tab_summary),
        ]:
            frame = tk.Frame(nb, bg=self.BG)
            nb.add(frame, text=title)
            builder(frame)

    def _tab_ports(self, parent):
        sf = tk.Frame(parent, bg=self.BG, pady=6); sf.pack(fill="x", padx=8)
        self.lbl_open = self._stat_badge(sf, "Open: 0",     self.GREEN)
        self.lbl_filtered = self._stat_badge(sf, "Filtered: 0", self.YELLOW)
        self.lbl_closed = self._stat_badge(sf, "Closed: 0",   self.DIM)
        self.lbl_total = self._stat_badge(sf, "Total: 0",    self.DIM)

        ff = tk.Frame(parent, bg=self.BG, pady=3); ff.pack(fill="x", padx=8)
        tk.Label(ff, text="Filter:", font=("Segoe UI",9),
                 bg=self.BG, fg=self.DIM).pack(side="left", padx=(0,5))
        self.v_filter = tk.StringVar()
        self.v_filter.trace("w", lambda *_: self._filter())
        e = tk.Entry(ff, textvariable=self.v_filter,
                     bg=self.BG3, fg=self.TEXT, insertbackground=self.TEXT,
                     font=("Consolas",9), relief="flat", width=22,
                     highlightthickness=1, highlightcolor=self.ACCENT,
                     highlightbackground=self.BORDER)
        e.pack(side="left", ipady=4)
        tk.Label(ff, text="  Status:", font=("Segoe UI",9),
                 bg=self.BG, fg=self.DIM).pack(side="left", padx=(8,4))
        self.v_sf = tk.StringVar(value="all")
        for t, v in [("All","all"),("Open","open"),("Filtered","filtered")]:
            tk.Radiobutton(ff, text=t, value=v, variable=self.v_sf,
                           command=self._filter,
                           bg=self.BG, fg=self.TEXT, selectcolor=self.BG3,
                           activebackground=self.BG, font=("Segoe UI",9)
                           ).pack(side="left", padx=3)

        tf = tk.Frame(parent, bg=self.BG)
        tf.pack(fill="both", expand=True, padx=8, pady=(4,8))
        cols = ("port","proto","status","service","risk","version","banner")
        self.tree = ttk.Treeview(tf, columns=cols, show="headings",
                                  style="Results.Treeview")
        hdrs = [("Port",70),("Proto",70),("Status",80),
                ("Service",120),("Risk",70),("Version",130),("Banner",320)]
        for (txt, w), col in zip(hdrs, cols):
            self.tree.heading(col, text=txt,
                command=lambda c=col: self._sort(c))
            self.tree.column(col, width=w, minwidth=40)

        vsb = ttk.Scrollbar(tf, orient="vertical",   command=self.tree.yview)
        hsb = ttk.Scrollbar(tf, orient="horizontal", command=self.tree.xview)
        self.tree.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)
        vsb.pack(side="right",  fill="y")
        hsb.pack(side="bottom", fill="x")
        self.tree.pack(fill="both", expand=True)

        self.tree.tag_configure("open_low",  foreground=self.GREEN)
        self.tree.tag_configure("open_med",  foreground=self.ORANGE)
        self.tree.tag_configure("open_high", foreground=self.RED,
                                font=("Consolas",9,"bold"))
        self.tree.tag_configure("filtered",  foreground=self.YELLOW)
        self.tree.tag_configure("closed",    foreground=self.DIM)
        self.tree.tag_configure("udp",       foreground=self.CYAN)

        menu = tk.Menu(self.tree, tearoff=0, bg=self.BG3, fg=self.TEXT,
                       activebackground=self.ACC2, activeforeground="white")
        menu.add_command(label="Copy Port",       command=self._copy_port)
        menu.add_command(label="Copy Banner",     command=self._copy_banner)
        menu.add_separator()
        menu.add_command(label="Open in Browser", command=self._browser)
        menu.add_command(label="Port Details…",   command=self._detail)
        self.tree.bind("<Button-3>",
                       lambda e: (self.tree.selection_set(
                           self.tree.identify_row(e.y)),
                                  menu.post(e.x_root, e.y_root)))
        self.tree.bind("<Double-1>", lambda _: self._detail())

    def _tab_info(self, parent):
        pw = tk.PanedWindow(parent, orient="horizontal",
                            bg=self.BG, sashwidth=4)
        pw.pack(fill="both", expand=True)

        for title, attr in [("📍 GeoIP Information","geo_txt"),
                            ("🔎 WHOIS Information","whois_txt")]:
            f = tk.Frame(pw, bg=self.BG2); pw.add(f, minsize=280)
            tk.Label(f, text=title, font=("Segoe UI",11,"bold"),
                     bg=self.BG2, fg=self.ACCENT,
                     pady=10, padx=14).pack(anchor="w")
            tk.Frame(f, height=1, bg=self.BORDER).pack(fill="x")
            sb = tk.Scrollbar(f); sb.pack(side="right", fill="y")
            t = tk.Text(f, bg=self.BG2, fg=self.TEXT,
                        font=("Consolas",9), relief="flat",
                        wrap="word", state="disabled",
                        padx=14, pady=10, yscrollcommand=sb.set)
            t.pack(fill="both", expand=True)
            sb.config(command=t.yview)
            setattr(self, attr, t)
            t.tag_configure("k", foreground=self.ACCENT,
                            font=("Consolas",9,"bold"))
            t.tag_configure("v", foreground=self.TEXT)

    def _tab_log(self, parent):
        tk.Label(parent, text="📋 Scan Log",
                 font=("Segoe UI",11,"bold"),
                 bg=self.BG, fg=self.ACCENT,
                 pady=10, padx=14).pack(anchor="w")
        sb = tk.Scrollbar(parent); sb.pack(side="right", fill="y")
        self.log_txt = tk.Text(parent, bg=self.BG, fg=self.TEXT,
                               font=("Consolas",8), relief="flat",
                               wrap="none", state="disabled",
                               padx=10, pady=8,
                               yscrollcommand=sb.set)
        self.log_txt.pack(fill="both", expand=True, padx=8, pady=(0,8))
        sb.config(command=self.log_txt.yview)
        for tag, fg in [("ok",self.GREEN),("warn",self.YELLOW),
                        ("err",self.RED),("dim",self.DIM)]:
            self.log_txt.tag_configure(tag, foreground=fg)
        tk.Button(parent, text="🗑 Clear",
                  font=("Segoe UI",8), bg=self.BG3, fg=self.DIM,
                  activebackground=self.BORDER, activeforeground=self.TEXT,
                  relief="flat", padx=8, pady=4, cursor="hand2",
                  command=self._clear_log).pack(side="right", padx=8, pady=4)

    def _tab_summary(self, parent):
        tk.Label(parent, text="💻 Scan Summary & OS Fingerprint",
                 font=("Segoe UI",12,"bold"),
                 bg=self.BG, fg=self.ACCENT,
                 pady=10, padx=14).pack(anchor="w")
        sb = tk.Scrollbar(parent); sb.pack(side="right", fill="y")
        self.sum_txt = tk.Text(parent, bg=self.BG, fg=self.TEXT,
                               font=("Consolas",10), relief="flat",
                               wrap="word", state="disabled",
                               padx=14, pady=10,
                               yscrollcommand=sb.set)
        self.sum_txt.pack(fill="both", expand=True, padx=8, pady=(0,8))
        sb.config(command=self.sum_txt.yview)
        for tag, fg, bold in [
            ("hdr",  self.ACCENT, True),  ("val",    self.TEXT,   False),
            ("ok",   self.GREEN,  False),  ("warn",   self.YELLOW, False),
            ("err",  self.RED,    True),   ("dim",    self.DIM,    False),
        ]:
            font = ("Consolas",10,"bold") if bold else ("Consolas",10)
            self.sum_txt.tag_configure(tag, foreground=fg, font=font)

    def _statusbar(self):
        tk.Frame(self.root, height=1, bg=self.BORDER).pack(fill="x", side="bottom")
        sf = tk.Frame(self.root, bg=self.BG3, pady=5)
        sf.pack(fill="x", side="bottom")
        self.v_progress = tk.DoubleVar(value=0)
        ttk.Progressbar(sf, variable=self.v_progress, mode="determinate",
                        style="H.Horizontal.TProgressbar",
                        length=400).pack(side="left", padx=(14,8))
        self.v_status = tk.StringVar(value="Ready — enter a target and click Start Scan")
        tk.Label(sf, textvariable=self.v_status,
                 font=("Segoe UI",9), bg=self.BG3, fg=self.DIM
                 ).pack(side="right", padx=14)
        self.lbl_time = tk.Label(sf, text="", font=("Segoe UI",9,"bold"),
                                 bg=self.BG3, fg=self.ACCENT)
        self.lbl_time.pack(side="right", padx=6)

    def _card(self, parent, title=None):
        outer = tk.Frame(parent, bg=self.BORDER, pady=1, padx=1)
        outer.pack(fill="x", pady=(0,10))
        inner = tk.Frame(outer, bg=self.BG2, padx=14, pady=12)
        inner.pack(fill="both")
        if title:
            tk.Label(inner, text=title, font=("Segoe UI",10,"bold"),
                     bg=self.BG2, fg=self.ACCENT).pack(anchor="w", pady=(0,8))
        return inner

    def _lbl(self, parent, text):
        tk.Label(parent, text=text, font=("Segoe UI",8),
                 bg=self.BG2, fg=self.DIM).pack(anchor="w")

    def _entry(self, parent, var):
        e = tk.Entry(parent, textvariable=var,
                     bg=self.BG3, fg=self.TEXT, insertbackground=self.TEXT,
                     font=("Consolas",10), relief="flat",
                     highlightthickness=1, highlightcolor=self.ACCENT,
                     highlightbackground=self.BORDER)
        e.pack(fill="x", pady=(3,0), ipady=5)
        return e

    def _stat_badge(self, parent, text, fg):
        lbl = tk.Label(parent, text=text, font=("Segoe UI",9,"bold"),
                       bg=self.BG2, fg=fg, padx=10, pady=3)
        lbl.pack(side="left", padx=(0,5))
        return lbl

    def _on_mode(self):
        m = self.v_mode.get()
        if m == "quick":
            self.v_ports.set(",".join(str(p) for p in QUICK_PORTS))
        elif m == "full":
            self.v_ports.set("1-65535")
        elif m == "stealth" and not DEPS["scapy"]:
            messagebox.showwarning("Scapy Required",
                "Stealth SYN scan requires Scapy.\n"
                "pip install scapy\n\nFalling back to TCP connect.")

    def _start(self):
        target = self.v_target.get().strip()
        if not target:
            messagebox.showerror("Error", "Please enter a target."); return

        mode = self.v_mode.get()
        try:
            ports = QUICK_PORTS if mode == "quick" else parse_ports(self.v_ports.get())
        except ValueError as e:
            messagebox.showerror("Bad port range", str(e)); return
        if not ports:
            messagebox.showerror("Error", "No valid ports."); return

        self._clear_results()
        self._log_write(f"Starting scan: {target}  ({len(ports)} ports)", "dim")

        self.btn_start.config(state="disabled")
        self.btn_stop.config(state="normal")
        self.t_start = time.time()

        self.scanner = NetworkScanner(
            target=target, ports=ports,
            timeout=float(self.v_timeout.get()),
            retries=int(self.v_retries.get()),
            grab_banners=self.v_banners.get(),
            scan_udp=self.v_udp.get(),
            scan_mode=mode,
            max_threads=int(self.v_threads.get()),
            callback=lambda r: self.rq.put(r),
            progress_cb=lambda sc, tot: self.rq.put(("progress", sc, tot)),
            log_cb=lambda m: self.lq.put(m),
        )
        self.scan_thread = threading.Thread(target=self._bg_scan, daemon=True)
        self.scan_thread.start()
        self.v_status.set(f"Scanning {target} — {len(ports)} ports…")

    def _bg_scan(self):
        try:
            self.all_results = self.scanner.scan()
            if self.v_whois.get():
                self.lq.put("[*] WHOIS lookup…")
                self.whois_data = whois_lookup(self.scanner.target)
            if self.v_geo.get() and self.scanner.target_ip:
                self.lq.put("[*] GeoIP lookup…")
                self.geo_data = geoip_lookup(self.scanner.target_ip)
            self.rq.put(("done", self.scanner.target_ip, self.scanner.os_info))
        except Exception as exc:
            self.rq.put(("error", str(exc)))

    def _stop(self):
        if self.scanner:
            self.scanner.stop_event.set()
        self.v_status.set("Scan stopped by user")
        self.btn_start.config(state="normal")
        self.btn_stop.config(state="disabled")

    def _poll(self):
        try:
            while True:
                item = self.rq.get_nowait()
                if isinstance(item, ScanResult):
                    self._add_row(item)
                elif isinstance(item, tuple):
                    tag = item[0]
                    if tag == "progress":
                        _, sc, tot = item
                        pct = sc / tot * 100 if tot else 0
                        self.v_progress.set(pct)
                        elapsed = time.time() - self.t_start
                        self.lbl_time.config(text=f"{elapsed:.1f}s")
                        self.v_status.set(f"Scanning… {sc}/{tot} ({pct:.1f}%)")
                    elif tag == "done":
                        self._on_done(item[1], item[2])
                    elif tag == "error":
                        self._on_err(item[1])
        except queue.Empty:
            pass
        try:
            while True:
                msg = self.lq.get_nowait()
                if "[+]" in msg:
                    tag = "ok"
                elif "[!]" in msg or "error" in msg.lower():
                    tag = "err"
                else:
                    tag = "dim"
                self._log_write(msg, tag)
        except queue.Empty:
            pass
        self.root.after(80, self._poll)

    def _row_tag(self, r: ScanResult) -> str:
        if r.status == "open":
            return {"HIGH":"open_high","MEDIUM":"open_med"}.get(r.risk,"open_low")
        if r.status in ("open|filtered",):
            return "udp"
        return {"filtered":"filtered","closed":"closed"}.get(r.status,"dim")

    def _add_row(self, r: ScanResult, show_closed=None):
        if show_closed is None:
            show_closed = self.v_show_closed.get()
        if r.status == "closed" and not show_closed:
            return
        b = r.banner.replace("\n"," ").replace("\r","")[:100] if r.banner else ""
        self.tree.insert("", "end", tags=(self._row_tag(r),),
                         values=(r.port, r.protocol, r.status,
                                 r.service or "unknown",
                                 r.risk, r.version or "", b))
        open_n = filtered_n = closed_n = 0
        for res in self.all_results:
            if res.status == "open":
                open_n += 1
            elif res.status == "filtered":
                filtered_n += 1
            elif res.status == "closed":
                closed_n += 1
        self.lbl_open.config(    text=f"Open: {open_n}")
        self.lbl_filtered.config(text=f"Filtered: {filtered_n}")
        self.lbl_closed.config(  text=f"Closed: {closed_n}")
        self.lbl_total.config(   text=f"Total: {len(self.all_results)}")

    def _on_done(self, ip, os_info):
        elapsed = time.time() - self.t_start if self.t_start else 0
        open_n  = sum(1 for r in self.all_results if r.status == "open")
        self.btn_start.config(state="normal")
        self.btn_stop.config(state="disabled")
        self.v_progress.set(100)
        self.lbl_time.config(text=f"{elapsed:.1f}s")
        self.v_status.set(
            f"✅ Done — {open_n} open port(s) in {elapsed:.2f}s")
        self._log_write(f"\n✅ Scan complete — {open_n} open port(s)", "ok")
        if self.geo_data:   self._update_geo()
        if self.whois_data: self._update_whois()
        self._update_summary(ip, os_info, elapsed)

    def _on_err(self, msg):
        self.btn_start.config(state="normal")
        self.btn_stop.config(state="disabled")
        self.v_status.set(f"❌ Error: {msg}")
        self._log_write(f"Error: {msg}", "err")
        messagebox.showerror("Scan Error", msg)

    def _update_geo(self):
        t = self.geo_txt
        t.config(state="normal"); t.delete("1.0","end")
        g = self.geo_data
        if g.get("status") == "success":
            for label, key in [
                ("IP",       "query"),("Country","country"),
                ("Region",   "regionName"),("City","city"),
                ("ZIP",      "zip"),("Timezone","timezone"),
                ("Lat/Lon",  None),   
                ("ISP",      "isp"),("Org","org"),
                ("AS",       "as"),("Proxy","proxy"),
                ("Hosting",  "hosting"),("Mobile","mobile"),
            ]:
                if key is None:
                    v = f'{g.get("lat","?")}  /  {g.get("lon","?")}'
                else:
                    v = g.get(key)
                if v not in (None, "", False):
                    t.insert("end", f"{label:<13}", "k")
                    t.insert("end", f"  {v}\n", "v")
        else:
            t.insert("end", g.get("error","GeoIP unavailable"), "v")
        t.config(state="disabled")

    def _update_whois(self):
        t = self.whois_txt
        t.config(state="normal"); t.delete("1.0","end")
        raw = self.whois_data.get("raw","")
        t.insert("end", raw if raw else self.whois_data.get("error","No data"))
        t.config(state="disabled")

    def _update_summary(self, ip, os_info, elapsed):
        t = self.sum_txt
        t.config(state="normal"); t.delete("1.0","end")
        open_r  = [r for r in self.all_results if r.status == "open"]
        filt_r  = [r for r in self.all_results if r.status == "filtered"]
        udp_r   = [r for r in self.all_results if r.status == "open|filtered"]
        high_r  = [r for r in open_r if r.risk == "HIGH"]
        med_r   = [r for r in open_r if r.risk == "MEDIUM"]

        def row(label, val, tag="val"):
            t.insert("end", f"  {label:<22}", "dim")
            t.insert("end", f"{val}\n", tag)

        t.insert("end", "═══ TARGET ═════════════════════════════\n", "hdr")
        row("Host",         self.v_target.get())
        row("IP Address",   ip or "N/A")
        row("Scan Mode",    self.v_mode.get().upper())
        row("Duration",     f"{elapsed:.2f}s")
        row("Threads",      str(self.v_threads.get()))

        t.insert("end", "\n═══ RESULTS ════════════════════════════\n","hdr")
        row("Open TCP",     str(len(open_r)),  "ok")
        row("Filtered",     str(len(filt_r)),  "warn")
        row("UDP open|filt",str(len(udp_r)))
        row("High Risk",    str(len(high_r)),  "err" if high_r else "ok")
        row("Medium Risk",  str(len(med_r)),   "warn" if med_r else "ok")

        t.insert("end", "\n═══ OS FINGERPRINT ═════════════════════\n","hdr")
        t.insert("end", f"  {os_info}\n", "val")

        t.insert("end", "\n═══ OPEN PORTS ═════════════════════════\n","hdr")
        for r in sorted(open_r, key=lambda x: x.port):
            risk_tag = {"HIGH":"err","MEDIUM":"warn"}.get(r.risk,"ok")
            t.insert("end", f"  {r.port:>6}/{r.protocol:<8}  "
                            f"{r.service:<22}", "val")
            t.insert("end", f"[{r.risk}]\n", risk_tag)

        if high_r:
            t.insert("end", "\n⚠  HIGH-RISK PORTS DETECTED\n", "err")
            for r in high_r:
                t.insert("end",
                    f"  • Port {r.port} ({r.service})  "
                    "— review firewall rules\n", "err")

        if self.geo_data.get("status") == "success":
            g = self.geo_data
            t.insert("end", "\n═══ LOCATION ═══════════════════════════\n","hdr")
            row("Country",  g.get("country","?"))
            row("City",     g.get("city","?"))
            row("ISP",      g.get("isp","?"))
            row("Org",      g.get("org","?"))
            row("Proxy/VPN",str(g.get("proxy",False)))

        t.config(state="disabled")

    def _filter(self, *_):
        for i in self.tree.get_children():
            self.tree.delete(i)
        ft   = self.v_filter.get().lower()
        sf   = self.v_sf.get()
        sc   = self.v_show_closed.get()
        for r in self.all_results:
            if sf == "open"     and r.status not in ("open","open|filtered"):
                continue
            if sf == "filtered" and r.status != "filtered":
                continue
            if r.status == "closed" and not sc:
                continue
            if ft:
                hay = f"{r.port} {r.protocol} {r.status} {r.service} {r.banner}".lower()
                if ft not in hay:
                    continue
            self._add_row(r, show_closed=True)

    def _sort(self, col):
        rev = self._sort_rev.get(col, False)
        data = [(self.tree.set(k, col), k) for k in self.tree.get_children()]
        try:
            data.sort(key=lambda x: int(x[0]), reverse=rev)
        except (ValueError, TypeError):
            data.sort(key=lambda x: x[0].lower(), reverse=rev)
        for idx, (_, k) in enumerate(data):
            self.tree.move(k, "", idx)
        self._sort_rev[col] = not rev

    def _selected_result(self) -> ScanResult | None:
        sel = self.tree.selection()
        if not sel:
            return None
        port  = int(self.tree.set(sel[0], "port"))
        proto = self.tree.set(sel[0], "proto")
        return next((r for r in self.all_results
                     if r.port == port and r.protocol == proto), None)

    def _copy_port(self):
        r = self._selected_result()
        if r:
            self.root.clipboard_clear()
            self.root.clipboard_append(str(r.port))

    def _copy_banner(self):
        r = self._selected_result()
        if r:
            self.root.clipboard_clear()
            self.root.clipboard_append(r.banner)

    def _browser(self):
        r = self._selected_result()
        if not r:
            return
        scheme = "https" if r.service in ("HTTPS","HTTPS-Alt","IMAPS","POP3S") \
                         or r.port in (443,8443,9443) else "http"
        webbrowser.open(f"{scheme}://{self.v_target.get()}:{r.port}")

    def _detail(self):
        r = self._selected_result()
        if not r:
            return
        win = tk.Toplevel(self.root)
        win.title(f"Port {r.port}/{r.protocol}")
        win.geometry("560x380")
        win.configure(bg=self.BG)
        tk.Label(win, text=f"Port {r.port}/{r.protocol}  —  {r.service}",
                 font=("Segoe UI",13,"bold"),
                 bg=self.BG, fg=self.ACCENT, pady=12).pack()
        t = tk.Text(win, bg=self.BG2, fg=self.TEXT,
                    font=("Consolas",9), relief="flat",
                    padx=14, pady=10)
        t.pack(fill="both", expand=True, padx=12, pady=(0,12))
        for k, v in [
            ("Port",      str(r.port)),
            ("Protocol",  r.protocol),
            ("Status",    r.status),
            ("Service",   r.service),
            ("Risk",      r.risk),
            ("Version",   r.version or "N/A"),
            ("Timestamp", r.timestamp.strftime("%Y-%m-%d %H:%M:%S")),
            ("Banner",    r.banner or "(none)"),
        ]:
            t.insert("end", f"{k}:\n  {v}\n\n")
        t.config(state="disabled")

    def _log_write(self, msg: str, tag: str = "dim"):
        ts = datetime.now().strftime("%H:%M:%S")
        self.log_txt.config(state="normal")
        self.log_txt.insert("end", f"[{ts}]  {msg}\n", tag)
        self.log_txt.see("end")
        self.log_txt.config(state="disabled")

    def _clear_log(self):
        self.log_txt.config(state="normal")
        self.log_txt.delete("1.0","end")
        self.log_txt.config(state="disabled")

    def _clear_results(self):
        for i in self.tree.get_children():
            self.tree.delete(i)
        self.all_results.clear()
        self.geo_data.clear()
        self.whois_data.clear()
        self.lbl_open.config(    text="Open: 0")
        self.lbl_filtered.config(text="Filtered: 0")
        self.lbl_closed.config(  text="Closed: 0")
        self.lbl_total.config(   text="Total: 0")
        self.v_progress.set(0)
        for w in (self.geo_txt, self.whois_txt, self.sum_txt):
            w.config(state="normal"); w.delete("1.0","end"); w.config(state="disabled")

    def _export_pdf(self):
        if not DEPS["reportlab"]:
            messagebox.showerror("Missing",
                "Install ReportLab:\n  pip install reportlab"); return
        if not self.all_results:
            messagebox.showwarning("Empty","No results to export."); return
        path = filedialog.asksaveasfilename(
            defaultextension=".pdf",
            filetypes=[("PDF","*.pdf")],
            initialfile=f"netscan_{self.v_target.get()}_"
                        f"{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf")
        if not path:
            return
        elapsed = (time.time() - self.t_start) if self.t_start else 0
        ok, msg = export_pdf(
            path=path, target=self.v_target.get(),
            target_ip=(self.scanner.target_ip if self.scanner else ""),
            results=self.all_results,
            os_info=(self.scanner.os_info if self.scanner else "Unknown"),
            geo=self.geo_data, whois_data=self.whois_data,
            scan_info={"mode": self.v_mode.get(),
                       "total": len(self.all_results),
                       "duration": f"{elapsed:.2f}s"},
        )
        if ok:
            messagebox.showinfo("PDF Saved", f"Report saved:\n{path}")
        else:
            messagebox.showerror("Export Error", msg)

    def _export_csv(self):
        if not self.all_results:
            messagebox.showwarning("Empty","No results to export."); return
        path = filedialog.asksaveasfilename(
            defaultextension=".csv",
            filetypes=[("CSV","*.csv")],
            initialfile=f"netscan_{self.v_target.get()}_"
                        f"{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv")
        if not path:
            return
        try:
            with open(path, "w", newline="", encoding="utf-8") as f:
                w = csv.writer(f)
                w.writerow(["Port","Protocol","Status","Service",
                            "Risk","Version","Banner","Timestamp"])
                for r in sorted(self.all_results, key=lambda x: x.port):
                    w.writerow([r.port, r.protocol, r.status, r.service,
                                r.risk, r.version,
                                r.banner.replace("\n","\\n") if r.banner else "",
                                r.timestamp.strftime("%Y-%m-%d %H:%M:%S")])
            messagebox.showinfo("CSV Saved", f"Data saved:\n{path}")
        except Exception as e:
            messagebox.showerror("Export Error", str(e))

def _dep_check_dialog(root: tk.Tk):
    missing = [pkg for pkg, key in [
        ("requests","requests"),("python-whois","whois"),
        ("reportlab","reportlab"),("scapy","scapy"),
    ] if not DEPS.get(key)]
    if missing and messagebox.askyesno(
        "Optional Dependencies",
        "Some optional packages are missing:\n"
        + "\n".join(f"  • {p}" for p in missing)
        + "\n\nInstall them now for full functionality?\n"
        "(The scanner works without them, just with fewer features.)",
        parent=root
    ):
        try:
            subprocess.run(
                [sys.executable, "-m", "pip", "install",
                 "--break-system-packages", "--quiet"] + missing,
                check=True)
            messagebox.showinfo("Done",
                "Packages installed.\nPlease restart NetScan Pro.", parent=root)
            sys.exit(0)
        except Exception as e:
            messagebox.showwarning("Install Failed",
                f"Could not auto-install.\n\n"
                f"Run manually:\n  pip install {' '.join(missing)}\n\n{e}",
                parent=root)

if __name__ == "__main__":
    root = tk.Tk()
    _dep_check_dialog(root)
    app = NetScanGUI(root)
    root.mainloop()
