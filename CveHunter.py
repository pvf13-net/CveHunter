#!/usr/bin/env python3
import argparse, ipaddress, socket, sys, re, subprocess, json
from concurrent.futures import ThreadPoolExecutor, as_completed
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from bs4 import BeautifulSoup

console = Console()

# ---------- HTTP session ----------
def make_session(timeout: int = 10):
    s = requests.Session()
    s.headers.update({"User-Agent": "CVE-Hunting/1.2 (+local)"})
    retry = Retry(total=3, backoff_factor=0.5, status_forcelist=[429, 500, 502, 503, 504])
    s.mount("http://", HTTPAdapter(max_retries=retry))
    s.mount("https://", HTTPAdapter(max_retries=retry))
    s.request = _with_timeout(s.request, timeout)
    return s

def _with_timeout(req, timeout):
    def wrapped(method, url, **kw):
        kw.setdefault("timeout", timeout)
        return req(method, url, **kw)
    return wrapped

# ---------- UI ----------
def banner():
    console.print(Panel.fit(
        "[bold green]CVE Hunting Tool[/]\n[bold yellow]Author:[/] pvf13-net\n[bold cyan]Hunting CVEs[/]",
        title="[bold blue]Welcome[/]", border_style="bold magenta"
    ))

# ---------- helpers ----------
def is_ip(v):
    try:
        ipaddress.ip_address(v); return True
    except ValueError:
        return False

def resolve_domain(domain: str) -> str:
    try:
        return socket.gethostbyname(domain)
    except Exception:
        console.print(f"[bold red][!] Cannot resolve {domain}[/]")
        sys.exit(1)

# ---------- nmap run & parse ----------
VULNERS_PATH = "/usr/share/nmap/scripts/vulners.nse"

def _run_nmap(ip: str, fast: bool = True) -> str:
    # Container-safe flags: -Pn (no ping), -sT (TCP connect), -n (no DNS), --reason for clarity
    cmd = [
        "nmap", "-sV", "-sT", "-Pn", "-n", "--reason",
        "--script", VULNERS_PATH, "--script-args", "mincvss=0.0",
        "-oN", "-", ip
    ]
    if fast:
        cmd.insert(1, "-F")  # top 100 ports first
    try:
        res = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
        return res.stdout
    except Exception as e:
        console.print(f"[red][!] nmap failed: {e}[/]")
        return ""

_port_re = re.compile(r"^(\d{1,5})/tcp\s+open\b", re.MULTILINE)
_cve_re  = re.compile(r"(CVE-\d{4}-\d{4,})", re.IGNORECASE)
_hn_re   = re.compile(r"^Nmap scan report for (.+)$", re.MULTILINE)

def _parse_nmap(out: str, ip: str):
    ports = [int(m.group(1)) for m in _port_re.finditer(out)]
    cves  = sorted(set(_cve_re.findall(out)), key=lambda x: (int(x.split("-")[1]), int(x.split("-")[2])))
    hn = []
    m = _hn_re.search(out)
    if m:
        name = m.group(1)
        hn = [name.split(" (")[0]]
    if not hn:
        hn = [ip]
    return {"ports": ports, "vulns": cves, "hostnames": hn}

def scan_target(ip: str) -> dict:
    console.print(f"[bold cyan][+] Scanning {ip} with nmap + vulners.com (2025 method)...[/]")
    out = _run_nmap(ip, fast=True)
    data = _parse_nmap(out, ip)
    if not data["ports"]:
        out2 = _run_nmap(ip, fast=False)
        d2 = _parse_nmap(out2, ip)
        data["ports"] = sorted(set(data["ports"] + d2["ports"]))
        data["vulns"] = sorted(set(data["vulns"] + d2["vulns"]),
                               key=lambda x: (int(x.split("-")[1]), int(x.split("-")[2])))
        if d2["hostnames"] and d2["hostnames"] != [ip]:
            data["hostnames"] = d2["hostnames"]
    return data

# ---------- NVD score (robust) ----------
def get_base_score(cve_id: str, session: requests.Session):
    """
    Returns (score_text, url). Tries NVD 2.0 JSON first, then HTML as fallback.
    """
    nvd_link = f"https://nvd.nist.gov/vuln/detail/{cve_id}"

    # 1) JSON API (stable, no scraping)
    try:
        jurl = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}"
        r = session.get(jurl)
        if r.status_code == 200:
            j = r.json()
            vulns = j.get("vulnerabilities") or []
            if vulns:
                metrics = (vulns[0].get("cve") or {}).get("metrics") or {}
                for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
                    if key in metrics and metrics[key]:
                        metric = metrics[key][0]
                        cvss   = metric.get("cvssData", {})
                        base   = cvss.get("baseScore") or metric.get("baseScore")
                        sev    = cvss.get("baseSeverity") or metric.get("baseSeverity", "")
                        vec    = cvss.get("vectorString", "")
                        score_text = f"{base} {sev}".strip() if base else "N/A"
                        return score_text, nvd_link
    except Exception:
        pass

    # 2) HTML fallback (best-effort)
    try:
        r = session.get(nvd_link)
        if r.status_code == 200:
            soup = BeautifulSoup(r.text, "html.parser")
            el = soup.find("a", {"data-testid": "vuln-cvss3-panel-score"})
            if el and el.text.strip():
                return el.text.strip(), nvd_link
    except Exception:
        pass

    return "N/A", nvd_link

# ---------- display ----------
def display_hostnames(hostnames):
    table = Table(title="Hostnames"); table.add_column("Hostname", style="cyan")
    for h in (hostnames or ["N/A"]): table.add_row(h)
    console.print(table)

def display_ports(ports):
    table = Table(title="Open Ports"); table.add_column("Port", justify="right", style="green")
    if not ports: table.add_row("N/A")
    else:
        for p in sorted(ports): table.add_row(str(p))
    console.print(table)

def display_cves(cves, session: requests.Session):
    if not cves:
        console.print("[yellow]No CVEs found.[/]")
        return
    table = Table(title="Vulnerabilities (CVEs)")
    table.add_column("CVE", style="bold red")
    table.add_column("Score", justify="center")
    table.add_column("Link", style="blue")
    # Be gentle with NVD rate limits
    max_workers = min(5, len(cves))
    with ThreadPoolExecutor(max_workers=max_workers) as ex:
        futures = {ex.submit(get_base_score, c, session): c for c in cves}
        for fut in as_completed(futures):
            c = futures[fut]; score, url = fut.result()
            table.add_row(c, score, f"[link={url}]{url}[/]")
    console.print(table)

# ---------- main ----------
def main():
    parser = argparse.ArgumentParser(description="CVEs Hunting Tool (improved)")
    parser.add_argument("-d", "--domain", help="IP address or domain to scan")
    args = parser.parse_args()

    banner()
    target = args.domain or sys.stdin.read().strip()
    if not target:
        console.print("[bold red][!] No target given[/]"); return

    ip = target if is_ip(target) else resolve_domain(target)
    console.print(f"[bold green][+] Target IP: {ip}[/]")

    data = scan_target(ip)
    session = make_session(timeout=10)
    display_hostnames(data["hostnames"])
    display_ports(data["ports"])
    display_cves(data["vulns"], session)

if __name__ == "__main__":
    main()
