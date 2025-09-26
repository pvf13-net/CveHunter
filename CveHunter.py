import argparse
import ipaddress
import socket
import sys
import re
from concurrent.futures import ThreadPoolExecutor, as_completed

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from bs4 import BeautifulSoup

console = Console()


def make_session(timeout: int, retries: int = 3, backoff: float = 0.5) -> requests.Session:
    s = requests.Session()
    s.headers.update({
        "User-Agent": "CVE-Spider/1.2 (+https://example.local)",
        "Accept": "text/html,application/json;q=0.9,*/*;q=0.8",
    })
    retry = Retry(
        total=retries,
        read=retries,
        connect=retries,
        backoff_factor=backoff,
        status_forcelist=[429, 500, 502, 503, 504],
        allowed_methods=frozenset(["GET", "HEAD"]),
        raise_on_status=False,
    )
    adapter = HTTPAdapter(max_retries=retry)
    s.mount("http://", adapter)
    s.mount("https://", adapter)
    s.request = _with_timeout(s.request, timeout)  # inject default timeout
    return s

def _with_timeout(request_func, timeout):
    def wrapped(method, url, **kwargs):
        if "timeout" not in kwargs:
            kwargs["timeout"] = timeout
        return request_func(method, url, **kwargs)
    return wrapped


def banner(to_file=None):
    banner_text = "[bold green]CVE Spidering Tool[/bold green]\n" \
                  "[bold yellow]Author:[/bold yellow] pvf13-net\n" \
                  "[bold cyan]Hunting CVEs[/bold cyan]"
    panel = Panel.fit(
        banner_text,
        title="[bold blue]Welcome[/bold blue]",
        border_style="bold magenta"
    )
    if to_file:
        # Write a plain-text banner for files
        to_file.write("=== CVE Spidering Tool ===\nAuthor: pvf13-net\nHunting CVEs\n\n")
    else:
        console.print(panel)


def is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False

def resolve_domain(domain: str) -> str:
    try:
        return socket.gethostbyname(domain)
    except socket.gaierror:
        console.print(f"[bold red][!] Unable to resolve domain: {domain}[/bold red]")
        sys.exit(1)


def fetch_internetdb(ip: str, session: requests.Session) -> dict:
    url = f"https://internetdb.shodan.io/{ip}"
    try:
        r = session.get(url)
        if r.status_code == 200:
            return r.json()
        console.print(f"[bold red][!] Error fetching InternetDB data: HTTP {r.status_code}[/bold red]")
        sys.exit(1)
    except requests.RequestException as e:
        console.print(f"[bold red][!] Request failed: {e}[/bold red]")
        sys.exit(1)


_CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE)

def get_base_score(cve_id: str, session: requests.Session):
    """
    Returns (score_text, url) for a CVE.
    Attempts multiple selectors to be resilient to minor NVD changes.
    """
    url = f"https://nvd.nist.gov/vuln/detail/{cve_id}"
    try:
        r = session.get(url)
        if r.status_code != 200:
            return f"HTTP {r.status_code}", url

        soup = BeautifulSoup(r.text, "html.parser")

        # Primary selector (current NVD)
        el = soup.find("a", {"data-testid": "vuln-cvss3-panel-score"})
        if el and el.text.strip():
            return el.text.strip(), url

        # Secondary attempts (legacy/fallbacks)
        alt = soup.select_one("#Cvss3NistCalculatorAnchor, .severityDetail a, .label-and-score > a")
        if alt and alt.text.strip():
            return alt.text.strip(), url

        # Sometimes score is in a span near 'CVSS 3.x Base Score'
        for possible in soup.find_all(["span", "a"]):
            txt = (possible.get_text(strip=True) or "")
            if re.match(r"^(CVSS.*Base Score|[0-9]+\.[0-9]+)$", txt):
                return txt, url

        return "Not Found", url
    except Exception as e:
        return f"Error: {str(e)}", url


def display_hostnames(hostnames, to_file=None):
    hostnames = sorted(set(hostnames or []))
    if to_file:
        to_file.write("\nHostnames:\n")
        if hostnames:
            for h in hostnames:
                to_file.write(f" -> {h}\n")
        else:
            to_file.write("N/A\n")
    else:
        table = Table(title="Hostnames")
        table.add_column("Hostname", style="cyan")
        if hostnames:
            for h in hostnames:
                table.add_row(h)
        else:
            table.add_row("N/A")
        console.print(table)

def display_ports(ports, to_file=None):
    ports = sorted(set(ports or []))
    if to_file:
        to_file.write("\nOpen Ports:\n")
        if ports:
            for p in ports:
                to_file.write(f" -> {p}\n")
        else:
            to_file.write("N/A\n")
    else:
        table = Table(title="Open Ports")
        table.add_column("Port", justify="right", style="green")
        if ports:
            for p in ports:
                table.add_row(str(p))
        else:
            table.add_row("N/A")
        console.print(table)

def display_cves(cves, session: requests.Session, threads: int, to_file=None):
    cves = [c for c in (cves or []) if _CVE_RE.match(c)]
    cves = sorted(set(cves), key=lambda s: (s.split("-")[1], int(s.split("-")[2])))

    if to_file:
        to_file.write("\nVulnerabilities (CVEs):\n\n")
        if not cves:
            to_file.write("N/A\n")
            return
    else:
        table = Table(title="Vulnerabilities (CVEs)")
        table.add_column("CVE", style="bold")
        table.add_column("Base Score", justify="center")
        table.add_column("Link", style="blue", overflow="fold")

    if not cves:
        if not to_file:
            console.print("[yellow]No CVEs found.[/yellow]")
        return

    max_workers = min(len(cves), max(1, threads))
    futures = []
    with ThreadPoolExecutor(max_workers=max_workers) as ex:
        for cve in cves:
            futures.append(ex.submit(get_base_score, cve, session))

        for cve, fut in zip(cves, as_completed(futures)):
            score, url = fut.result()
            if to_file:
                to_file.write(f" -> | {cve}\t| {score}\t| {url}\t|\n")
            else:
                table.add_row(cve, str(score), f"[link={url}]{url}[/link]")

    if not to_file:
        console.print(table)


def main():
    parser = argparse.ArgumentParser(description="CVEs Hunting Tool (improved)")
    parser.add_argument("-d", "--domain", help="IP address or domain to scan")
    parser.add_argument("-o", "--output", help="Write human-readable results to a text file", type=str)
    parser.add_argument("--threads", help="Max concurrent CVE lookups (default: 8)", type=int, default=8)
    parser.add_argument("--timeout", help="HTTP timeout seconds (default: 10)", type=int, default=10)
    args = parser.parse_args()

    out_fh = open(args.output, "w", encoding="utf-8") if args.output else None
    try:
        banner(out_fh)

        # Determine target (arg or piped)
        if not args.domain:
            piped = sys.stdin.read().strip()
            if not piped:
                console.print("[bold red][!] No input provided via pipe or -d/--domain.[/bold red]")
                sys.exit(1)
            target = piped
        else:
            target = args.domain.strip()

        # Resolve if domain
        if not is_ip(target):
            console.print(f"[bold yellow][+] Resolving domain {target} to IP...[/bold yellow]") if not out_fh else None
            ip = resolve_domain(target)
            if out_fh:
                out_fh.write(f"Resolved {target} -> {ip}\n")
            else:
                console.print(f"[bold green][+] Resolved IP: {ip}[/bold green]")
        else:
            ip = target

        # HTTP session with retry/timeout
        session = make_session(timeout=args.timeout)

        if not out_fh:
            console.print(f"[bold cyan][+] Fetching data for IP: {ip}...[/bold cyan]")
        data = fetch_internetdb(ip, session)

        display_hostnames(data.get("hostnames", []), out_fh)
        display_ports(data.get("ports", []), out_fh)
        display_cves(data.get("vulns", []), session=session, threads=args.threads, to_file=out_fh)

    finally:
        if out_fh:
            out_fh.close()

if __name__ == "__main__":
    main()
