#!/usr/bin/env python3
"""
Port scanner: scans a target host for open TCP ports, resolves service names,
and saves results to a timestamped file.

Usage:
  python3 port_scanner.py <target> [options]

Examples:
  python3 port_scanner.py 192.168.1.1
  python3 port_scanner.py scanme.nmap.org --ports 1-1024
  python3 port_scanner.py 10.0.0.1 --ports 22,80,443,8080 -t 100 -o results.html
"""

import argparse
import csv
import ipaddress
import os
import socket
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime


BANNER = """
╔══════════════════════════════╗
║        Python Port Scanner        ║
╚══════════════════════════════╝
"""

WELL_KNOWN = {
    20: "ftp-data", 21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp",
    53: "dns", 67: "dhcp", 68: "dhcp", 69: "tftp", 80: "http",
    110: "pop3", 119: "nntp", 123: "ntp", 135: "msrpc", 137: "netbios-ns",
    138: "netbios-dgm", 139: "netbios-ssn", 143: "imap", 161: "snmp",
    162: "snmptrap", 194: "irc", 389: "ldap", 443: "https", 445: "smb",
    465: "smtps", 514: "syslog", 515: "printer", 587: "submission",
    636: "ldaps", 993: "imaps", 995: "pop3s", 1080: "socks",
    1194: "openvpn", 1433: "mssql", 1521: "oracle", 2049: "nfs",
    2181: "zookeeper", 3306: "mysql", 3389: "rdp", 4444: "metasploit",
    5432: "postgresql", 5900: "vnc", 5985: "winrm-http", 5986: "winrm-https",
    6379: "redis", 6443: "kubernetes-api", 7001: "weblogic", 8080: "http-alt",
    8443: "https-alt", 8888: "jupyter", 9000: "php-fpm", 9200: "elasticsearch",
    9300: "elasticsearch-cluster", 11211: "memcached", 27017: "mongodb",
    27018: "mongodb-shard", 27019: "mongodb-config",
}


def resolve_host(target: str) -> tuple[str, str]:
    try:
        ip = str(ipaddress.ip_address(target))
        try:
            hostname = socket.gethostbyaddr(ip)[0]
        except socket.herror:
            hostname = ip
        return ip, hostname
    except ValueError:
        pass
    try:
        ip = socket.gethostbyname(target)
        return ip, target
    except socket.gaierror as e:
        sys.exit(f"[!] Cannot resolve '{target}': {e}")


def get_service(port: int) -> str:
    if port in WELL_KNOWN:
        return WELL_KNOWN[port]
    try:
        return socket.getservbyport(port, "tcp")
    except OSError:
        return "unknown"


def grab_banner(ip: str, port: int, timeout: float) -> str:
    try:
        with socket.create_connection((ip, port), timeout=timeout) as s:
            s.settimeout(timeout)
            data = s.recv(1024)
            return data.decode(errors="replace").strip().splitlines()[0][:80]
    except Exception:
        return ""


def scan_port(ip: str, port: int, timeout: float, banner: bool) -> dict:
    """Return a result dict with state: open / closed / filtered."""
    service = get_service(port)
    try:
        with socket.create_connection((ip, port), timeout=timeout):
            pass
        state = "open"
    except ConnectionRefusedError:
        state = "closed"
    except (socket.timeout, TimeoutError, OSError):
        state = "filtered"

    result = {"port": port, "state": state, "service": service, "banner": ""}
    if state == "open" and banner:
        result["banner"] = grab_banner(ip, port, timeout)
    return result


def parse_ports(spec: str) -> list[int]:
    ports = set()
    for part in spec.split(","):
        part = part.strip()
        if "-" in part:
            lo, hi = part.split("-", 1)
            lo, hi = int(lo), int(hi)
            if not (1 <= lo <= hi <= 65535):
                sys.exit(f"[!] Invalid port range: {part}")
            ports.update(range(lo, hi + 1))
        else:
            p = int(part)
            if not (1 <= p <= 65535):
                sys.exit(f"[!] Invalid port: {p}")
            ports.add(p)
    return sorted(ports)


def draw_progress(completed: int, total: int, bar_width: int = 38) -> None:
    pct = completed / total
    filled = int(bar_width * pct)
    bar = "█" * filled + "░" * (bar_width - filled)
    print(f"\r  [{bar}] {pct*100:5.1f}%  {completed}/{total} ports", end="", file=sys.stderr, flush=True)


def save_html(
    path: str,
    target: str,
    ip: str,
    hostname: str,
    results: list[dict],
    start: datetime,
    end: datetime,
    ports_spec: str = "",
) -> None:
    import json as _json
    duration = (end - start).total_seconds()
    open_count = sum(1 for r in results if r["state"] == "open")
    closed_count = sum(1 for r in results if r["state"] == "closed")
    filtered_count = sum(1 for r in results if r["state"] == "filtered")

    export_payload = _json.dumps({
        "meta": {
            "target": target,
            "ip": ip,
            "hostname": hostname,
            "ports_spec": ports_spec,
            "started": start.strftime("%Y-%m-%dT%H:%M:%S"),
            "finished": end.strftime("%Y-%m-%dT%H:%M:%S"),
            "duration_seconds": round(duration, 2),
            "total_scanned": len(results),
            "open": open_count,
            "closed": closed_count,
            "filtered": filtered_count,
        },
        "results": results,
    }, indent=2)

    rows = ""
    for r in results:
        state = r["state"]
        if state == "open":
            state_html = '<span class="badge badge-open">open</span>'
            row_class = "row-open"
        elif state == "closed":
            state_html = '<span class="badge badge-closed">closed</span>'
            row_class = "row-closed"
        else:
            state_html = '<span class="badge badge-filtered">filtered</span>'
            row_class = "row-filtered"

        banner_cell = (
            f'<span class="banner">{r["banner"]}</span>'
            if r["banner"] else '<span class="na">—</span>'
        )
        rows += f"""
        <tr class="{row_class}" data-state="{state}">
          <td><span class="port-badge">{r['port']}</span></td>
          <td>{state_html}</td>
          <td>{r['service']}</td>
          <td>{banner_cell}</td>
        </tr>"""

    ts = start.strftime("%Y%m%d_%H%M%S")
    safe_target = target.replace(".", "_").replace(":", "_")

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Port Scan Report — {target}</title>
  <style>
    *, *::before, *::after {{ box-sizing: border-box; margin: 0; padding: 0; }}
    body {{
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
      background: #0f172a;
      color: #e2e8f0;
      min-height: 100vh;
      padding: 2rem;
    }}
    .container {{ max-width: 960px; margin: 0 auto; }}

    header {{
      display: flex;
      align-items: center;
      gap: 1rem;
      margin-bottom: 2rem;
    }}
    .logo {{
      width: 48px; height: 48px;
      background: linear-gradient(135deg, #6366f1, #8b5cf6);
      border-radius: 12px;
      display: flex; align-items: center; justify-content: center;
      font-size: 1.4rem;
    }}
    h1 {{ font-size: 1.5rem; font-weight: 700; color: #f1f5f9; }}
    h1 span {{ color: #8b5cf6; }}
    .subtitle {{ font-size: 0.82rem; color: #64748b; margin-top: 3px; }}

    .cards {{
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(140px, 1fr));
      gap: 1rem;
      margin-bottom: 2rem;
    }}
    .card {{
      background: #1e293b;
      border: 1px solid #334155;
      border-radius: 12px;
      padding: 1.1rem 1.25rem;
    }}
    .card-label {{ font-size: 0.68rem; text-transform: uppercase; letter-spacing: 0.08em; color: #64748b; margin-bottom: 0.35rem; }}
    .card-value {{ font-size: 1.05rem; font-weight: 600; color: #f1f5f9; word-break: break-all; }}
    .card-value.c-open     {{ color: #22c55e; font-size: 1.3rem; }}
    .card-value.c-closed   {{ color: #f87171; font-size: 1.3rem; }}
    .card-value.c-filtered {{ color: #fb923c; font-size: 1.3rem; }}

    .toolbar {{
      display: flex;
      align-items: center;
      gap: 0.5rem;
      margin-bottom: 0.75rem;
      flex-wrap: wrap;
    }}
    .toolbar-label {{ font-size: 0.7rem; text-transform: uppercase; letter-spacing: 0.08em; color: #64748b; margin-right: 0.25rem; }}
    .filter-btn {{
      padding: 0.3rem 0.75rem;
      border-radius: 20px;
      border: 1px solid #334155;
      background: #1e293b;
      color: #94a3b8;
      font-size: 0.78rem;
      cursor: pointer;
      transition: all 0.15s;
    }}
    .filter-btn:hover {{ border-color: #6366f1; color: #a5b4fc; }}
    .filter-btn.active {{ background: #312e81; border-color: #6366f1; color: #a5b4fc; font-weight: 600; }}
    .filter-btn.active.f-open     {{ background: #14532d; border-color: #22c55e; color: #86efac; }}
    .filter-btn.active.f-closed   {{ background: #450a0a; border-color: #f87171; color: #fca5a5; }}
    .filter-btn.active.f-filtered {{ background: #431407; border-color: #fb923c; color: #fdba74; }}

    .export-btn {{
      padding: 0.3rem 0.85rem;
      border-radius: 20px;
      border: 1px solid #334155;
      background: #1e293b;
      color: #94a3b8;
      font-size: 0.78rem;
      cursor: pointer;
      transition: all 0.15s;
    }}
    .export-btn:hover {{ border-color: #8b5cf6; color: #c4b5fd; background: #2e1065; }}

    .search-wrap {{ margin-left: auto; }}
    #search {{
      background: #1e293b;
      border: 1px solid #334155;
      border-radius: 8px;
      color: #e2e8f0;
      font-size: 0.82rem;
      padding: 0.3rem 0.75rem;
      outline: none;
      width: 160px;
      transition: border-color 0.15s;
    }}
    #search:focus {{ border-color: #6366f1; }}
    #search::placeholder {{ color: #475569; }}

    table {{
      width: 100%;
      border-collapse: collapse;
      background: #1e293b;
      border: 1px solid #334155;
      border-radius: 12px;
      overflow: hidden;
    }}
    thead {{ background: #0f172a; position: sticky; top: 0; z-index: 1; }}
    th {{
      padding: 0.7rem 1rem;
      text-align: left;
      font-size: 0.68rem;
      text-transform: uppercase;
      letter-spacing: 0.08em;
      color: #64748b;
      font-weight: 600;
      cursor: pointer;
      user-select: none;
    }}
    th:hover {{ color: #94a3b8; }}
    td {{
      padding: 0.6rem 1rem;
      font-size: 0.88rem;
      border-top: 1px solid #0f172a;
    }}
    tr.row-open td   {{ background: rgba(34,197,94,0.04); }}
    tr.row-closed td {{ background: rgba(248,113,113,0.03); }}
    tr.row-filtered td {{ background: rgba(251,146,60,0.03); }}
    tr:hover td {{ filter: brightness(1.12); }}
    tr.hidden {{ display: none; }}

    .port-badge {{
      display: inline-block;
      background: #1e1b4b;
      color: #a5b4fc;
      padding: 0.12rem 0.5rem;
      border-radius: 6px;
      font-family: "SF Mono", "Fira Code", monospace;
      font-size: 0.82rem;
      font-weight: 600;
    }}
    .badge {{
      display: inline-block;
      padding: 0.12rem 0.5rem;
      border-radius: 6px;
      font-size: 0.75rem;
      font-weight: 700;
      text-transform: uppercase;
      letter-spacing: 0.04em;
    }}
    .badge-open     {{ background: #14532d; color: #86efac; }}
    .badge-closed   {{ background: #450a0a; color: #fca5a5; }}
    .badge-filtered {{ background: #431407; color: #fdba74; }}

    .banner {{ font-family: "SF Mono","Fira Code",monospace; font-size: 0.76rem; color: #94a3b8; }}
    .na {{ color: #334155; }}

    #row-count {{ font-size: 0.75rem; color: #475569; margin-left: auto; }}

    footer {{
      margin-top: 2rem;
      text-align: center;
      font-size: 0.72rem;
      color: #334155;
    }}
  </style>
</head>
<body>
  <div class="container">
    <header>
      <div class="logo">&#128270;</div>
      <div>
        <h1>Port Scan &mdash; <span>{target}</span></h1>
        <div class="subtitle">
          {ip} &bull; {hostname} &bull; Scanned {len(results)} ports in {duration:.2f}s &bull; {start.strftime('%Y-%m-%d %H:%M:%S')}
        </div>
      </div>
    </header>

    <div class="cards">
      <div class="card">
        <div class="card-label">Target IP</div>
        <div class="card-value">{ip}</div>
      </div>
      <div class="card">
        <div class="card-label">Hostname</div>
        <div class="card-value">{hostname}</div>
      </div>
      <div class="card">
        <div class="card-label">Ports Scanned</div>
        <div class="card-value">{len(results)}</div>
      </div>
      <div class="card">
        <div class="card-label">Duration</div>
        <div class="card-value">{duration:.2f}s</div>
      </div>
      <div class="card">
        <div class="card-label">Open</div>
        <div class="card-value c-open">{open_count}</div>
      </div>
      <div class="card">
        <div class="card-label">Closed</div>
        <div class="card-value c-closed">{closed_count}</div>
      </div>
      <div class="card">
        <div class="card-label">Filtered</div>
        <div class="card-value c-filtered">{filtered_count}</div>
      </div>
    </div>

    <div class="toolbar">
      <span class="toolbar-label">Filter:</span>
      <button class="filter-btn active" onclick="filterTable('all', this)">All ({len(results)})</button>
      <button class="filter-btn f-open"     onclick="filterTable('open', this)">Open ({open_count})</button>
      <button class="filter-btn f-closed"   onclick="filterTable('closed', this)">Closed ({closed_count})</button>
      <button class="filter-btn f-filtered" onclick="filterTable('filtered', this)">Filtered ({filtered_count})</button>
      <div class="search-wrap">
        <input id="search" type="text" placeholder="Search port / service…" oninput="applyFilters()">
      </div>
      <button class="export-btn" onclick="exportJSON()">&#8675; Export JSON</button>
      <span id="row-count"></span>
    </div>

    <table id="results-table">
      <thead>
        <tr>
          <th onclick="sortTable(0)">Port &#8597;</th>
          <th onclick="sortTable(1)">State &#8597;</th>
          <th onclick="sortTable(2)">Service &#8597;</th>
          <th>Banner</th>
        </tr>
      </thead>
      <tbody id="tbody">{rows}
      </tbody>
    </table>

    <footer>Python Port Scanner &bull; {start.strftime('%Y-%m-%d')}</footer>
  </div>

  <script>
    const SCAN_DATA = {export_payload};

    function exportJSON() {{
      const blob = new Blob([JSON.stringify(SCAN_DATA, null, 2)], {{type: 'application/json'}});
      const a = document.createElement('a');
      a.href = URL.createObjectURL(blob);
      a.download = 'scan_{safe_target}_{ts}.json';
      a.click();
      URL.revokeObjectURL(a.href);
    }}

    let activeFilter = 'all';
    let sortCol = 0, sortAsc = true;

    function filterTable(state, btn) {{
      activeFilter = state;
      document.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active'));
      btn.classList.add('active');
      applyFilters();
    }}

    function applyFilters() {{
      const query = document.getElementById('search').value.toLowerCase();
      const rows = document.querySelectorAll('#tbody tr');
      let visible = 0;
      rows.forEach(row => {{
        const state = row.dataset.state;
        const text = row.textContent.toLowerCase();
        const stateMatch = activeFilter === 'all' || state === activeFilter;
        const textMatch = !query || text.includes(query);
        const show = stateMatch && textMatch;
        row.classList.toggle('hidden', !show);
        if (show) visible++;
      }});
      document.getElementById('row-count').textContent = visible + ' row' + (visible !== 1 ? 's' : '');
    }}

    function sortTable(col) {{
      if (sortCol === col) {{ sortAsc = !sortAsc; }} else {{ sortCol = col; sortAsc = true; }}
      const tbody = document.getElementById('tbody');
      const rows = Array.from(tbody.querySelectorAll('tr'));
      rows.sort((a, b) => {{
        const aVal = a.cells[col].textContent.trim();
        const bVal = b.cells[col].textContent.trim();
        const aNum = Number(aVal), bNum = Number(bVal);
        const cmp = (!isNaN(aNum) && !isNaN(bNum))
          ? aNum - bNum
          : aVal.localeCompare(bVal);
        return sortAsc ? cmp : -cmp;
      }});
      rows.forEach(r => tbody.appendChild(r));
    }}

    applyFilters();
  </script>
</body>
</html>"""

    with open(path, "w") as f:
        f.write(html)


def save_results(
    path: str,
    target: str,
    ip: str,
    hostname: str,
    results: list[dict],
    start: datetime,
    end: datetime,
    ports_spec: str = "",
) -> None:
    ext = os.path.splitext(path)[1].lower()

    if ext == ".html":
        save_html(path, target, ip, hostname, results, start, end, ports_spec=ports_spec)
    elif ext == ".csv":
        with open(path, "w", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=["port", "state", "service", "banner"])
            writer.writeheader()
            writer.writerows(results)
    else:
        duration = (end - start).total_seconds()
        open_c = sum(1 for r in results if r["state"] == "open")
        lines = [
            "Port Scan Report",
            "================",
            f"Target   : {target}",
            f"IP       : {ip}",
            f"Hostname : {hostname}",
            f"Started  : {start.strftime('%Y-%m-%d %H:%M:%S')}",
            f"Finished : {end.strftime('%Y-%m-%d %H:%M:%S')}",
            f"Duration : {duration:.2f}s",
            f"Scanned  : {len(results)} ports",
            f"Open     : {open_c}",
            "",
            f"{'PORT':<8}{'STATE':<12}{'SERVICE':<22}BANNER",
            "-" * 70,
        ]
        for r in results:
            lines.append(f"{r['port']:<8}{r['state']:<12}{r['service']:<22}{r['banner']}")
        with open(path, "w") as f:
            f.write("\n".join(lines) + "\n")

    print(f"\n[+] Results saved to: {path}")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="TCP port scanner with service detection",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument("target", help="IP address or hostname to scan")
    parser.add_argument(
        "--ports", "-p",
        default="1-1024",
        help="Port spec: single (80), list (22,80,443), range (1-1024). Default: 1-1024",
    )
    parser.add_argument(
        "-t", "--threads",
        type=int,
        default=200,
        help="Number of concurrent threads (default: 200)",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=1.0,
        help="Connection timeout in seconds (default: 1.0)",
    )
    parser.add_argument(
        "-b", "--banner",
        action="store_true",
        help="Attempt to grab service banners from open ports (slower)",
    )
    parser.add_argument(
        "-o", "--output",
        help="Output file path (.html, .csv, or .txt). Auto-generated .html if omitted.",
    )
    parser.add_argument(
        "--no-save",
        action="store_true",
        help="Do not save results to a file",
    )

    args = parser.parse_args()

    print(BANNER)

    ip, hostname = resolve_host(args.target)
    ports = parse_ports(args.ports)

    print(f"  Target   : {args.target}")
    print(f"  IP       : {ip}")
    print(f"  Hostname : {hostname}")
    print(f"  Ports    : {len(ports)} ({args.ports})")
    print(f"  Threads  : {args.threads}")
    print(f"  Timeout  : {args.timeout}s")
    print(f"  Banners  : {'yes' if args.banner else 'no'}")
    print()
    print(f"  {'PORT':<7} {'STATE':<10} {'SERVICE'}")
    print("  " + "-" * 38)

    all_results: list[dict] = []
    start = datetime.now()

    try:
        with ThreadPoolExecutor(max_workers=args.threads) as pool:
            futures = {
                pool.submit(scan_port, ip, port, args.timeout, args.banner): port
                for port in ports
            }
            completed = 0
            for future in as_completed(futures):
                completed += 1
                result = future.result()
                all_results.append(result)
                if result["state"] == "open":
                    print(f"  {result['port']:<7} {'open':<10} {result['service']}")
                draw_progress(completed, len(ports))
    except KeyboardInterrupt:
        print("\n[!] Scan interrupted by user.", file=sys.stderr)

    end = datetime.now()
    print("\r" + " " * 60 + "\r", end="", file=sys.stderr)

    duration = (end - start).total_seconds()
    all_results.sort(key=lambda r: r["port"])

    open_c     = sum(1 for r in all_results if r["state"] == "open")
    closed_c   = sum(1 for r in all_results if r["state"] == "closed")
    filtered_c = sum(1 for r in all_results if r["state"] == "filtered")

    print()
    print(f"  Scan complete in {duration:.2f}s")
    print(f"  Open: {open_c}  |  Closed: {closed_c}  |  Filtered: {filtered_c}")

    if not args.no_save:
        if args.output:
            out_path = args.output
        else:
            ts = start.strftime("%Y%m%d_%H%M%S")
            safe_target = args.target.replace(".", "_").replace(":", "_")
            out_path = f"scan_{safe_target}_{ts}.html"

        save_results(out_path, args.target, ip, hostname, all_results, start, end, ports_spec=args.ports)


if __name__ == "__main__":
    main()
