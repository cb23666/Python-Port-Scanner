[README.md](https://github.com/user-attachments/files/28276953/README.md)
# Python Port Scanner

![Python](https://img.shields.io/badge/Python-3.10%2B-blue?logo=python&logoColor=white)
![Platform](https://img.shields.io/badge/Platform-macOS%20%7C%20Linux%20%7C%20Windows-lightgrey)
![License](https://img.shields.io/badge/License-MIT-green)
![Zero Dependencies](https://img.shields.io/badge/Dependencies-None-brightgreen)

A fast, multithreaded TCP port scanner with service detection, banner grabbing, and exportable reports — built entirely with Python's standard library.

---

## Features

- **Multithreaded scanning** — up to 500 concurrent threads for full 65535-port scans in seconds
- **Port state detection** — distinguishes `open`, `closed`, and `filtered` ports
- **Service name resolution** — built-in table of 60+ well-known services with OS fallback
- **Banner grabbing** — optionally reads the first response line from open ports (`-b`)
- **Flexible port targeting** — single ports, comma-separated lists, ranges, or mixed
- **Three export formats** — HTML report, CSV, and plain text
- **Interactive HTML report** — filterable, sortable, searchable with one-click JSON export
- **Live progress bar** — real-time terminal feedback during scanning
- **Zero dependencies** — standard library only, no `pip install` required

---

## Requirements

- Python 3.10 or higher
- No third-party packages

---

## Usage

```
python3 port_scanner.py <target> [options]
```

### Arguments

| Argument | Description |
|---|---|
| `target` | IP address or hostname to scan |

### Options

| Flag | Default | Description |
|---|---|---|
| `--ports`, `-p` | `1-1024` | Port specification (see examples below) |
| `--threads`, `-t` | `200` | Number of concurrent threads |
| `--timeout` | `1.0` | Per-port connection timeout in seconds |
| `--banner`, `-b` | off | Grab service banners from open ports |
| `--output`, `-o` | auto `.html` | Output file path (`.html`, `.csv`, or `.txt`) |
| `--no-save` | off | Skip saving results to a file |

---

## Examples

**Scan default ports (1–1024) on a host:**
```bash
python3 port_scanner.py 192.168.1.1
```

**Scan all 65535 ports:**
```bash
python3 port_scanner.py 192.168.1.1 --ports 1-65535 -t 500
```

**Scan specific ports:**
```bash
python3 port_scanner.py 192.168.1.1 --ports 22,80,443,8080,8443
```

**Mix ranges and individual ports:**
```bash
python3 port_scanner.py 192.168.1.1 --ports 1-1024,3306,5432,6379,27017
```

**Grab banners and export as HTML:**
```bash
python3 port_scanner.py 192.168.1.1 --ports 1-1024 -b -o report.html
```

**Export results as CSV:**
```bash
python3 port_scanner.py 192.168.1.1 -o results.csv
```

**Scan without saving output:**
```bash
python3 port_scanner.py 192.168.1.1 --no-save
```

---

## Output

### Terminal

```
╔══════════════════════════════╗
║        Python Port Scanner        ║
╚══════════════════════════════╝

  Target   : 192.168.1.1
  IP       : 192.168.1.1
  Hostname : router.local
  Ports    : 1024 (1-1024)
  Threads  : 200
  Timeout  : 1.0s
  Banners  : no

  PORT    STATE      SERVICE
  --------------------------------------
  22      open       ssh
  80      open       http
  443     open       https

  [██████████████████████████████████████] 100.0%  1024/1024 ports

  Scan complete in 2.31s
  Open: 3  |  Closed: 1018  |  Filtered: 3
```

### HTML Report

The HTML report (default output) opens in any browser and includes:

- **Summary cards** — target IP, hostname, scan duration, open / closed / filtered counts
- **Filter buttons** — instantly show only Open, Closed, or Filtered rows
- **Live search** — filter by port number or service name as you type
- **Sortable columns** — click any column header to sort ascending or descending
- **Color-coded rows** — green (open), red (closed), orange (filtered)
- **Export JSON button** — downloads the full scan results as a structured `.json` file

### JSON Export (from HTML)

Clicking **Export JSON** in the HTML report downloads a structured file:

```json
{
  "meta": {
    "target": "192.168.1.1",
    "ip": "192.168.1.1",
    "hostname": "router.local",
    "ports_spec": "1-1024",
    "started": "2026-05-26T12:00:00",
    "finished": "2026-05-26T12:00:02",
    "duration_seconds": 2.31,
    "total_scanned": 1024,
    "open": 3,
    "closed": 1018,
    "filtered": 3
  },
  "results": [
    { "port": 22, "state": "open", "service": "ssh", "banner": "SSH-2.0-OpenSSH_9.0" },
    { "port": 80, "state": "open", "service": "http", "banner": "" },
    ...
  ]
}
```

---

## Port States

| State | Meaning |
|---|---|
| `open` | Port accepted the connection — a service is listening |
| `closed` | Port actively rejected the connection (TCP RST) — no service, but host is reachable |
| `filtered` | No response within the timeout — likely blocked by a firewall |

---

## Performance Tips

| Scenario | Recommended flags |
|---|---|
| Quick scan (top 1024) | default settings |
| Full scan (all 65535) | `--ports 1-65535 -t 500` |
| Slow/remote target | `--timeout 2.0 -t 100` |
| Fast local network | `--timeout 0.5 -t 500` |

---

## Legal Notice

Only scan hosts you own or have **explicit written permission** to test. Unauthorized port scanning may violate computer fraud laws in your jurisdiction. This tool is intended for network administrators, security professionals, and authorized penetration testers.

---

## License

MIT — see [LICENSE](LICENSE) for details.
