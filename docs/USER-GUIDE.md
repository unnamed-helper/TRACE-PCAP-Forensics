# TRACE User Guide

How to go from "I have a capture" to "I know what to look at" in a few minutes.

## 1. Open a capture

- Click **Open capture** or drag one or more `.pcap` / `.pcapng` files onto the page.
- Multiple files are merged into one timeline.
- gzip-compressed files are not opened directly — decompress first. Truncated or corrupt files load what is valid and show a warning banner.
- For very large captures use the **packet limit** in the Open dialog. Packet *metadata* is kept in browser memory; payload bytes are re-read from the file on demand.

## 2. Read the dashboard

The top row shows **Packets, Hosts, Flows, Detections, Data volume, Duration**. Click a card to jump to that tab.

| Panel | Use it to |
|---|---|
| Protocols | See the protocol mix at a glance |
| Top talkers | Spot the hosts moving the most bytes |
| Top conversations | Find the heaviest host pairs |
| Top domains | DNS / HTTP Host / TLS SNI names grouped by parent domain. Click one to see it **and all its subdomains**. Use **NX only** to see names that returned NXDOMAIN |
| Traffic over time | Drag across the chart to filter the packet list to that time window |
| Traffic map | Hosts and links with animated direction arrows. **Replay capture** plays the capture back |

**Traffic over time** and **Traffic map** have **Close / Open** buttons to collapse them when you need screen space.

## 3. Work the tabs

### Packets
Every decoded packet. Use the filter box (syntax in the [README](../README.md#filter-syntax-packets-tab)) or the dropdowns. Click a row to open the **details drawer**: decoded layers, hex dump, follow stream, save payload, **Add to notes** and **Custom note…**.
Change **Rows** at the bottom (25 – 1000) and jump to any page.

### Flows
Bidirectional conversations with state, packets, bytes and duration. Click a flow to open the drawer, then:
- **Filter packet list** — show only that flow's packets.
- **Show flow map** — animated two-node view plus a packet ladder; click a ladder row to open that packet.
- **Add to notes / Custom note…**

### Detections
Suricata, Rules and Heuristic findings together; filter by source and severity. Click a finding for:
- **What was observed** — structured facts, not a raw blob.
- **Evidence** — **Open all evidence packets in Packets tab** applies a view containing exactly those packets.
- **ATT&CK** technique where relevant.

### Hosts
Per-host totals, role (internal / external / multicast), peers and findings. Click a host to **investigate** it (its flows, names, ports, findings).

### Timeline
Detections, DNS lookups, HTTP requests, TLS sessions, cleartext-credential events and long / large connections in time order, filterable by type.

### Protocol logs
Tables for **DNS, HTTP, TLS, NXDOMAIN, Credentials**. The NXDOMAIN log lists every NX name with parent domain, reply count, client count and servers.

## 4. A 10-minute triage workflow

1. **Open the capture**; note the time range and size on the dashboard.
2. **Detections tab** — sort by severity; read the top findings' *What was observed*.
3. For each lead, click **Open all evidence packets** and confirm in the packets (don't trust a threshold).
4. **Top domains** — look for odd parents, high subdomain counts, NX badges. Click through to the packets.
5. **Hosts** — investigate any internal host that is a top talker *and* has findings.
6. **Flows → Show flow map** for the suspicious conversation; confirm direction and timing.
7. **Notes** — add quick or custom notes as you go (they autosave in the browser).
8. **Export** — HTML report or CSV/JSON of exactly what you filtered, plus **IOCs**.

## 5. Running Suricata (optional)

1. Start the backend (`./start.sh` or `START-WINDOWS.bat`) and open <http://127.0.0.1:8765>.
2. Open **Suricata**, click **Check service**.
3. Choose **Rule source**: *Auto*, *TRACE rules folder* or *suricata.yaml*. Optionally paste extra rules and click **Validate rules**.
4. **Run Suricata on loaded capture**. Alerts appear as **Suricata** findings linked to packets/flows.

Harmless engine notes (missing `threshold.config`, `setrlimit`) are hidden and counted; real warnings stay visible under **Engine warnings**.

## 6. Built-in rule engine (no Suricata)

In the same dialog, **Built-in engine**: load the `rules/` folder (needs the backend) or pick / paste `.rules` files, then **Run**. Results appear as **Rules** findings. See [RULES-ENGINE.md](RULES-ENGINE.md) for what is supported.

## 7. Notes, bookmarks, export

- **Add to notes** saves a one-line evidence note; **Custom note…** lets you write your own title and text.
- Star a packet to bookmark it.
- **Export** → filtered packets, all packets, flows, hosts, detections, timeline, protocol logs, IOCs, HTML report, print / PDF.

## Keyboard shortcuts

`/` focus search · `j` / `k` next / previous packet · `b` bookmark · `Esc` close drawer or dialog.
