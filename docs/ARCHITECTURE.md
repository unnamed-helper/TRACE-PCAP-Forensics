# Architecture

```
            ┌────────────────────────── index.html (browser) ─────────────────────────┐
 .pcap /    │  Streaming reader ─► Decoders ─► Flows/Hosts/Edges ─► Heuristics ─► UI │
 .pcapng ──►│  (File.slice      (L2–L7)     aggregates          findings    tabs │
            │   chunks)                                                map/drawer    │
            │        ▲ raw bytes re-read on demand            Built-in rule engine ──┘
            └────────┼────────────────────────────────────────────────────────────────
                     │  optional, loopback only (127.0.0.1)
            ┌────────┴─────────── backend.py (Python stdlib) ──────────┐
            │  /health  /rules-info  /rules-content  /validate  /analyze │──► suricata -r file -S rules
            └────────────────────────────────────────────────────────────┘     (eve.json → alerts)
```

## Browser side (`index.html`)

- **Reader** — parses pcap / pcapng record headers in chunks; keeps compact per-packet metadata (offsets, lengths, decoded fields) and re-reads raw bytes with `File.slice()` when a packet is opened or a rule needs a payload. Truncated / corrupt files stop cleanly with a warning.
- **Decoders** — Ethernet / VLAN / QinQ / SLL / loopback / raw IP → IPv4 / IPv6 → TCP / UDP / ICMP / ARP / SCTP → DNS, HTTP, TLS, SSH, SMB, RDP and cleartext-credential labelling.
- **Aggregation** — flows (5-tuple + state), hosts (role, peers), edges (host pairs), DNS / HTTP / TLS logs, timeline.
- **Findings** — three sources share one model (`mkFinding`): `Suricata`, `Rules`, `Heuristic`. `rebuildFindings()` merges them; `afterFindingsChange()` refreshes the UI.
- **Views** — a filter language compiles to a predicate over packets; special views (evidence, flow, host, time window) are layered on top. Every table uses one pager (`PGS` / `pagerFill`) so rows-per-page and page jump behave the same everywhere.
- **Built-in rule engine** — parses rules (`reParse`), builds protocol/port buckets, evaluates header → flow → payload buffers per packet, aggregates hits per rule + flow + direction.

## Backend (`backend.py`)

Standard library only. It serves `index.html` and a small JSON API on `127.0.0.1`:

| Endpoint | Purpose |
|---|---|
| `GET /health` | Detect Suricata binary / config / version; report rules folder |
| `GET /rules-info`, `/rules-content` | List and fetch `rules/*.rules` for the UI |
| `POST /validate` | `suricata -T` on the combined rule file; returns per-rule errors with file and line |
| `POST /analyze` | Upload capture (multipart) → run Suricata → parse `eve.json` → alerts |

Behaviours worth knowing:

- Loopback bind, `Host` / `Origin` checks, per-run temp directory deleted afterwards, upload size cap (`--max-upload-mb`), run timeout (`--timeout`).
- Rules from the folder and pasted text are concatenated; errors are mapped back to the original file / line.
- If rules need a protocol disabled in `suricata.yaml` (e.g. `modbus`, `dnp3`), the backend enables just those protocols for the run and retries.
- An empty threshold file is supplied for the run so a missing `threshold.config` does not produce noise; known-harmless warnings are reported separately as notes.
- On Windows, Suricata's folder is added to `PATH` for the child process; common failure exit codes (e.g. `0xC0000135`) are translated into a hint.

## Why a single file?

The goal is "copy one file to a locked-down machine and it works". Everything — markup, CSS, JS, icons — is inline, so there is nothing to fetch and nothing to block.
