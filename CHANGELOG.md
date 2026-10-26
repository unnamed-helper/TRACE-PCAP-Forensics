# Changelog

## 1.0.0 — first public release

### Added
- Single-file offline PCAP / PCAPNG workspace: streaming reader, decoders, flows, hosts, timeline, protocol logs, traffic map with replay.
- Optional local Suricata backend (loopback only) with rule validation and alert-to-packet linking.
- `rules/` folder and **built-in rule engine** (subset of Suricata rule language, no Suricata required).
- DNS / NXDOMAIN analysis: NXDOMAIN burst, distributed NXDOMAIN pattern, every NX name listed, top domains grouped by parent with NX filter, `domain:` and `rcode:` filters.
- Per-flow animated map with packet ladder.
- Structured finding context, evidence buttons that open all related packets, quick and custom notes on findings / flows / packets.
- Collapsible Traffic-over-time and Traffic-map panels.
- Rows-per-page (25 – 1000) and page jump on Packets, Flows, Detections, Hosts, Timeline and Protocol logs.

### Fixed
- Suricata `modbus` / `dnp3` "cannot be used in a signature" errors (protocols auto-enabled for the run).
- Missing `threshold.config` and `setrlimit` warnings no longer surface as errors.
- Clear message and fix hint for Windows exit code `3221225781`.
- Rows-per-page selector in Packets had no effect.
