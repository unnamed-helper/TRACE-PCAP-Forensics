# Troubleshooting

## Suricata exits with code `3221225781` (0xC0000135) on Windows
A required DLL could not be found when Suricata started. Fix:
- Reinstall Suricata with the official installer (it ships the runtime files it needs) and install the **Npcap** runtime it asks for.
- Make sure Suricata's install folder (default `C:\Program Files\Suricata`) is on `PATH`, or set `SURICATA_BIN` / `SURICATA_CONFIG`.
- Run `suricata -V` in a terminal; if that fails, the problem is the installation, not TRACE.

## `protocol "modbus" cannot be used in a signature` (also `dnp3`)
Those protocols are disabled in the default `suricata.yaml`. TRACE detects this, enables only the named protocols for that run and retries; the run summary lists what it enabled. To make it permanent, enable them under `app-layer.protocols` in your config.

## Warnings: `threshold.config: No such file or directory`, `setrlimit unavailable`
Harmless for analysing a capture. TRACE gives Suricata an empty threshold file for the run and hides known-harmless notes (it shows a count). Real warnings stay under **Engine warnings**.

## `Duplicate signature` / rules rejected
Every `sid` must be unique across the `rules/` folder and pasted rules. The rule-problems list shows the file and line.

## "No rules loaded" / zero alerts
- Zero alerts only means no enabled rule matched.
- Check **Rule source** and the rule count in the run summary.
- Stock `*-events.rules` need Suricata's decoder; the built-in engine skips them.

## The page says "IDS not checked"
The Suricata features need the backend. Start `./start.sh` / `START-WINDOWS.bat` and open <http://127.0.0.1:8765> (or click **Check service** with the right address). Opening `index.html` directly works for everything else.

## A capture will not open
- gzip-compressed: decompress it first.
- Truncated / corrupt: TRACE loads what is valid and shows a warning.
- Not a pcap / pcapng: other formats (e.g. Netmon `.cap`) must be converted (`editcap -F pcapng in.cap out.pcapng`).

## Big captures are slow or the tab runs out of memory
Use the **packet limit** in the Open dialog, or split the file first (`editcap -c 500000 big.pcap part.pcap`). Packet metadata is kept in memory.

## Rows per page doesn't seem to apply
Use the **Rows** selector under each table (25 – 1000). Filters reset to page 1 by design.
