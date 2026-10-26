# Install and configure Suricata for TRACE

TRACE can inspect captures without Suricata. Installing Suricata adds the **real Suricata IDS engine** to the local workflow. TRACE does not include, install, or update Suricata for you.

> **Version note:** use a currently supported stable release from the official project. The exact package, paths and service names depend on the operating system and installation method. Official sources: [Suricata downloads](https://suricata.io/download/), [official installation guide](https://docs.suricata.io/en/latest/install.html), and [official quickstart](https://docs.suricata.io/en/latest/quickstart.html).

## 1. Windows 10/11

1. Download the current 64-bit Windows installer from the [official Suricata download page](https://suricata.io/download/). Use the official installer rather than copying individual executable files.
2. Install any prerequisites required by that release. Depending on the build, this can include **Npcap** and the **Microsoft Visual C++ Redistributable (x64)**. Get prerequisites from their official vendor sites and follow your organisation's software approval process.
3. Complete the installer and locate `suricata.exe` and `suricata.yaml`. TRACE checks common install locations, but custom installations may need explicit paths.
4. Open PowerShell or Command Prompt and verify the binary:

   ```powershell
   suricata.exe -V
   ```

   If the command is not on `PATH`, run it using the full path to `suricata.exe`.
5. If TRACE cannot discover the executable or configuration, set the paths **before** starting TRACE:

   ```powershell
   $env:SURICATA_BIN = 'C:\Program Files\Suricata\suricata.exe'
   $env:SURICATA_CONFIG = 'C:\Program Files\Suricata\suricata.yaml'
   .\START-WINDOWS.bat
   ```

   Replace the example paths with the paths that exist on your system. Keep the terminal open while using TRACE.

## 2. Ubuntu

The Open Information Security Foundation (OISF) maintains a stable PPA. Review the [official Ubuntu installation guidance](https://docs.suricata.io/en/latest/install.html) first, especially on managed or air-gapped hosts.

```bash
sudo apt-get update
sudo apt-get install software-properties-common
sudo add-apt-repository ppa:oisf/suricata-stable
sudo apt-get update
sudo apt-get install suricata
suricata -V
```

Install/update an available ruleset where policy permits:

```bash
sudo suricata-update
```

Common package paths are `/etc/suricata/suricata.yaml` and `/var/lib/suricata/rules/`, but confirm them for your package. For Debian or other distributions, use the [official installation documentation](https://docs.suricata.io/en/latest/install.html) and the distribution's supported package instructions rather than assuming Ubuntu paths.

## 3. macOS, Debian and RPM-based Linux

Use the official [Suricata installation guide](https://docs.suricata.io/en/latest/install.html) and choose the section for your operating system. Package availability and configuration paths vary. Do not copy commands for one distribution into another without checking the official instructions.

## 4. Verify configuration and rules

Find the `suricata.yaml` path from your install. Validate the configuration before using it:

```bash
suricata -T -c /path/to/suricata.yaml
```

On Windows, use `suricata.exe` and the real Windows path. If your install requires a rule file to be explicitly selected, test that file according to the official documentation. To fetch/manage the Emerging Threats Open ruleset on supported package installations, use `suricata-update` when internet access and your organisation's policy allow it. **An air-gapped system can use only rules that have been securely transferred to it.**

## 5. Start TRACE with the optional backend

From the extracted repository folder:

- **Windows:** double-click `START-WINDOWS.bat`, or start it from a terminal.
- **Linux/macOS:** run `./start.sh` (if needed, run `chmod +x start.sh` first).
- **Manual:** run `python backend.py`.

Then open [http://127.0.0.1:8765](http://127.0.0.1:8765). In TRACE:

1. Open **Suricata**.
2. Select **Check service** to verify TRACE can run the local engine.
3. Choose a rule source: automatic detection, the repository's `rules/` directory, or the rules configured in `suricata.yaml`.
4. Optionally add trusted custom rules and validate them.
5. Load a PCAP/PCAPNG capture and choose **Run Suricata on loaded capture**.
6. Review findings and open the linked packet/flow evidence. Treat alerts as evidence to investigate, not an automatic verdict.

The optional backend binds to loopback (`127.0.0.1`) and is intended for a single analyst on the same workstation. **Do not expose it to a LAN or the public internet.** Do not change the bind address to `0.0.0.0`.

## 6. What Suricata adds—and what it does not

- Suricata evaluates packets against the rules and protocol decoders supported by your installed Suricata version and configured rule set.
- TRACE's built-in rule engine remains available without Suricata, but supports only a subset of the Suricata rule language; see [RULES-ENGINE.md](RULES-ENGINE.md).
- Suricata alerts depend on enabled rules, configuration, protocol visibility and the capture contents. No alert does not prove a capture is benign.
- Encrypted application payloads are not decrypted by TRACE. TLS metadata may still be available.
- Installing Suricata alone does not guarantee a useful ruleset is installed or current. Confirm rule source and validation status.

## 7. Troubleshooting

- **TRACE says Suricata not found:** run `suricata -V` (or `suricata.exe -V`), set `SURICATA_BIN`, and restart the backend.
- **Configuration not found:** set `SURICATA_CONFIG` to the actual `suricata.yaml` path and restart the backend.
- **Rule errors:** validate the config and rule file with the installed Suricata version; third-party rules may use keywords or protocol features not available in an older engine.
- **Windows DLL/launch errors:** install the supported official build and its required x64 prerequisites; avoid mixing files from different architectures or releases.
- **No findings:** confirm the selected rule source, that rules are loaded, and that the traffic in the capture matches enabled signatures. Also review TRACE's separate Heuristic and Rules finding sources.
- **Air-gapped host:** download installers and rule updates on an approved connected machine, verify them, then transfer them using your organisation's controlled process. Do not expect the app to fetch updates itself.

For platform-specific details, use the [official Suricata docs](https://docs.suricata.io/en/latest/) and [troubleshooting guide](TROUBLESHOOTING.md).
