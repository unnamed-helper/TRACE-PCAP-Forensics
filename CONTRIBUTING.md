# Contributing

Thanks for helping make TRACE better for the community.

## Ground rules

1. **Stay offline.** No CDN links, remote fonts, analytics or runtime network calls (other than the loopback backend). The test suite fails on any external request.
2. **Stay single-file.** `index.html` must keep working when copied alone to a machine with no internet.
3. **Be honest in the UI and docs.** If something is a heuristic, say so; if a feature is untested on a platform, say so.
4. **Python backend = standard library only.**

## Dev setup

```bash
git clone <your-fork> && cd trace-pcap
pip install -r requirements-dev.txt && playwright install chromium  # test-time only
sudo apt install tcpdump suricata                                   # Linux example; Suricata is optional for base tests
python tests/run_all.py                                             # browser suite; tcpdump is required
python backend.py &  python tests/run_all.py --with-suricata        # adds Suricata comparison and end-to-end tests
```

Regenerate synthetic fixtures with `python tools/make_pcaps.py tests/data` and `python tools/make_nx.py tests/data/nx-flood.pcap` (scapy required).

## Pull requests

- One topic per PR; describe what changed and how you tested it.
- Add or update a test for behaviour changes; paste the `run_all.py` result.
- Update `CHANGELOG.md` and the relevant doc in `docs/`.
- New heuristics: document the trigger and thresholds in `docs/DETECTIONS.md` and add a fixture that triggers (and one that does not).
- Captures in `samples/` and `tests/data/` must be **synthetic or fully sanitised** — never real customer traffic.

## Good first issues

- Windows testing reports for the launcher and Suricata paths.
- More decoders (QUIC, SMB2 detail, Kerberos, LDAP).
- Additional rule-engine keywords (`byte_test`, `flowbits` basics).
- Accessibility and keyboard navigation improvements.
- Translations of the docs.
