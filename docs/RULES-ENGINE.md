# Rules in TRACE

There are two engines. Both read standard Suricata-style rule text.

1. **Real Suricata** (optional, via the local backend) — the full rule language, run on the capture file.
2. **TRACE built-in engine** (no Suricata, no backend) — a deliberately small, honest subset that runs in the browser.

## Where rules come from

- The **`rules/`** folder next to `index.html` / `backend.py` (`*.rules`). Point the backend elsewhere with `python backend.py --rules-dir PATH`.
- Rules pasted into the Suricata dialog.
- (Suricata only) the rule files named in your `suricata.yaml`.

With the backend, **Rule source** controls what Suricata loads:

| Rule source | Behaviour |
|---|---|
| Auto | `rules/` folder (+ pasted rules) if the folder has rules; otherwise pasted rules only; otherwise the rules in `suricata.yaml` |
| TRACE `rules/` folder | Loaded exclusively (`-S`): only these rules run |
| `suricata.yaml` | Uses your Suricata's configured rule files (`-s` adds pasted rules) |

Suricata rejects duplicate `sid`s — keep ids unique across the folder and pasted rules.

## Built-in engine: supported

| Area | Keywords |
|---|---|
| Header | protocol, source/destination address and port, direction (`->`, `<>`), `$HOME_NET` / `$EXTERNAL_NET`, port ranges and lists, negation |
| Packet | `flow` (`to_server`, `to_client`, `established`), `flags`, `dsize`, `ttl`, `itype`, `icode`, `urilen` |
| Content | `content` with `nocase`, `depth`, `offset`, `distance`, `within`, `startswith`, `endswith`, `!` negation and `\|hex\|` bytes; `pcre` with `i`, `s`, `m` and relative / buffer flags |
| Buffers | `http.uri` (percent-decoded), `http.uri.raw`, `http.method`, `http.user_agent`, `http.host`, `http.header`, `http.cookie`, `http.request_line`, `http.stat_code`, `http.stat_msg`, `http.content_type`, `dns.query`, `tls.sni`, plus the legacy `http_*` content modifiers |
| Metadata | `msg`, `sid`, `rev`, `classtype`, `priority` |

## Built-in engine: not supported (rule is skipped and listed)

`flowbits`, `flowint`, `byte_test`, `byte_jump`, `app-layer-event`, `decode-event`, `file.*` / `filemagic` / `filestore`, `noalert`, `threshold` / `detection_filter` state, Lua, `datasets`, IP reputation, and other stateful or decoder-specific keywords.

A skipped rule is **never silently ignored**: the run summary shows how many rules are active vs skipped and the reason per rule.

## How matching works

- **Per packet, no TCP reassembly.** A pattern split across two TCP segments will not match.
- Candidate rules are bucketed by protocol and destination port to keep large rule sets fast; payload bytes are read lazily from the file in 8 MB chunks.
- Hits are aggregated **per rule + flow + direction** into one **Rules** finding, with the matching packets as evidence.

## Verification and performance

- On 17 test rules covering the supported keywords, the built-in engine returned the same flows as **real Suricata 7.0.3** (16 rules runnable, 1 skipped for `flowbits`). See `tests/engine_vs_suricata.py`.
- Stock Suricata `*-events.rules`: **373 of 373 skipped** (they depend on Suricata's decoder and app-layer events). Use Suricata for those.
- Speed (headless Chromium, synthetic data): 2,016 rules over a 199,280-packet capture ≈ 1.7 s; 20,000 rules parse in ≈ 0.4 s.

This is a spot check on a small rule set, not a compatibility guarantee. For production detection, run Suricata.

## Writing a rule that works in both engines

```
alert http any any -> any any (msg:"Scanner UA sqlmap"; http.user_agent; content:"sqlmap"; nocase; sid:9100001; rev:1; classtype:web-application-attack; priority:1;)
alert tcp any any -> any 80 (msg:"Admin URI"; flow:established,to_server; http.uri; content:"/admin"; sid:9100002; rev:1;)
```
