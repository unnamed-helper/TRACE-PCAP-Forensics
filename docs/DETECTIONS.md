# Heuristic detections

Heuristics run in the browser on the decoded capture. They are **leads to verify, not proof**.
Thresholds are taken from the source (`runHeuristics` in `index.html`); severity can rise with volume.

| Finding | Trigger | Severity | Check next |
|---|---|---|---|
| **TCP port scan** | One source opens connections to **≥ 15** distinct ports on a target that got no SYN-ACK (or were reset) | Medium; High at ≥ 100 ports | Source host legitimacy; scanner / vuln-management schedule |
| **Host sweep** | One source probes **≥ 20** hosts on the same service | Medium | Is the source an authorised scanner? |
| **Beaconing** | Repeated connections to one destination with median interval 2 s – 2 h, **≥ 80 %** of intervals within ±20 % of the median | Medium | Destination reputation, process on the source, jitter |
| **DNS tunnelling / DGA** | Many unique names under one parent with long labels (avg ≥ 14), high entropy (≥ 3.3) or mostly text records | Medium | Query content, TXT usage, resolver logs |
| **NXDOMAIN burst** | Per client + parent domain: **≥ 25** NXDOMAIN replies or **≥ 10** unique failed names | Low; Medium at ≥ 30 names or ≥ 100 replies | Malware DGA, misconfiguration, typo storms |
| **Distributed NXDOMAIN pattern** | **≥ 3 clients**, **≥ 50** NXDOMAIN replies, **≥ 25** unique names under one parent (random-subdomain / water-torture style) | Medium; High at ≥ 500 names, ≥ 1000 replies or ≥ 200/s | Authoritative / resolver load, victim zone, source spread |
| **SYN / UDP / ICMP flood pattern** | SYN: ≥ 100 packets from ≥ 3 sources to one target; UDP: ≥ 250 from ≥ 3; ICMP: ≥ 100 from ≥ 2 | Medium; High at ≥ 2000 packets, ≥ 25 sources or ≥ 500 pps | Spoofing, service impact, upstream mitigation |
| **Distributed traffic burst** | In one one-second bucket: **≥ 150** packets to one destination from **≥ 10** distinct sources | Medium; High at ≥ 1500 packets or ≥ 50 sources | Is it a flash crowd or an attack? |
| **Traffic spike** | A one-second bin ≥ 5× the capture average and ≥ 100 packets (needs ≥ 5 one-second bins) | Medium; High at ≥ 10× | What changed at that second? |
| **UDP reflection-port volume** | High volume involving well-known reflection service ports | Medium; High at ≥ 1000 packets | Open resolvers / NTP / memcached |
| **UDP service concentration** | Heavy UDP towards one service port | Medium; High at ≥ 3000 packets or ≥ 40 sources | Same as above |
| **High SYN-ACK volume** | Many SYN-ACKs for one target / port (backscatter) | Low; Medium at ≥ 1500 | Spoofed SYN flood against that host |
| **Cleartext credentials** | FTP / Telnet / POP3 / IMAP / HTTP basic etc. carrying credentials (**type only is shown**) | Medium | Rotate the credential; find the client |
| **Large outbound transfer** | **≥ 25 MiB** one-way with a **≥ 5:1** ratio to the return direction; Medium when the destination is external, otherwise Low | Low / Medium | Data-loss review, destination |
| **Commonly abused port** | Completed TCP exchange with a port such as 4444, 31337, 1337, 6667/6697, 9001/9030, 12345, 5555, 2222 | Low | Service identity |
| **Deprecated TLS version** | A deprecated protocol version offered in a handshake | Low | Client / server config |
| **Large ICMP payloads** (tunnel hint) | ≥ 5 ICMP packets with large payloads | Low | Payload content; ICMP tunnelling tools |
| **ARP spoofing hint** | One IP claimed by more than one MAC address | Medium | DHCP / failover / VRRP before assuming an attack |

Each finding carries a MITRE ATT&CK tag where one applies (for example `T1568.002` for DGA-style DNS).

## Why a heuristic may be wrong

- Legitimate scanners, load tests, monitoring and CDNs look like attacks.
- A short capture can make a normal pattern look periodic or bursty.
- Capture-point bias: you only see what crossed the sensor.

Treat every finding as "open the evidence packets and decide".
