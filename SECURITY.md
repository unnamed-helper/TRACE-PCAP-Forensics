# Security policy

## Reporting a vulnerability

Please **do not open a public issue** for security problems. Use GitHub's *Report a vulnerability* (Security tab → Advisories) on this repository, or contact the maintainer privately.

Include: what you found, steps to reproduce, affected version / commit, and the impact you expect. You'll get an acknowledgement and a fix plan as soon as the maintainer can respond.

## Scope

- `index.html` (CSP bypass, XSS via crafted packet content, data exfiltration paths)
- `backend.py` (non-loopback exposure, path traversal, command injection, upload handling)

## Out of scope

- Detection quality (false positives / negatives) — open a normal issue.
- Vulnerabilities in Suricata itself — report them to the Suricata project.

## Design notes

See [docs/SECURITY-AND-PRIVACY.md](docs/SECURITY-AND-PRIVACY.md). The backend has no authentication and is meant for a single-user workstation on loopback.
