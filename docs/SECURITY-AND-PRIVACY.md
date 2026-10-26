# Security and privacy design

## What "air-gapped" means here

- **No external resources.** No CDN scripts, fonts, analytics or update checks.
- **Content-Security-Policy** (meta tag):
  `default-src 'self' data: blob:; connect-src 'self' http://127.0.0.1:* http://localhost:*; img-src 'self' data: blob:; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'; object-src 'none'; base-uri 'none'; form-action 'none'`
  The only network destination the page may contact is the local backend.
- **Automated check:** the test suite records every request the page makes while loading and analysing captures and fails on anything not local, and fails on any CSP violation.
- **Captures stay in the browser.** Files are read with the File API; payload bytes are re-read from the file, not uploaded.
- **Notes and bookmarks** are autosaved in the browser's local storage on this machine only.

## The optional backend

- Binds to `127.0.0.1` only; rejects requests whose `Host` / `Origin` is not loopback (blocks DNS-rebinding and cross-site requests).
- Writes uploads to a private temp directory and deletes it after each run.
- Runs only the Suricata binary it detected (or `SURICATA_BIN`), with arguments it constructs — user text is never passed to a shell.
- No authentication: it assumes a single-user workstation. **Do not expose it on a network** or change the bind address.

## Handling sensitive data

- Credential detections report the *type* (e.g. "FTP USER/PASS") and never display the secret.
- HTML reports and exports contain what you chose to export — treat them with the same classification as the capture.
- The sample captures are synthetic.

## Known limits

- A browser extension or compromised browser can read whatever the page can. Use a clean profile on sensitive machines.
- CSP `'unsafe-inline'` is required because the app is a single file.
- Rule files you load are trusted input for Suricata; only use rules you trust.

Report vulnerabilities as described in [SECURITY.md](../SECURITY.md).
