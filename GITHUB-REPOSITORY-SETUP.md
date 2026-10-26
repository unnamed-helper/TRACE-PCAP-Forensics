# Publish TRACE on GitHub

## Suggested repository details

- **Repository name:** `TRACE-PCAP-Forensics` (or `trace-pcap-forensics`)
- **Short description:** Offline-first PCAP/PCAPNG forensics workbench with flow visualisation, evidence-linked detections, a built-in rule engine and optional local Suricata integration.
- **Suggested topics:** `pcap`, `pcapng`, `network-forensics`, `dfir`, `incident-response`, `suricata`, `cybersecurity`, `offline-tool`, `threat-hunting`
- **Website:** leave blank unless you have a project page.
- **Visibility:** Public only if you are permitted to publish all included code, screenshots, test fixtures and documentation.

## Upload using GitHub's website

1. Sign in to GitHub and create a new repository with the name above. Do not initialise a second README or license if uploading these existing files.
2. Extract the release ZIP locally. Open the `TRACE` folder and upload its **contents**, so `README.md`, `index.html`, `backend.py`, `docs/`, `samples/` and `.github/` are at repository root.
3. Review the commit diff, then commit the files.
4. Open `README.md` in GitHub and confirm screenshots and relative links render.
5. Check **Actions** for the automated workflow. It installs test dependencies and runs browser/Suricata tests in CI; review the result before describing the build as fully tested.
6. Add a GitHub Release after you have tested the exact release on the platforms you claim to support.

## Upload using Git

From the extracted project folder (the folder containing `README.md`):

```bash
git init
git add .
git status
git commit -m "Initial public release of TRACE PCAP Forensics"
git branch -M main
git remote add origin https://github.com/YOUR-USERNAME/trace-pcap-forensics.git
git push -u origin main
```

Replace `YOUR-USERNAME` and the repository name with the actual URL shown by GitHub. Do not publish customer captures, internal rules, credentials, private notes, or sensitive screenshots. The `.gitignore` excludes general PCAP/PCAPNG files while allowing the intentionally bundled synthetic samples and test fixtures. Inspect `git status` before every commit.

## Before you publish

- Confirm you have the right to publish all code and assets.
- Verify the author/copyright line and choose the correct maintainer contact in GitHub settings.
- Read `SECURITY.md` and configure private vulnerability reporting on the repository.
- Test the single-file browser mode separately from the optional backend.
- Test Suricata integration on each platform you claim to support.
- Avoid claiming certification, complete detection, guaranteed multi-GB performance, or zero-risk security.
