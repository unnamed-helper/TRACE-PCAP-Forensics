# Release validation record

This file records the checks performed while preparing the community repository package.

- [x] Archive listing and repository structure reviewed.
- [x] README, user guide, detection guide, architecture, privacy and troubleshooting docs present.
- [x] Suricata install guide added with links to official documentation.
- [x] `backend.py` Python syntax compiled successfully (see package validation command below).
- [ ] Browser test suite: **not passed in the preparation environment** because Playwright's Chromium executable was not installed. Run `playwright install chromium`, then `python tests/run_all.py`.
- [ ] Suricata integration tests: **not run successfully in the preparation environment** because Suricata was not installed. On a test host with Suricata configured, start the backend and run `python tests/run_all.py --with-suricata`.
- [ ] Windows launcher and Windows Suricata integration need testing on Windows.

Do not represent the release as fully tested until the unchecked platform-specific checks are completed.
