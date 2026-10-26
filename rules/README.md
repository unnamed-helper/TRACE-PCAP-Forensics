# rules/

Drop your Suricata-style `*.rules` files here.

- With the Suricata backend, files in this folder are loaded **exclusively** (`-S`) when *Rule source* is *Auto* or *TRACE rules folder*.
- The built-in engine can load this folder too (needs the backend to list/read it) or you can pick files in the dialog.
- `sid`s must be unique across all files.
- Stock Suricata `*-events.rules` work only with real Suricata.

See [../docs/RULES-ENGINE.md](../docs/RULES-ENGINE.md).
