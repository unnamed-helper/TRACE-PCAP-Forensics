#!/usr/bin/env python3
"""TRACE local backend - optional Suricata bridge.  Python 3.8+, standard library only.

Binds to 127.0.0.1 only.  Nothing leaves the machine: captures are written to a private temp dir,
run through the locally installed Suricata, and deleted afterwards.

  python backend.py                 -> http://127.0.0.1:8765  (also serves index.html)
  python backend.py --port 9000 --max-upload-mb 8192
  env: SURICATA_BIN, SURICATA_CONFIG
"""
import argparse, json, os, re, shutil, subprocess, sys, tempfile, time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

HERE = os.path.dirname(os.path.abspath(__file__))
CFG = {"max_upload": 4 * 1024 ** 3, "timeout": 1800}
WIN_DIRS = [r"C:\Program Files\Suricata", r"C:\Program Files (x86)\Suricata", r"C:\Suricata"]
CFG_CANDIDATES = ["/etc/suricata/suricata.yaml", "/usr/local/etc/suricata/suricata.yaml",
                  "/opt/homebrew/etc/suricata/suricata.yaml", "/opt/suricata/etc/suricata/suricata.yaml"]


def find_binary():
    b = os.environ.get("SURICATA_BIN")
    if b and os.path.exists(b):
        return b
    w = shutil.which("suricata") or shutil.which("suricata.exe")
    if w:
        return w
    for d in WIN_DIRS:
        p = os.path.join(d, "suricata.exe")
        if os.path.exists(p):
            return p
    return None


def find_config(binary):
    c = os.environ.get("SURICATA_CONFIG")
    if c and os.path.exists(c):
        return c
    if binary:
        d = os.path.dirname(binary)
        for p in (os.path.join(d, "suricata.yaml"), os.path.join(d, "..", "etc", "suricata.yaml")):
            if os.path.exists(p):
                return os.path.abspath(p)
    for p in CFG_CANDIDATES:
        if os.path.exists(p):
            return p
    return None


WIN_CODES = {
    0xC0000135: ("a required DLL was not found (STATUS_DLL_NOT_FOUND, 0xC0000135)",
                 "Suricata could not start because a Windows DLL it depends on is missing. Fix: (1) install Npcap from https://npcap.com "
                 "with the 'WinPcap API-compatible mode' option ticked (provides wpcap.dll/Packet.dll); (2) install the Microsoft Visual C++ "
                 "Redistributable 2015-2022 (x64); (3) run the official Suricata MSI installer instead of copying files; "
                 "then test in a terminal: cd to the Suricata folder and run  suricata.exe -V"),
    0xC000007B: ("bad image / 32-bit vs 64-bit mismatch (0xC000007B)",
                 "Install the x64 versions of Npcap and the Visual C++ Redistributable that match your Suricata build."),
    0xC0000005: ("Suricata crashed with an access violation (0xC0000005)",
                 "Re-run with a different capture to see whether it is file-specific; update Suricata; check the suricata.yaml for unsupported settings."),
    0xC0000409: ("Suricata aborted (0xC0000409)", "Check suricata.yaml and the rules; run suricata.exe -T -c <config> in a terminal for details."),
}


def explain_exit(code):
    """Map a Windows NTSTATUS exit code (signed or unsigned) to (message, hint), else None."""
    if code is None:
        return None
    return WIN_CODES.get(code & 0xFFFFFFFF) if (code < 0 or code > 255) else None


def child_env(binary):
    """Environment for Suricata: on Windows make sure its own folder and the Npcap folder are on PATH so DLLs resolve."""
    env = dict(os.environ)
    if os.name == "nt" and binary:
        extra = [os.path.dirname(os.path.abspath(binary)),
                 os.path.join(os.environ.get("SystemRoot", r"C:\Windows"), "System32", "Npcap"),
                 os.path.join(os.environ.get("SystemRoot", r"C:\Windows"), "System32")]
        env["PATH"] = os.pathsep.join([p for p in extra if os.path.isdir(p)] + [env.get("PATH", "")])
    return env


def probe(binary):
    """Run `suricata -V`; returns (ok, version_or_message, hint)."""
    try:
        o = subprocess.run([binary, "-V"], capture_output=True, text=True, timeout=30, env=child_env(binary),
                           cwd=os.path.dirname(os.path.abspath(binary)) or None)
    except Exception as e:
        return False, "could not execute: %s" % e, None
    if o.returncode != 0:
        ex = explain_exit(o.returncode)
        return False, ex[0] if ex else "exit code %s" % o.returncode, ex[1] if ex else tail(o.stderr or o.stdout, 400)
    m = re.search(r"(\d+\.\d+[\.\d\w-]*)", o.stdout + o.stderr)
    return True, (m.group(1) if m else (o.stdout or o.stderr).strip()[:60]), None


def version(binary):
    return probe(binary)[1]


def tail(s, n=4000):
    s = s or ""
    return s[-n:]


RULES_DIR = os.path.join(HERE, "rules")


def list_rule_files():
    """*.rules files in the TRACE rules folder (copied there by the analyst)."""
    try:
        names = sorted(n for n in os.listdir(RULES_DIR) if n.lower().endswith(".rules"))
    except OSError:
        return []
    out = []
    for n in names:
        p = os.path.join(RULES_DIR, n)
        try:
            txt = open(p, encoding="utf-8", errors="replace").read()
        except OSError:
            continue
        cnt = sum(1 for l in txt.splitlines() if l.strip() and not l.lstrip().startswith("#"))
        out.append({"name": n, "path": p, "size": len(txt), "rules": cnt})
    return out


def build_rules_file(dest, custom_text, use_folder):
    """Concatenate TRACE\\rules\\*.rules + custom rules into one file; returns (path, sources) where
    sources maps line ranges back to the file they came from (so errors can name the right file)."""
    sources, lines = [], []
    if use_folder:
        for f in list_rule_files():
            body = open(f["path"], encoding="utf-8", errors="replace").read().splitlines()
            sources.append((len(lines) + 1, len(lines) + len(body), f["name"]))
            lines += body
    if custom_text and custom_text.strip():
        body = custom_text.strip().splitlines()
        sources.append((len(lines) + 1, len(lines) + len(body), "custom (pasted rules)"))
        lines += body
    if not lines:
        return None, sources
    open(dest, "w", encoding="utf-8").write("\n".join(lines) + "\n")
    return dest, sources


def source_of(line_no, sources):
    for a, b, n in sources:
        if a <= line_no <= b:
            return n, line_no - a + 1
    return "rules", line_no


def parse_rule_errors(text, sources):
    """Return [{file, line, error, rule}] for every rule Suricata refused to load."""
    out, last = [], ""
    for l in text.splitlines():
        m = re.search(r"(?:Error|<Error>|E):\s*(detect-parse:.*)", l)
        if m:
            last = m.group(1).strip()
        m = re.search(r'error parsing signature "(.*)" from file (.+?) at line (\d+)', l)
        if m:
            path, ln = m.group(2), int(m.group(3))
            if os.path.basename(path.replace("\\\\", "/")).startswith("trace_rules"):
                f, ln = source_of(ln, sources)
            else:
                f = os.path.basename(path.replace("\\\\", "/"))
            out.append({"file": f, "line": ln, "error": last[:300], "rule": m.group(1)[:240]})
    return out


BENIGN = (r"setrlimit", r"threshold-config", r"threshold\.config", r"unable to (?:set|raise) .*(?:rlimit|limit)",
          r"Running in live mode.*(?:ignored)", r"no (?:valid )?(?:default )?(?:log|logging) ?(?:output|directory)?.*stats")


def is_benign(line):
    """Warnings that appear on a normal Windows run and do not affect the analysis of a pcap."""
    return any(re.search(b, line, re.I) for b in BENIGN)


def run_suricata(binary, cfg, pcap, rules_path, logdir, validate_only=False, exclusive=True):
    """Run Suricata.  If rules use a protocol whose detection is disabled in suricata.yaml (e.g. modbus, dnp3 on a
    default Windows install) enable just those protocols for this run and try again - up to 3 passes."""
    enabled = []
    for _ in range(4):
        cmd = [binary, "-v"]
        if cfg:
            cmd += ["-c", cfg]
        for pr in enabled:
            cmd += ["--set", "app-layer.protocols.%s.enabled=yes" % pr]
        # A default Windows install points threshold-file at a path that does not exist ("threshold.config: No such
        # file") - give Suricata an empty one for this run so the warning (and its noise) goes away.
        try:
            th = os.path.join(logdir, "trace-threshold.config")
            open(th, "a").close()
            cmd += ["--set", "threshold-file=" + th]
        except OSError:
            pass
        if validate_only:
            cmd += ["-T"]
        else:
            cmd += ["-r", pcap, "-l", logdir, "-k", "none"]
        if rules_path:
            cmd += ["-S" if exclusive else "-s", rules_path]
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=CFG["timeout"], cwd=logdir, env=child_env(binary))
        err = (p.stderr or "") + "\n" + (p.stdout or "")
        need = [x for x in dict.fromkeys(re.findall(r'protocol "([\w-]+)" cannot be used in a signature', err)) if x not in enabled]
        if not need:
            break
        enabled += need
    p.enabled_protocols = enabled
    return p


SEV = {1: "High", 2: "Medium", 3: "Low"}


def parse_eve(path):
    alerts, counts = [], {}
    if not os.path.exists(path):
        return alerts, counts
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        for line in f:
            try:
                e = json.loads(line)
            except ValueError:
                continue
            t = e.get("event_type", "?")
            counts[t] = counts.get(t, 0) + 1
            if t != "alert":
                continue
            a = e.get("alert", {})
            alerts.append({
                "timestamp": e.get("timestamp"), "src_ip": e.get("src_ip"), "src_port": e.get("src_port"),
                "dest_ip": e.get("dest_ip"), "dest_port": e.get("dest_port"), "proto": e.get("proto"),
                "app_proto": e.get("app_proto"), "flow_id": e.get("flow_id"),
                "signature": a.get("signature"), "signature_id": a.get("signature_id"), "rev": a.get("rev"),
                "category": a.get("category"), "severity": a.get("severity"),
                "severity_label": SEV.get(a.get("severity"), "Medium"), "action": a.get("action"),
                "metadata": a.get("metadata"), "http": e.get("http"), "tls": e.get("tls"), "dns": e.get("dns"),
            })
    return alerts, counts


def parse_multipart(rfile, ctype, length, tmpdir):
    """Streaming multipart/form-data parser (no `cgi`, which is removed in 3.13).
    Files go to disk, small text fields stay in memory."""
    m = re.search(r'boundary=(?:"([^"]+)"|([^;]+))', ctype)
    if not m:
        raise ValueError("missing multipart boundary")
    boundary = (m.group(1) or m.group(2)).encode()
    delim = b"\r\n--" + boundary
    buf = b"\r\n"  # first boundary has no leading CRLF; prepend one so delim matches
    remaining = length
    fields, files = {}, {}
    state = "preamble"
    cur = None
    CH = 1 << 20

    def read_more():
        nonlocal remaining
        if remaining <= 0:
            return b""
        d = rfile.read(min(CH, remaining))
        remaining -= len(d)
        return d

    while True:
        if state == "preamble":
            i = buf.find(delim)
            if i < 0:
                d = read_more()
                if not d:
                    raise ValueError("malformed multipart (no boundary)")
                buf += d
                continue
            buf = buf[i + len(delim):]
            state = "after_boundary"
        elif state == "after_boundary":
            while len(buf) < 2:
                d = read_more()
                if not d:
                    raise ValueError("malformed multipart")
                buf += d
            if buf[:2] == b"--":
                break
            buf = buf[2:] if buf[:2] == b"\r\n" else buf
            state = "headers"
        elif state == "headers":
            i = buf.find(b"\r\n\r\n")
            if i < 0:
                d = read_more()
                if not d:
                    raise ValueError("malformed multipart headers")
                buf += d
                continue
            hdr = buf[:i].decode("utf-8", "replace")
            buf = buf[i + 4:]
            nm = re.search(r'name="([^"]*)"', hdr)
            fn = re.search(r'filename="([^"]*)"', hdr)
            name = nm.group(1) if nm else ""
            if fn is not None:
                path = os.path.join(tmpdir, "up_%s.bin" % re.sub(r"\W", "_", name))
                cur = {"name": name, "fh": open(path, "wb"), "path": path, "filename": fn.group(1), "file": True}
            else:
                cur = {"name": name, "data": bytearray(), "file": False}
            state = "body"
        elif state == "body":
            i = buf.find(delim)
            if i >= 0:
                chunk, buf = buf[:i], buf[i + len(delim):]
                (cur["fh"].write(chunk) if cur["file"] else cur["data"].extend(chunk))
                if cur["file"]:
                    cur["fh"].close()
                    files[cur["name"]] = cur
                else:
                    fields[cur["name"]] = bytes(cur["data"]).decode("utf-8", "replace")
                cur = None
                state = "after_boundary"
            else:
                keep = len(delim) + 4
                if len(buf) > keep:
                    chunk, buf = buf[:-keep], buf[-keep:]
                    (cur["fh"].write(chunk) if cur["file"] else cur["data"].extend(chunk))
                d = read_more()
                if not d:
                    raise ValueError("upload ended early")
                buf += d
    return fields, files


class H(BaseHTTPRequestHandler):
    server_version = "TRACE-backend"
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt, *a):
        sys.stderr.write("[%s] %s\n" % (time.strftime("%H:%M:%S"), fmt % a))

    # ---- security: loopback Host only (blocks DNS-rebinding), reject foreign web Origins
    def _ok_origin(self):
        host = (self.headers.get("Host") or "").split(":")[0].strip("[]").lower()
        if host not in ("127.0.0.1", "localhost", "::1"):
            return False
        o = self.headers.get("Origin")
        if o and o != "null":
            h = re.sub(r"^https?://", "", o).split(":")[0].strip("[]").lower()
            if h not in ("127.0.0.1", "localhost", "::1"):
                return False
        return True

    def _send(self, code, obj=None, raw=None, ctype="application/json"):
        body = raw if raw is not None else json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        o = self.headers.get("Origin")
        if o:
            self.send_header("Access-Control-Allow-Origin", o)  # only reached for loopback/null origins
            self.send_header("Vary", "Origin")
        self.end_headers()
        self.wfile.write(body)

    def do_OPTIONS(self):
        if not self._ok_origin():
            return self._send(403, {"ok": False, "error": "forbidden origin"})
        self.send_response(204)
        o = self.headers.get("Origin")
        if o:
            self.send_header("Access-Control-Allow-Origin", o)
        self.send_header("Access-Control-Allow-Methods", "GET,POST,OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.send_header("Content-Length", "0")
        self.end_headers()

    def do_GET(self):
        if not self._ok_origin():
            return self._send(403, {"ok": False, "error": "forbidden origin"})
        path = self.path.split("?")[0]
        if path in ("/", "/index.html"):
            f = os.path.join(HERE, "index.html")
            if not os.path.exists(f):
                f = os.path.join(HERE, "dist", "index.html")
            if os.path.exists(f):
                return self._send(200, raw=open(f, "rb").read(), ctype="text/html; charset=utf-8")
            return self._send(404, {"ok": False, "error": "index.html not found next to backend.py"})
        if path in ("/rules-info", "/rules-content"):
            fl = list_rule_files()
            if path == "/rules-info":
                return self._send(200, {"ok": True, "dir": RULES_DIR, "files": [{"name": f["name"], "rules": f["rules"], "size": f["size"]} for f in fl]})
            return self._send(200, {"ok": True, "dir": RULES_DIR, "files": [{"name": f["name"], "text": open(f["path"], encoding="utf-8", errors="replace").read()} for f in fl]})
        if path == "/health":
            b = find_binary()
            c = find_config(b) if b else None
            hint = None
            if not b:
                hint = "Suricata not found. Install it (https://suricata.io/download/) or set SURICATA_BIN."
            elif not c:
                hint = "suricata.yaml not found. Set SURICATA_CONFIG to its full path."
            runnable, vmsg = True, None
            if b:
                runnable, vmsg, vhint = probe(b)
                if not runnable:
                    hint = "Suricata was found but cannot start: %s. %s" % (vmsg, vhint or "")
            return self._send(200, {"ok": True, "suricata": bool(b and c and runnable), "binary": b, "config": c,
                                    "version": (vmsg if runnable else None), "hint": hint, "rules_dir": RULES_DIR, "rule_files": len(list_rule_files()), "rules_count": sum(f["rules"] for f in list_rule_files()),
                                    "max_upload_mb": CFG["max_upload"] // 1024 ** 2})
        self._send(404, {"ok": False, "error": "not found"})

    def do_POST(self):
        if not self._ok_origin():
            return self._send(403, {"ok": False, "error": "forbidden origin"})
        path = self.path.split("?")[0]
        try:
            length = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            length = 0
        if path == "/validate":
            return self._validate(length)
        if path != "/analyze":
            return self._send(404, {"ok": False, "error": "not found"})
        if length <= 0:
            return self._send(411, {"ok": False, "error": "Content-Length required"})
        if length > CFG["max_upload"]:
            return self._send(413, {"ok": False, "error": "Upload larger than limit (%d MB). Restart backend with --max-upload-mb." % (CFG["max_upload"] // 1024 ** 2)})
        b = find_binary()
        cfg = find_config(b) if b else None
        if not b or not cfg:
            return self._send(200, {"ok": False, "error": "Suricata is not available.", "hint": "Install Suricata or set SURICATA_BIN / SURICATA_CONFIG.", "binary": b, "config": cfg})
        tmp = tempfile.mkdtemp(prefix="trace_")
        try:
            fields, files = parse_multipart(self.rfile, self.headers.get("Content-Type", ""), length, tmp)
            if "capture" not in files:
                return self._send(400, {"ok": False, "error": "No 'capture' file in upload."})
            pcap = files["capture"]["path"]
            logdir = os.path.join(tmp, "logs")
            os.makedirs(logdir)
            rules = (fields.get("rules") or "").strip()
            if "rules" in files:
                rules = open(files["rules"]["path"], encoding="utf-8", errors="replace").read().strip()
            folder = list_rule_files()
            src_mode = (fields.get("source") or "auto").lower()          # auto | trace | suricata
            use_folder = bool(folder) and src_mode in ("auto", "trace")
            rpath, sources = build_rules_file(os.path.join(tmp, "trace_rules.rules"), rules, use_folder)
            exclusive = True
            if src_mode == "suricata" or (rpath is None):
                exclusive = False        # use the rules configured in suricata.yaml (plus any custom ones)
                if rules:
                    rpath, sources = build_rules_file(os.path.join(tmp, "trace_rules.rules"), rules, False)
            t0 = time.time()
            try:
                p = run_suricata(b, cfg, pcap, rpath, logdir, exclusive=exclusive)
            except subprocess.TimeoutExpired:
                return self._send(200, {"ok": False, "error": "Suricata timed out after %d s." % CFG["timeout"]})
            el = time.time() - t0
            alerts, counts = parse_eve(os.path.join(logdir, "eve.json"))
            err = (p.stderr or "") + "\n" + (p.stdout or "")
            all_w = [l.strip() for l in err.splitlines() if re.search(r"(<(Warning|Error)>|^\s*(E|W|Error|Warning):)", l)]
            warnings = [l for l in all_w if not is_benign(l)][:30]
            notes = [l for l in all_w if is_benign(l)][:30]
            m = re.search(r"(\d+) rules successfully loaded(?:, (\d+) rules failed)?|(\d+) signatures processed", err)
            loaded = int(m.group(1) or m.group(3)) if m else None
            failed_n = int(m.group(2)) if (m and m.group(2)) else 0
            rule_errors = parse_rule_errors(err, sources)
            custom_err = [e for e in rule_errors if e["file"].startswith("custom")]
            ok = p.returncode == 0
            resp = {"ok": ok, "alerts": alerts, "version": version(b), "returncode": p.returncode,
                    "stderr": tail(p.stderr), "stdout": tail(p.stdout), "event_counts": counts,
                    "rules_loaded": loaded, "rules_failed": failed_n or len(rule_errors), "rule_errors": rule_errors[:50],
                    "enabled_protocols": getattr(p, "enabled_protocols", []),
                    "rules_source": ("TRACE rules folder" + (" + pasted rules" if rules else "")) if (use_folder and exclusive) else ("pasted rules only" if (rpath and exclusive) else "suricata.yaml rule-files" + (" + pasted rules" if rules else "")),
                    "rule_files": [{"name": f["name"], "rules": f["rules"]} for f in folder] if use_folder else [],
                    "elapsed": round(el, 2), "warnings": warnings, "notes": notes, "binary": b, "config": cfg}
            if ok and custom_err:
                resp["ok"] = False
                resp["error"] = "Your pasted rules failed to load: %s (line %d): %s" % (custom_err[0]["file"], custom_err[0]["line"], custom_err[0]["error"])
                resp["hint"] = "Fix the rule syntax (use Validate rules) and run again."
            elif ok and loaded == 0 and rule_errors:
                resp["ok"] = False
                resp["error"] = "No rules could be loaded (%d rejected). First problem: %s: %s" % (len(rule_errors), rule_errors[0]["file"], rule_errors[0]["error"])
                resp["hint"] = "Open the rule problems list below."
            if not ok:
                ex = explain_exit(p.returncode)
                resp["error"] = ("Suricata could not run: " + ex[0]) if ex else "Suricata exited with code %s" % p.returncode
                resp["hint"] = ex[1] if ex else "Check the rule problems / stderr below."
            return self._send(200, resp)
        except ValueError as e:
            return self._send(400, {"ok": False, "error": str(e)})
        except Exception as e:  # noqa
            return self._send(500, {"ok": False, "error": "%s: %s" % (type(e).__name__, e)})
        finally:
            shutil.rmtree(tmp, ignore_errors=True)

    def _validate(self, length):
        try:
            data = json.loads(self.rfile.read(min(length, 2 * 1024 * 1024)) or b"{}")
        except ValueError:
            return self._send(400, {"ok": False, "error": "bad JSON"})
        b = find_binary()
        cfg = find_config(b) if b else None
        if not b:
            return self._send(200, {"ok": False, "error": "Suricata not found."})
        tmp = tempfile.mkdtemp(prefix="trace_v_")
        try:
            folder = list_rule_files()
            use_folder = bool(folder) and (data.get("source") or "auto") in ("auto", "trace")
            rp, sources = build_rules_file(os.path.join(tmp, "trace_rules.rules"), data.get("rules") or "", use_folder)
            if rp is None:
                return self._send(200, {"ok": True, "rules_loaded": 0, "errors": [], "note": "No rules to validate (paste rules or copy .rules files into the TRACE rules folder)."})
            p = run_suricata(b, cfg, None, rp, tmp, validate_only=True)
            err = (p.stderr or "") + "\n" + (p.stdout or "")
            rule_errors = parse_rule_errors(err, sources)
            m = re.search(r"(\d+) rules successfully loaded(?:, (\d+) rules failed)?|(\d+) signatures processed", err)
            msgs = ["%s (line %d): %s" % (e["file"], e["line"], e["error"]) for e in rule_errors]
            if not msgs:
                msgs = [l.strip() for l in err.splitlines() if re.search(r"(<Error>|^\s*(E|Error):)", l)]
            return self._send(200, {"ok": p.returncode == 0 and not rule_errors, "returncode": p.returncode, "errors": msgs[:50],
                                    "enabled_protocols": getattr(p, "enabled_protocols", []),
                                    "rules_loaded": int(m.group(1) or m.group(3)) if m else None, "rules_failed": len(rule_errors), "stderr": tail(err)})
        except Exception as e:  # noqa
            return self._send(200, {"ok": False, "error": str(e)})
        finally:
            shutil.rmtree(tmp, ignore_errors=True)


def main():
    ap = argparse.ArgumentParser(description="TRACE local backend (Suricata bridge)")
    ap.add_argument("--port", type=int, default=8765)
    ap.add_argument("--max-upload-mb", type=int, default=4096)
    ap.add_argument("--timeout", type=int, default=1800, help="Suricata run timeout, seconds")
    ap.add_argument("--rules-dir", default=None, help="folder of .rules files (default: ./rules next to backend.py)")
    a = ap.parse_args()
    global RULES_DIR
    if a.rules_dir:
        RULES_DIR = os.path.abspath(a.rules_dir)
    CFG["max_upload"] = a.max_upload_mb * 1024 ** 2
    CFG["timeout"] = a.timeout
    srv = ThreadingHTTPServer(("127.0.0.1", a.port), H)
    b = find_binary()
    print("TRACE backend  http://127.0.0.1:%d   (loopback only)" % a.port)
    print("Rules   :", RULES_DIR, "(%d file(s))" % len(list_rule_files()))
    print("Suricata:", b or "NOT FOUND (analysis works in the browser; IDS alerts need Suricata)")
    if b:
        print("Config  :", find_config(b) or "NOT FOUND - set SURICATA_CONFIG", "| version", version(b))
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        print("\nbye")


if __name__ == "__main__":
    main()
