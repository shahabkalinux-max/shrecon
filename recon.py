#!/usr/bin/env python3
"""
recon.py - Modular Wide/Narrow recon orchestrator (authorized targets only).

Layers:
  1. Scope guard   (Scope)
  2. Collectors    (wide_collect / narrow_collect) -> wrap subfinder, httpx, katana, gau
  3. Normalize     (normalize_url, dedup)
  4. Scoring       (score_endpoint / score_asset)
  5. Storage+diff  (SQLite; "new since last run")
  6. Report        (Markdown, sorted by score)

Requires (in PATH): subfinder, httpx (ProjectDiscovery), katana, gau
Usage:
  python recon.py wide   --scope scope.json
  python recon.py narrow --scope scope.json --target https://app.example.com
  python recon.py report --scope scope.json
"""
import argparse, fnmatch, json, os, re, shutil, sqlite3, subprocess, sys, time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from urllib.parse import urlparse, parse_qsl, urlunparse

# Ensure ~/go/bin is in PATH for tools installed via go install (katana, naabu, gau, etc.)
_go_bin = os.path.expanduser("~/go/bin")
if os.path.exists(_go_bin) and _go_bin not in os.environ.get("PATH", ""):
    os.environ["PATH"] = f"{_go_bin}:{os.environ.get('PATH', '')}"

DB = "recon.db"

# ---------------------------------------------------------------- tool profiles (tools.json)
# Placeholders in args: {rate} {threads} {conc} {timeout} + per-call vars ({domain} {target} {url} ...)
# The exact token "{headers}" expands to the program's custom headers using header_flag/header_mode.
DEFAULT_TOOLS = {
    "subfinder": {"args": ["-d", "{domain}", "-silent"], "sends_requests": False,
                  "version_cmd": ["-version"]},
    "httpx":     {"args": ["-silent", "-json", "-status-code", "-title", "-tech-detect",
                            "-rl", "{rate}", "-threads", "{threads}", "{headers}"],
                  "sends_requests": True, "header_flag": "-H", "version_cmd": ["-version"]},
    "katana":    {"args": ["-u", "{target}", "-silent", "-d", "3", "-jc", "-rl", "{rate}", "{headers}"],
                  "sends_requests": True, "header_flag": "-H", "version_cmd": ["-version"]},
    "gau":       {"args": ["{domain}"], "sends_requests": False, "version_cmd": ["--version"]},
    "dnsx":      {"args": ["-silent", "-json", "-a", "-cname", "-rl", "{rate}"],
                  "sends_requests": False, "version_cmd": ["-version"]},
    "naabu":     {"args": ["-silent", "-json", "-rate", "{rate}", "-top-ports", "100"],
                  "sends_requests": False, "version_cmd": ["-version"],
                  "_note": "raw TCP, HTTP headers do not apply; gated by allow_portscan in scope.json"},
    "nuclei":    {"args": ["-u", "{url}", "-tags", "{tags}", "-severity", "low,medium,high,critical",
                            "-rl", "{rate}", "-silent", "-jsonl", "{headers}"],
                  "sends_requests": True, "header_flag": "-H", "version_cmd": ["-version"]},
    "arjun":     {"args": ["-u", "{url}", "--stable", "-q", "-oJ", "{out}", "-d", "{delay}", "{headers}"],
                  "sends_requests": True, "header_flag": "--headers", "header_mode": "joined",
                  "version_cmd": ["-h"]},
    "gowitness": {"args": ["scan", "file", "-f", "/dev/stdin", "--threads", "4", "{headers}"],
                  "sends_requests": True, "header_flag": None, "version_cmd": ["version"],
                  "_note": "set header_flag after checking `gowitness scan file -h` for your version"},
    "ffuf":      {"args": ["-u", "{url}/FUZZ", "-w", "{wordlist}", "-mc", "200,204,301,302,307,401,403,405",
                            "-rate", "{rate}", "-t", "{threads}", "-s", "-json", "{headers}"],
                  "sends_requests": True, "header_flag": "-H", "version_cmd": ["-V"]},
    "x8":        {"args": ["-u", "{url}", "-w", "{wordlist}", "--output", "{out}", "{headers}"],
                  "sends_requests": True, "header_flag": "--headers", "header_mode": "repeat",
                  "version_cmd": ["-V"]},
}
TOOLS_FILE = os.getenv("RECON_TOOLS", "tools.json")

def load_tools():
    t = {k: dict(v) for k, v in DEFAULT_TOOLS.items()}
    if os.path.exists(TOOLS_FILE):
        for name, cfg in json.load(open(TOOLS_FILE)).items():
            t.setdefault(name, {}).update({k: v for k, v in cfg.items() if not k.startswith("_")})
    return t

TOOLS = load_tools()

def build(scope, name, **kw):
    """Build argv for a tool from its profile; enforce program headers."""
    t = TOOLS[name]
    v = {"rate": scope.rate, "threads": scope.conc * 5, "conc": scope.conc,
         "timeout": scope.timeout, "delay": max(1, 10 // max(1, scope.rate)), **kw}
    flag, mode = t.get("header_flag"), t.get("header_mode", "repeat")
    if t.get("sends_requests") and scope.headers and not flag:
        msg = f"[!] {name}: custom headers configured but no header_flag in tools.json"
        if scope.strict_headers:
            sys.exit(msg + " (strict_headers=true -> refusing to run)")
        print(msg + " -> running WITHOUT headers")
    bin_name = t.get("bin", name)
    if bin_name == "httpx" and shutil.which("httpx") == "/usr/bin/httpx" and shutil.which("httpx-toolkit"):
        bin_name = "httpx-toolkit"
    elif bin_name == "gau" and not shutil.which("gau") and os.path.exists(os.path.expanduser("~/go/bin/gau")):
        bin_name = os.path.expanduser("~/go/bin/gau")
    argv = [bin_name]
    for a in t["args"]:
        if a == "{headers}":
            if flag and scope.headers:
                items = [f"{k}: {val}" for k, val in scope.headers.items()]
                argv += [flag, "\n".join(items)] if mode == "joined" else \
                        [x for it in items for x in (flag, it)]
            continue
        try:
            argv.append(a.format_map(v))
        except KeyError as e:
            sys.exit(f"[!] tools.json: unknown placeholder {e} in {name} args")
    return argv

def doctor(scope=None):
    for name, t in TOOLS.items():
        b = t.get("bin", name)
        if b == "httpx" and shutil.which("httpx") == "/usr/bin/httpx" and shutil.which("httpx-toolkit"):
            b = "httpx-toolkit"
        elif b == "gau" and not shutil.which("gau") and os.path.exists(os.path.expanduser("~/go/bin/gau")):
            b = os.path.expanduser("~/go/bin/gau")
        path = shutil.which(b)
        ver = "-"
        if path and t.get("version_cmd"):
            try:
                p = subprocess.run([b] + t["version_cmd"], capture_output=True, text=True, timeout=10)
                ver = ((p.stdout + p.stderr).strip().splitlines() or ["?"])[0][:60]
            except Exception:
                ver = "?"
        hdr = ("n/a (passive)" if not t.get("sends_requests") else
               ("yes (" + t["header_flag"] + ")" if t.get("header_flag") else "NO"))
        print(f"{name:10} {'OK ' if path else 'MISSING':8} headers={hdr:14} {ver}")
    if scope is not None:
        print(f"\nheaders from scope: {scope.headers or '(none)'}  strict={scope.strict_headers}")

# ---------------------------------------------------------------- 1. Scope
class Scope:
    """scope.json example:
    {"in_scope": ["*.example.com", "example.com"],
     "out_of_scope": ["admin.example.com", "*.internal.example.com"],
     "rate_limit": 10, "concurrency": 5, "timeout": 300}
    """
    def __init__(self, path):
        with open(path) as fh:
            c = json.load(fh)
        self.inc = [p.lower() for p in c["in_scope"]]
        self.exc = [p.lower() for p in c.get("out_of_scope", [])]
        self.rate = int(c.get("rate_limit", 10))
        self.conc = int(c.get("concurrency", 5))
        self.timeout = int(c.get("timeout", 300))
        self.headers = c.get("headers", {})                 # e.g. {"X-Bug-Bounty": "yourhandle"}
        self.strict_headers = bool(c.get("strict_headers", False))
        self.roots = sorted({p.lstrip("*.") for p in self.inc})   # unique root domains

    def allowed(self, host):
        host = (host or "").lower().split(":")[0]
        if not host:
            return False
        if any(fnmatch.fnmatch(host, p) for p in self.exc):
            return False
        return any(fnmatch.fnmatch(host, p) for p in self.inc)

    def url_allowed(self, url):
        return self.allowed(urlparse(url).hostname)

# ---------------------------------------------------------------- helpers
def run(cmd, timeout, stdin=None):
    try:
        p = subprocess.run(cmd, input=stdin, capture_output=True, text=True, timeout=timeout)
    except FileNotFoundError:
        sys.exit(f"[!] tool not found: {cmd[0]}")
    except subprocess.TimeoutExpired as e:
        print(f"[!] timeout: {' '.join(cmd[:3])}... (saving partial output)")
        if e.stdout:
            return e.stdout.splitlines()
        return []
    if p.returncode != 0 or p.stderr.strip():
        with open("recon.log", "a") as f:
            f.write(f"[{now()}] {' '.join(cmd)} rc={p.returncode}\n{p.stderr[-2000:]}\n")
    if p.returncode != 0:
        print(f"[!] {cmd[0]} exited {p.returncode} (details in recon.log; check flags for your tool version)")
    return p.stdout.splitlines()

def now():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")

# ---------------------------------------------------------------- 3. Normalize
NOISE_EXT = re.compile(r"\.(png|jpe?g|gif|svg|ico|woff2?|ttf|css|mp4|webp)(\?|$)", re.I)

def normalize_url(u):
    """Collapse values of params so /a?id=1 and /a?id=2 become one 'shape'."""
    p = urlparse(u.strip())
    keys = sorted({k for k, _ in parse_qsl(p.query, keep_blank_values=True)})
    path = re.sub(r"/\d+(?=/|$)", "/{n}", p.path)          # /user/123 -> /user/{n}
    path = re.sub(r"/[0-9a-fA-F]{8}-[0-9a-fA-F-]{27}(?=/|$)", "/{uuid}", path)
    # NOTE: literals like /users/me stay distinct from /users/{n}/settings on purpose
    shape = urlunparse((p.scheme, p.netloc, path, "", "&".join(keys), ""))
    return shape, keys

# ---------------------------------------------------------------- 4. Scoring
SENSITIVE_PATH = re.compile(
    r"(admin|login|oauth|sso|token|api|graphql|upload|export|import|download|"
    r"invoice|payment|billing|user|account|profile|reset|internal|debug|config|v\d+)", re.I)
IDOR_PARAMS = {"id", "uid", "user", "user_id", "account", "order", "invoice", "file", "doc"}
REDIRECT_PARAMS = {"url", "redirect", "next", "return", "callback", "dest", "continue"}
SSRF_PARAMS = {"url", "uri", "src", "host", "feed", "webhook", "target", "image"}

def score_endpoint(path, params):
    s, why = 0, []
    if SENSITIVE_PATH.search(path):
        s += 2; why.append("sensitive-path")
    ps = {p.lower() for p in params}
    if ps:
        s += 1; why.append("has-params")
    if ps & IDOR_PARAMS:
        s += 3; why.append("idor-like-param")
    if ps & REDIRECT_PARAMS:
        s += 2; why.append("redirect-like-param")
    if ps & SSRF_PARAMS:
        s += 2; why.append("ssrf-like-param")
    return s, ",".join(why)

def score_asset(a):
    s, why = 0, []
    tech = " ".join(a.get("tech") or []).lower()
    title = (a.get("title") or "").lower()
    if a.get("status") in (401, 403):
        s += 2; why.append("auth-gated")
    if re.search(r"(jenkins|grafana|kibana|gitlab|jira|admin|swagger|graphql)", title + tech):
        s += 3; why.append("interesting-service")
    if re.search(r"(dev|stage|staging|test|uat|beta|internal)", a["host"]):
        s += 2; why.append("non-prod-name")
    return s, ",".join(why)

# ---------------------------------------------------------------- 5. Storage
def db():
    c = sqlite3.connect(DB)
    c.executescript("""
    CREATE TABLE IF NOT EXISTS assets(
      host TEXT PRIMARY KEY, url TEXT, status INT, title TEXT, tech TEXT,
      score INT, why TEXT, first_seen TEXT, last_seen TEXT, run_id TEXT);
    CREATE TABLE IF NOT EXISTS endpoints(
      shape TEXT PRIMARY KEY, example TEXT, params TEXT,
      score INT, why TEXT, first_seen TEXT, last_seen TEXT, run_id TEXT);
    """)
    c.execute("CREATE TABLE IF NOT EXISTS runs(run_id TEXT PRIMARY KEY, started TEXT)")
    for t in ("assets", "endpoints"):
        for col in ("last_run_id TEXT", "react_run TEXT"):
            try:
                c.execute(f"ALTER TABLE {t} ADD COLUMN {col}")
            except sqlite3.OperationalError:
                pass
    return c

PREV_RUN = None

def begin_run(c, run_id):
    global PREV_RUN
    r = c.execute("SELECT MAX(run_id) FROM runs").fetchone()
    PREV_RUN = r[0]
    c.execute("INSERT OR IGNORE INTO runs VALUES(?,?)", (run_id, now()))
    c.commit()

def _react(row_last_run, run_id):
    """Seen before, absent in the previous run, back now -> reactivated."""
    return PREV_RUN is not None and row_last_run not in (PREV_RUN, run_id)

def upsert_asset(c, a, run_id):
    sc, why = score_asset(a)
    r = c.execute("SELECT last_run_id FROM assets WHERE host=?", (a["host"],)).fetchone()
    if r:
        react = run_id if _react(r[0], run_id) else None
        c.execute("UPDATE assets SET url=?,status=?,title=?,tech=?,score=?,why=?,last_seen=?,last_run_id=?,"
                  "react_run=COALESCE(?,react_run) WHERE host=?",
                  (a["url"], a["status"], a["title"], json.dumps(a["tech"]), sc, why, now(), run_id, react, a["host"]))
    else:
        c.execute("INSERT INTO assets(host,url,status,title,tech,score,why,first_seen,last_seen,run_id,last_run_id) "
                  "VALUES(?,?,?,?,?,?,?,?,?,?,?)",
                  (a["host"], a["url"], a["status"], a["title"], json.dumps(a["tech"]),
                   sc, why, now(), now(), run_id, run_id))

def upsert_endpoint(c, shape, example, params, run_id):
    path = urlparse(shape).path
    sc, why = score_endpoint(path, params)
    r = c.execute("SELECT last_run_id FROM endpoints WHERE shape=?", (shape,)).fetchone()
    if r:
        react = run_id if _react(r[0], run_id) else None
        c.execute("UPDATE endpoints SET last_seen=?,last_run_id=?,react_run=COALESCE(?,react_run) WHERE shape=?",
                  (now(), run_id, react, shape))
    else:
        c.execute("INSERT INTO endpoints(shape,example,params,score,why,first_seen,last_seen,run_id,last_run_id) "
                  "VALUES(?,?,?,?,?,?,?,?,?)",
                  (shape, example, ",".join(params), sc, why, now(), now(), run_id, run_id))

# ---------------------------------------------------------------- 2. Collectors
def wide_collect(scope, c, run_id):
    hosts = set()
    for root in scope.roots:
        print(f"[wide] subfinder {root}")
        hosts.update(h.strip().lower() for h in
                     run(build(scope, "subfinder", domain=root), scope.timeout))
        hosts.add(root)
    hosts = {h for h in hosts if scope.allowed(h)}          # scope guard BEFORE probing
    print(f"[wide] {len(hosts)} in-scope candidates -> probing")
    if not hosts:
        return
    out = run(build(scope, "httpx"),
              scope.timeout * 3, stdin="\n".join(sorted(hosts)))
    live = 0
    for line in out:
        try:
            j = json.loads(line)
        except json.JSONDecodeError:
            continue
        host = (j.get("host") or urlparse(j.get("url", "")).hostname or "").lower()
        if not scope.allowed(host):
            continue
        upsert_asset(c, {"host": host, "url": j.get("url"), "status": j.get("status_code"),
                         "title": j.get("title"), "tech": j.get("tech") or []}, run_id)
        live += 1
    c.commit()
    print(f"[wide] live: {live}")

def narrow_collect(scope, c, run_id, target):
    if not scope.url_allowed(target):
        sys.exit("[!] target is OUT of scope. aborting.")
    host = urlparse(target).hostname
    urls = set()
    print(f"[narrow] katana {target}")
    urls.update(run(build(scope, "katana", target=target), scope.timeout))
    print(f"[narrow] gau {host}")
    urls.update(run(build(scope, "gau", domain=host), scope.timeout))           # passive history
    n = 0
    for u in urls:
        u = u.strip()
        if not u.startswith("http") or NOISE_EXT.search(u) or not scope.url_allowed(u):
            continue
        shape, params = normalize_url(u)
        upsert_endpoint(c, shape, u, params, run_id)
        n += 1
    c.commit()
    print(f"[narrow] processed {n} in-scope URLs")

# ---------------------------------------------------------------- 6. Report
def report(c, last_only=True):
    last = c.execute("SELECT MAX(run_id) FROM runs").fetchone()[0]
    print(f"# Recon report (run {last})\n")
    for title, col in (("NEW", "run_id"), ("REACTIVATED (seen before, gone, back now)", "react_run")):
        print(f"## {title} assets (by score)")
        for r in c.execute(f"SELECT score,host,status,title,why FROM assets WHERE {col}=? ORDER BY score DESC", (last,)):
            print(f"- [{r[0]}] {r[1]}  {r[2]}  {r[3] or ''}  ({r[4]})")
        print(f"\n## {title} endpoints (by score) -> manual review")
        for r in c.execute(f"SELECT score,example,why FROM endpoints WHERE {col}=? ORDER BY score DESC LIMIT 100", (last,)):
            print(f"- [{r[0]}] {r[1]}  ({r[2]})")
        print()

# ---------------------------------------------------------------- main
def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("mode", choices=["wide", "narrow", "report", "doctor", "init-tools"])
    ap.add_argument("--scope")
    ap.add_argument("--target")
    a = ap.parse_args()
    if a.mode == "init-tools":
        if os.path.exists(TOOLS_FILE):
            sys.exit(f"{TOOLS_FILE} already exists; edit it directly")
        json.dump(DEFAULT_TOOLS, open(TOOLS_FILE, "w"), indent=2)
        print(f"wrote {TOOLS_FILE}"); return
    if a.mode == "doctor":
        doctor(Scope(a.scope) if a.scope else None); return
    if not a.scope:
        sys.exit("--scope required")
    scope, c = Scope(a.scope), db()
    run_id = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    if a.mode != "report":
        begin_run(c, run_id)
    if a.mode == "wide":
        wide_collect(scope, c, run_id); report(c)
    elif a.mode == "narrow":
        if not a.target:
            sys.exit("--target required")
        narrow_collect(scope, c, run_id, a.target); report(c)
    else:
        report(c)

if __name__ == "__main__":
    main()
