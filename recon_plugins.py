#!/usr/bin/env python3
"""
recon_plugins.py - extends recon.py with optional plugins + notifications.
Put next to recon.py.

Extra scope.json keys (all default to false = safest):
  "allow_portscan": false,   # many programs forbid port scanning: check the rules first
  "allow_active":   false,   # nuclei / arjun / ffuf-style active probing
  "allow_screens":  true

Env for Telegram: TG_TOKEN, TG_CHAT

Usage:
  python recon_plugins.py full --scope scope.json [--notify-min 5]
"""
import argparse, json, os, re, shutil, sqlite3, sys, time, urllib.parse, urllib.request
from datetime import datetime, timezone
import recon
from recon import Scope, db, run, build, wide_collect, narrow_collect

# ------------------------------------------------ input routing: tech -> nuclei tags
TECH_TAGS = {
    "wordpress": "wordpress", "jenkins": "jenkins", "grafana": "grafana",
    "gitlab": "gitlab", "jira": "jira", "apache": "apache", "nginx": "nginx",
    "tomcat": "tomcat", "spring": "springboot", "graphql": "graphql",
    "laravel": "laravel", "drupal": "drupal", "joomla": "joomla",
}
BASE_TAGS = ["exposure", "misconfig", "takeover"]   # low-noise defaults

def extra_tables(c):
    c.executescript("""
    CREATE TABLE IF NOT EXISTS ports(host TEXT, port INT, first_seen TEXT, run_id TEXT,
                                     PRIMARY KEY(host,port));
    CREATE TABLE IF NOT EXISTS signals(key TEXT PRIMARY KEY, host TEXT, template TEXT,
                                       severity TEXT, matched TEXT, first_seen TEXT, run_id TEXT);
    """)

def now():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")

def live_hosts(c, run_scope):
    rows = c.execute("SELECT host, url, tech FROM assets").fetchall()
    return [(h, u, json.loads(t or "[]")) for h, u, t in rows if run_scope.allowed(h)]

# ------------------------------------------------ plugins
def p_dnsx(scope, c, run_id):
    """Resolve hosts; flag CNAME chains that leave the scope (never probe those targets)."""
    hosts = [h for h, _, _ in live_hosts(c, scope)]
    if not hosts:
        return
    out = run(build(scope, "dnsx"),
              scope.timeout, stdin="\n".join(hosts))
    for line in out:
        try:
            j = json.loads(line)
        except json.JSONDecodeError:
            continue
        host = (j.get("host") or "").lower()
        for cn in j.get("cname") or []:
            cn = cn.rstrip(".").lower()
            if not scope.allowed(cn):
                key = f"{host}|cname|{cn}"
                c.execute("INSERT OR IGNORE INTO signals VALUES(?,?,?,?,?,?,?)",
                          (key, host, "external-cname", "info",
                           f"{cn} (out of scope: check takeover by DNS/fingerprint only, do not scan)",
                           now(), run_id))
    c.commit()

def p_naabu(scope, c, run_id):
    if not scope.cfg.get("allow_portscan"):
        print("[naabu] skipped (allow_portscan=false)"); return
    hosts = [h for h, _, _ in live_hosts(c, scope)]            # hostnames only, scope-checked
    for line in run(build(scope, "naabu"),
                    scope.timeout * 3, stdin="\n".join(hosts)):
        try:
            j = json.loads(line)
        except json.JSONDecodeError:
            continue
        host = (j.get("host") or "").lower()
        if scope.allowed(host):                                 # re-check after resolve
            c.execute("INSERT OR IGNORE INTO ports VALUES(?,?,?,?)",
                      (host, j.get("port"), now(), run_id))
    c.commit()

def p_nuclei(scope, c, run_id):
    """Tech-routed, low-noise templates only. Results are SIGNALS to verify manually."""
    if not scope.cfg.get("allow_active"):
        print("[nuclei] skipped (allow_active=false)"); return
    for host, url, tech in live_hosts(c, scope):
        tags = set(BASE_TAGS)
        tl = " ".join(tech).lower()
        tags.update(t for k, t in TECH_TAGS.items() if k in tl)   # input routing
        out = run(build(scope, "nuclei", url=url, tags=",".join(sorted(tags))), scope.timeout)
        for line in out:
            try:
                j = json.loads(line)
            except json.JSONDecodeError:
                continue
            key = f"{host}|{j.get('template-id')}|{j.get('matched-at')}"
            c.execute("INSERT OR IGNORE INTO signals VALUES(?,?,?,?,?,?,?)",
                      (key, host, j.get("template-id"),
                       (j.get("info") or {}).get("severity"), j.get("matched-at"), now(), run_id))
    c.commit()

def p_arjun(scope, c, run_id, top=15):
    """Hidden-param discovery only on the highest-scored endpoints from narrow recon."""
    if not scope.cfg.get("allow_active"):
        print("[arjun] skipped (allow_active=false)"); return
    rows = c.execute("SELECT example FROM endpoints ORDER BY score DESC LIMIT ?", (top,)).fetchall()
    for (u,) in rows:
        if scope.url_allowed(u):
            run(build(scope, "arjun", url=u, out=f"arjun_{run_id}.json"), scope.timeout)

def p_ffuf(scope, c, run_id, top=5):
    """Targeted sensitive directory & file fuzzing on top live hosts."""
    if not scope.cfg.get("allow_active"):
        print("[ffuf] skipped (allow_active=false)"); return
    base_dir = os.path.dirname(__file__)
    wordlist = os.path.join(base_dir, "wordlists", "sensitive_paths.txt")
    if not os.path.exists(wordlist):
        return
    rows = c.execute("SELECT url, host FROM assets WHERE url IS NOT NULL ORDER BY score DESC LIMIT ?", (top,)).fetchall()
    for u, host in rows:
        if not scope.url_allowed(u):
            continue
        out = run(build(scope, "ffuf", url=u.rstrip("/"), wordlist=wordlist), scope.timeout * 2)
        for line in out:
            try:
                j = json.loads(line)
            except json.JSONDecodeError:
                continue
            res_url = j.get("url")
            status = j.get("status")
            if res_url and scope.url_allowed(res_url):
                shape, params = recon.normalize_url(res_url)
                recon.upsert_endpoint(c, shape, res_url, params, run_id)
                path_lower = urllib.parse.urlparse(res_url).path.lower()
                critical_matches = [".env", ".git", "backup", "dump", "actuator", "swagger", "admin", "phpinfo"]
                if any(k in path_lower for k in critical_matches):
                    sev = "high" if any(k in path_lower for k in [".env", ".git", "backup", "dump"]) else "medium"
                    key = f"{host}|ffuf|{path_lower}"
                    c.execute("INSERT OR IGNORE INTO signals VALUES(?,?,?,?,?,?,?)",
                              (key, host, "exposed-sensitive-path", sev, f"{res_url} (Status: {status})", now(), run_id))
    c.commit()

def p_x8(scope, c, run_id, top=10):
    """Fast hidden parameter discovery using x8 on top scored endpoints."""
    if not scope.cfg.get("allow_active"):
        print("[x8] skipped (allow_active=false)"); return
    base_dir = os.path.dirname(__file__)
    wordlist = os.path.join(base_dir, "wordlists", "parameters.txt")
    if not os.path.exists(wordlist):
        return
    rows = c.execute("SELECT example FROM endpoints ORDER BY score DESC LIMIT ?", (top,)).fetchall()
    for (u,) in rows:
        if scope.url_allowed(u):
            out_file = f"x8_{run_id}.txt"
            run(build(scope, "x8", url=u, wordlist=wordlist, out=out_file), scope.timeout)

JS_PATH = re.compile(r"[\"'`](/(?:api|v[0-9]+|internal|admin|auth|[a-zA-Z0-9_\-]+)(?:/[a-zA-Z0-9_\-{}.:]+)+)[\"'`]")
JS_SECRETS = {
    "aws-access-key": re.compile(r"AKIA[0-9A-Z]{16}"),
    "google-api-key": re.compile(r"AIza[0-9A-Za-z_\-]{35}"),
    "firebase-key": re.compile(r"AIzaSy[0-9A-Za-z_\-]{33}"),
    "google-oauth-client": re.compile(r"[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com"),
    "stripe-key": re.compile(r"pk_(?:live|test)_[0-9a-zA-Z]{24,}"),
    "slack-webhook": re.compile(r"https://hooks\.slack\.com/services/T[a-zA-Z0-9_]{8}/B[a-zA-Z0-9_]{8}/[a-zA-Z0-9_]{24}"),
    "jwt-token": re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9-_]{10,}\b"),
    "mailgun-api-key": re.compile(r"key-[0-9a-zA-Z]{32}"),
    "github-token": re.compile(r"(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{36}"),
    "generic-key-assign": re.compile(r"(?i)(?:api[_-]?key|secret|token|bearer|client[_-]?secret)[\"'\s:=]+[\"']([A-Za-z0-9_\-]{20,})[\"']"),
}

def _mask(v):
    return v[:4] + "..." + v[-2:] if len(v) > 8 else "***"

def p_js(scope, c, run_id, limit=50):
    """Extract paths + secret-like strings from in-scope .js files. Output = leads for manual review."""
    rows = c.execute("SELECT example FROM endpoints WHERE example LIKE '%.js%' ORDER BY score DESC LIMIT ?",
                     (limit,)).fetchall()
    for (u,) in rows:
        if not scope.url_allowed(u):
            continue
        time.sleep(1.0 / max(1, scope.rate))
        try:
            req = urllib.request.Request(u, headers={"User-Agent": "Mozilla/5.0 (recon)", **scope.headers})
            body = urllib.request.urlopen(req, timeout=15).read(2_000_000).decode("utf-8", "ignore")
        except Exception as e:
            print(f"[js] fetch failed {u}: {e}"); continue
        base = urllib.parse.urlparse(u)
        host = base.hostname
        for path in set(JS_PATH.findall(body)):
            full = f"{base.scheme}://{base.netloc}{path}"
            shape, params = recon.normalize_url(full)
            recon.upsert_endpoint(c, shape, full, params, run_id)
        for name, rx in JS_SECRETS.items():
            for m in set(rx.findall(body)) if rx.groups else set(rx.findall(body)):
                val = m if isinstance(m, str) else m[0]
                c.execute("INSERT OR IGNORE INTO signals VALUES(?,?,?,?,?,?,?)",
                          (f"{u}|{name}|{val[:8]}", host, f"js-{name}", "needs-review",
                           f"{u} -> {_mask(val)} (may be public/test key: verify manually)", now(), run_id))
    c.commit()

def p_screens(scope, c, run_id):
    if not scope.cfg.get("allow_screens", True):
        return
    urls = [u for _, u, _ in live_hosts(c, scope)]
    if urls:
        run(build(scope, "gowitness"), scope.timeout * 2, stdin="\n".join(urls))

# ------------------------------------------------ notify
def notify(text):
    tok, chat = os.getenv("TG_TOKEN"), os.getenv("TG_CHAT")
    if not (tok and chat):
        print(text); return
    data = urllib.parse.urlencode({"chat_id": chat, "text": text[:4000]}).encode()
    try:
        urllib.request.urlopen(f"https://api.telegram.org/bot{tok}/sendMessage", data, timeout=15)
    except Exception as e:
        print("[notify] failed:", e)

def notify_new(c, run_id, min_score):
    lines = []
    for s, h, st, t in c.execute(
            "SELECT score,host,status,title FROM assets WHERE run_id=? AND score>=? ORDER BY score DESC",
            (run_id, min_score)):
        lines.append(f"[asset {s}] {h} {st} {t or ''}")
    for s, ex, w in c.execute(
            "SELECT score,example,why FROM endpoints WHERE run_id=? AND score>=? ORDER BY score DESC LIMIT 20",
            (run_id, min_score)):
        lines.append(f"[endpoint {s}] {ex} ({w})")
    for sev, h, tpl in c.execute("SELECT severity,host,template FROM signals WHERE run_id=?", (run_id,)):
        lines.append(f"[signal {sev}] {h} {tpl}  (verify manually)")
    for h, p in c.execute("SELECT host,port FROM ports WHERE run_id=?", (run_id,)):
        lines.append(f"[port] {h}:{p}")
    if lines:
        notify(f"Recon run {run_id}: {len(lines)} new items\n" + "\n".join(lines))
    else:
        print("[notify] nothing new above threshold")

# ------------------------------------------------ main
def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("mode", choices=["full"])
    ap.add_argument("--scope", required=True)
    ap.add_argument("--notify-min", type=int, default=5)
    ap.add_argument("--narrow-top", type=int, default=5, help="how many top-scored live hosts get narrow recon")
    a = ap.parse_args()

    scope = Scope(a.scope)
    scope.cfg = json.load(open(a.scope))
    c = db(); extra_tables(c)
    run_id = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    recon.begin_run(c, run_id)

    wide_collect(scope, c, run_id)
    p_dnsx(scope, c, run_id)
    p_naabu(scope, c, run_id)
    # narrow only on the most interesting hosts, not everything
    top = c.execute("SELECT url FROM assets ORDER BY score DESC LIMIT ?", (a.narrow_top,)).fetchall()
    for (u,) in top:
        narrow_collect(scope, c, run_id, u)
    p_js(scope, c, run_id)
    p_ffuf(scope, c, run_id)
    p_x8(scope, c, run_id)
    p_arjun(scope, c, run_id)
    p_nuclei(scope, c, run_id)
    p_screens(scope, c, run_id)
    notify_new(c, run_id, a.notify_min)

if __name__ == "__main__":
    main()
