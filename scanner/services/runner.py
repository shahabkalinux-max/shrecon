import json
import os
import shutil
import subprocess
import threading
import time
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from urllib.parse import urlparse

from django.db import connection
from django.utils import timezone as dj_timezone

import recon
import recon_plugins
from scanner.models import Program, ScanRun, Asset, Endpoint, Port, Signal

ACTIVE_THREADS = {}
ACTIVE_PROCESSES = {}
CANCEL_REQUESTS = set()


class RunLogger:
    def __init__(self, scan_run):
        self.scan_run = scan_run
        self.buffer = []

    def log(self, message):
        ts = dj_timezone.now().strftime("%Y-%m-%d %H:%M:%S")
        line = f"[{ts}] {message}"
        print(line)
        self.buffer.append(line)
        self.scan_run.log_output = "\n".join(self.buffer)
        self.scan_run.save(update_fields=['log_output'])


class ScopeBridge:
    """Bridges Django Program model to the Scope object expected by recon.build and tools."""
    def __init__(self, program):
        self.program = program
        self.inc = program.get_in_scope_patterns()
        self.exc = program.get_out_of_scope_patterns()
        self.rate = program.rate_limit
        self.conc = program.concurrency
        self.timeout = program.timeout
        self.headers = program.headers or {}
        self.strict_headers = program.strict_headers
        self.roots = program.get_roots()
        self.cfg = {
            "allow_portscan": program.allow_portscan,
            "allow_active": program.allow_active,
            "allow_screens": program.allow_screens,
            "enable_katana": program.enable_katana,
            "enable_gau": program.enable_gau,
            "enable_ffuf": program.enable_ffuf,
            "enable_js_analysis": program.enable_js_analysis,
            "enable_param_discovery": program.enable_param_discovery,
            "enable_nuclei": program.enable_nuclei,
        }

    def allowed(self, host):
        return self.program.is_host_allowed(host)

    def url_allowed(self, url):
        return self.program.is_url_allowed(url)


def run_cmd(cmd, timeout, stdin=None, scan_run_id=None, logger=None):
    """Interruptible subprocess runner tracking PID for instant cancellation."""
    if scan_run_id and scan_run_id in CANCEL_REQUESTS:
        return []

    try:
        proc = subprocess.Popen(
            cmd,
            stdin=subprocess.PIPE if stdin else None,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
    except FileNotFoundError:
        if logger:
            logger.log(f"[!] Tool binary not found: {cmd[0]}")
        return []

    if scan_run_id:
        ACTIVE_PROCESSES[scan_run_id] = proc

    try:
        stdout, stderr = proc.communicate(input=stdin, timeout=timeout)
    except subprocess.TimeoutExpired:
        proc.kill()
        out_tail, _ = proc.communicate()
        if logger:
            logger.log(f"[!] Timeout reached for: {' '.join(cmd[:3])}... (saving collected output)")
        if out_tail:
            return out_tail.splitlines()
        return []
    except Exception as e:
        proc.kill()
        proc.communicate()
        if logger:
            logger.log(f"[!] Execution failed: {e}")
        return []
    finally:
        if scan_run_id:
            ACTIVE_PROCESSES.pop(scan_run_id, None)

    if scan_run_id and scan_run_id in CANCEL_REQUESTS:
        return []

    if proc.returncode != 0 or stderr.strip():
        with open("recon.log", "a") as f:
            f.write(f"[{recon.now()}] {' '.join(cmd)} rc={proc.returncode}\n{stderr[-2000:]}\n")
    if proc.returncode != 0:
        if logger:
            logger.log(f"[!] {cmd[0]} exited {proc.returncode} (check recon.log for details)")
    return stdout.splitlines()


def stop_scan(scan_run_id):
    """Immediately terminates the active process and cancels the scan."""
    CANCEL_REQUESTS.add(scan_run_id)

    # 1. Kill active subprocess if running
    proc = ACTIVE_PROCESSES.get(scan_run_id)
    if proc:
        try:
            proc.terminate()
            try:
                proc.wait(timeout=1.0)
            except subprocess.TimeoutExpired:
                proc.kill()
        except Exception:
            pass

    # 2. Update ScanRun model
    try:
        scan_run = ScanRun.objects.get(id=scan_run_id)
        if scan_run.status in ('pending', 'running'):
            scan_run.status = 'stopped'
            scan_run.completed_at = dj_timezone.now()
            ts = dj_timezone.now().strftime("%Y-%m-%d %H:%M:%S")
            scan_run.log_output += f"\n[{ts}] [!] Scan stopped by user."
            scan_run.save(update_fields=['status', 'completed_at', 'log_output'])
    except Exception:
        pass

    ACTIVE_THREADS.pop(scan_run_id, None)
    ACTIVE_PROCESSES.pop(scan_run_id, None)


def _is_reactivated(prev_run, existing_last_run, current_run):
    """Seen before, absent in the previous run, back now -> reactivated."""
    return (
        prev_run is not None
        and existing_last_run is not None
        and existing_last_run.id not in (prev_run.id, current_run.id)
    )


def upsert_asset_orm(program, scan_run, prev_run, a_dict):
    sc, why = recon.score_asset(a_dict)
    host = (a_dict.get("host") or "").lower().strip()
    if not host or not program.is_host_allowed(host):
        return None, False

    asset = Asset.objects.filter(program=program, host=host).first()
    if asset:
        react = scan_run if _is_reactivated(prev_run, asset.last_run, scan_run) else asset.react_run
        asset.url = a_dict.get("url") or asset.url
        asset.status = a_dict.get("status") if a_dict.get("status") is not None else asset.status
        asset.title = a_dict.get("title") or asset.title
        asset.tech = a_dict.get("tech") or asset.tech
        asset.score = sc
        asset.why = why
        asset.last_run = scan_run
        if react:
            asset.react_run = react
        asset.save()
        return asset, False
    else:
        asset = Asset.objects.create(
            program=program,
            host=host,
            url=a_dict.get("url"),
            status=a_dict.get("status"),
            title=a_dict.get("title"),
            tech=a_dict.get("tech") or [],
            score=sc,
            why=why,
            first_run=scan_run,
            last_run=scan_run,
        )
        return asset, True


def upsert_endpoint_orm(program, scan_run, prev_run, shape, example, params):
    path = urlparse(shape).path
    param_list = params if isinstance(params, (list, set, tuple)) else str(params).split(",")
    sc, why = recon.score_endpoint(path, param_list)
    params_str = ",".join(param_list)

    endpoint = Endpoint.objects.filter(program=program, shape=shape).first()
    if endpoint:
        react = scan_run if _is_reactivated(prev_run, endpoint.last_run, scan_run) else endpoint.react_run
        endpoint.example = example
        endpoint.params = params_str
        endpoint.score = sc
        endpoint.why = why
        endpoint.last_run = scan_run
        if react:
            endpoint.react_run = react
        endpoint.save()
        return endpoint, False
    else:
        endpoint = Endpoint.objects.create(
            program=program,
            shape=shape,
            example=example,
            params=params_str,
            score=sc,
            why=why,
            first_run=scan_run,
            last_run=scan_run,
        )
        return endpoint, True


def upsert_port_orm(program, scan_run, host, port):
    host = host.lower().strip()
    if not program.is_host_allowed(host):
        return None, False
    port_obj, created = Port.objects.get_or_create(
        program=program,
        host=host,
        port=int(port),
        defaults={"last_run": scan_run}
    )
    if not created and port_obj.last_run != scan_run:
        port_obj.last_run = scan_run
        port_obj.save(update_fields=['last_run'])
    return port_obj, created


def upsert_signal_orm(program, scan_run, key, host, template, severity, matched):
    sig, created = Signal.objects.get_or_create(
        program=program,
        key=key,
        defaults={
            "host": host,
            "template": template,
            "severity": severity or "info",
            "matched": matched,
            "last_run": scan_run,
        }
    )
    if not created and sig.last_run != scan_run:
        sig.last_run = scan_run
        sig.save(update_fields=['last_run'])
    return sig, created


def wide_collect_django(scope, program, scan_run, prev_run, logger):
    if scan_run.id in CANCEL_REQUESTS:
        return
    logger.log(f"[Wide] Gathering subdomains for roots: {', '.join(scope.roots)}")
    hosts = set()
    for root in scope.roots:
        if scan_run.id in CANCEL_REQUESTS:
            return
        logger.log(f"[Wide] subfinder {root}")
        subfinder_out = run_cmd(recon.build(scope, "subfinder", domain=root), scope.timeout, scan_run_id=scan_run.id, logger=logger)
        for h in subfinder_out:
            if h.strip():
                hosts.add(h.strip().lower())
        hosts.add(root.lower())

    if scan_run.id in CANCEL_REQUESTS:
        return

    # Scope guard BEFORE probing
    in_scope_hosts = {h for h in hosts if scope.allowed(h)}
    logger.log(f"[Wide] {len(in_scope_hosts)} in-scope candidates (out of {len(hosts)}) -> probing with httpx")
    if not in_scope_hosts:
        return

    httpx_out = run_cmd(
        recon.build(scope, "httpx"),
        scope.timeout * 3,
        stdin="\n".join(sorted(in_scope_hosts)),
        scan_run_id=scan_run.id,
        logger=logger
    )
    live = 0
    for line in httpx_out:
        if scan_run.id in CANCEL_REQUESTS:
            return
        try:
            j = json.loads(line)
        except json.JSONDecodeError:
            continue
        host = (j.get("host") or urlparse(j.get("url", "")).hostname or "").lower()
        if not scope.allowed(host):
            continue
        upsert_asset_orm(program, scan_run, prev_run, {
            "host": host,
            "url": j.get("url"),
            "status": j.get("status_code"),
            "title": j.get("title"),
            "tech": j.get("tech") or []
        })
        live += 1
    logger.log(f"[Wide] Completed: {live} live assets discovered/updated.")


def narrow_collect_django(scope, program, scan_run, prev_run, target, logger):
    if scan_run.id in CANCEL_REQUESTS:
        return
    if not scope.url_allowed(target):
        logger.log(f"[!] Target {target} is OUT of scope. Aborting narrow scan.")
        return
    host = urlparse(target).hostname
    urls = set()
    if scope.cfg.get("enable_katana", True):
        logger.log(f"[Narrow] katana {target}")
        urls.update(run_cmd(recon.build(scope, "katana", target=target), scope.timeout, scan_run_id=scan_run.id, logger=logger))
    else:
        logger.log("[Narrow] katana skipped (enable_katana=false)")
    if scan_run.id in CANCEL_REQUESTS:
        return
    if scope.cfg.get("enable_gau", True):
        logger.log(f"[Narrow] gau {host}")
        urls.update(run_cmd(recon.build(scope, "gau", domain=host), scope.timeout, scan_run_id=scan_run.id, logger=logger))
    else:
        logger.log("[Narrow] gau skipped (enable_gau=false)")

    processed = 0
    for u in urls:
        if scan_run.id in CANCEL_REQUESTS:
            return
        u = u.strip()
        if not u.startswith("http") or recon.NOISE_EXT.search(u) or not scope.url_allowed(u):
            continue
        shape, params = recon.normalize_url(u)
        upsert_endpoint_orm(program, scan_run, prev_run, shape, u, params)
        processed += 1
    logger.log(f"[Narrow] Processed {processed} in-scope URLs for {target}.")


def p_dnsx_django(scope, program, scan_run, logger):
    if scan_run.id in CANCEL_REQUESTS:
        return
    logger.log("[dnsx] Resolving live assets and checking CNAMEs...")
    live_hosts = [a.host for a in Asset.objects.filter(program=program) if scope.allowed(a.host)]
    if not live_hosts:
        return
    out = run_cmd(recon.build(scope, "dnsx"), scope.timeout, stdin="\n".join(live_hosts), scan_run_id=scan_run.id, logger=logger)
    for line in out:
        if scan_run.id in CANCEL_REQUESTS:
            return
        try:
            j = json.loads(line)
        except json.JSONDecodeError:
            continue
        host = (j.get("host") or "").lower()
        for cn in j.get("cname") or []:
            cn = cn.rstrip(".").lower()
            if not scope.allowed(cn):
                key = f"{host}|cname|{cn}"
                upsert_signal_orm(
                    program, scan_run, key, host, "external-cname", "info",
                    f"{cn} (out of scope: check takeover by DNS/fingerprint only, do not scan)"
                )
    logger.log("[dnsx] Completed.")


def p_naabu_django(scope, program, scan_run, logger):
    if scan_run.id in CANCEL_REQUESTS:
        return
    if not scope.cfg.get("allow_portscan"):
        logger.log("[naabu] skipped (allow_portscan=false)")
        return
    logger.log("[naabu] Scanning top ports on live assets...")
    live_hosts = [a.host for a in Asset.objects.filter(program=program) if scope.allowed(a.host)]
    if not live_hosts:
        return
    out = run_cmd(recon.build(scope, "naabu"), scope.timeout * 3, stdin="\n".join(live_hosts), scan_run_id=scan_run.id, logger=logger)
    for line in out:
        if scan_run.id in CANCEL_REQUESTS:
            return
        try:
            j = json.loads(line)
        except json.JSONDecodeError:
            continue
        host = (j.get("host") or "").lower()
        if scope.allowed(host):
            upsert_port_orm(program, scan_run, host, j.get("port"))
    logger.log("[naabu] Completed.")


def p_nuclei_django(scope, program, scan_run, logger):
    if scan_run.id in CANCEL_REQUESTS:
        return
    if not scope.cfg.get("allow_active"):
        logger.log("[nuclei] skipped (allow_active=false)")
        return
    if not scope.cfg.get("enable_nuclei", True):
        logger.log("[nuclei] skipped (enable_nuclei=false)")
        return
    logger.log("[nuclei] Running tech-routed safe templates (leads for manual review)...")
    live_assets = Asset.objects.filter(program=program)
    for a in live_assets:
        if scan_run.id in CANCEL_REQUESTS:
            return
        if not a.url or not scope.url_allowed(a.url):
            continue
        tags = set(recon_plugins.BASE_TAGS)
        tl = " ".join(a.tech or []).lower()
        tags.update(t for k, t in recon_plugins.TECH_TAGS.items() if k in tl)
        out = run_cmd(recon.build(scope, "nuclei", url=a.url, tags=",".join(sorted(tags))), scope.timeout, scan_run_id=scan_run.id, logger=logger)
        for line in out:
            if scan_run.id in CANCEL_REQUESTS:
                return
            try:
                j = json.loads(line)
            except json.JSONDecodeError:
                continue
            key = f"{a.host}|{j.get('template-id')}|{j.get('matched-at')}"
            sev = (j.get("info") or {}).get("severity", "info")
            upsert_signal_orm(program, scan_run, key, a.host, j.get('template-id'), sev, j.get('matched-at'))
    logger.log("[nuclei] Completed.")


def p_arjun_django(scope, program, scan_run, logger, top=15):
    if scan_run.id in CANCEL_REQUESTS:
        return
    if not scope.cfg.get("allow_active"):
        logger.log("[arjun] skipped (allow_active=false)")
        return
    if not scope.cfg.get("enable_param_discovery", True):
        logger.log("[arjun] skipped (enable_param_discovery=false)")
        return
    logger.log("[arjun] Finding hidden parameters on top scored endpoints...")
    endpoints = Endpoint.objects.filter(program=program).order_by('-score')[:top]
    for ep in endpoints:
        if scan_run.id in CANCEL_REQUESTS:
            return
        if scope.url_allowed(ep.example):
            run_cmd(recon.build(scope, "arjun", url=ep.example, out=f"arjun_{scan_run.run_id}.json"), scope.timeout, scan_run_id=scan_run.id, logger=logger)
    logger.log("[arjun] Completed.")


def p_ffuf_django(scope, program, scan_run, prev_run, logger, top=5):
    if scan_run.id in CANCEL_REQUESTS:
        return
    if not scope.cfg.get("allow_active"):
        logger.log("[ffuf] skipped (allow_active=false)")
        return
    if not scope.cfg.get("enable_ffuf", True):
        logger.log("[ffuf] skipped (enable_ffuf=false)")
        return
    base_dir = os.path.dirname(os.path.dirname(os.path.dirname(__file__)))
    wordlist_path = os.path.join(base_dir, "wordlists", "sensitive_paths.txt")
    if not os.path.exists(wordlist_path):
        logger.log(f"[ffuf] wordlist not found at {wordlist_path}")
        return

    logger.log("[ffuf] Running targeted sensitive path discovery on top assets...")
    top_assets = Asset.objects.filter(program=program).order_by('-score')[:top]
    for a in top_assets:
        if scan_run.id in CANCEL_REQUESTS:
            return
        if not a.url or not scope.url_allowed(a.url):
            continue
        base_url = a.url.rstrip("/")
        cmd = recon.build(scope, "ffuf", url=base_url, wordlist=wordlist_path)
        out = run_cmd(cmd, scope.timeout * 2, scan_run_id=scan_run.id, logger=logger)
        found_count = 0
        for line in out:
            if scan_run.id in CANCEL_REQUESTS:
                return
            try:
                j = json.loads(line)
            except json.JSONDecodeError:
                continue
            matched_url = j.get("url")
            status = j.get("status")
            if matched_url and scope.url_allowed(matched_url):
                shape, params = recon.normalize_url(matched_url)
                upsert_endpoint_orm(program, scan_run, prev_run, shape, matched_url, params)
                found_count += 1
                path_lower = urlparse(matched_url).path.lower()
                critical_matches = [".env", ".git", "backup", "dump", "actuator", "swagger", "admin", "phpinfo"]
                if any(k in path_lower for k in critical_matches):
                    sev = "high" if any(k in path_lower for k in [".env", ".git", "backup", "dump"]) else "medium"
                    key = f"{a.host}|ffuf|{path_lower}"
                    upsert_signal_orm(
                        program, scan_run, key, a.host, "exposed-sensitive-path", sev,
                        f"{matched_url} (Status: {status}, Size: {j.get('length')})"
                    )
        logger.log(f"[ffuf] {a.host}: found {found_count} paths.")
    logger.log("[ffuf] Completed.")


def p_x8_django(scope, program, scan_run, logger, top=10):
    if scan_run.id in CANCEL_REQUESTS:
        return
    if not scope.cfg.get("allow_active"):
        logger.log("[x8] skipped (allow_active=false)")
        return
    if not scope.cfg.get("enable_param_discovery", True):
        logger.log("[x8] skipped (enable_param_discovery=false)")
        return
    if not shutil.which("x8"):
        logger.log("[x8] skipped (x8 binary not installed)")
        return
    base_dir = os.path.dirname(os.path.dirname(os.path.dirname(__file__)))
    wordlist_path = os.path.join(base_dir, "wordlists", "parameters.txt")
    if not os.path.exists(wordlist_path):
        return
    logger.log("[x8] Finding hidden parameters on top scored endpoints using x8...")
    endpoints = Endpoint.objects.filter(program=program).order_by('-score')[:top]
    for ep in endpoints:
        if scan_run.id in CANCEL_REQUESTS:
            return
        if scope.url_allowed(ep.example):
            out_file = f"x8_{scan_run.run_id}.txt"
            cmd = recon.build(scope, "x8", url=ep.example, wordlist=wordlist_path, out=out_file)
            run_cmd(cmd, scope.timeout, scan_run_id=scan_run.id, logger=logger)
    logger.log("[x8] Completed.")


def p_js_django(scope, program, scan_run, prev_run, logger, limit=50):
    if scan_run.id in CANCEL_REQUESTS:
        return
    if not scope.cfg.get("enable_js_analysis", True):
        logger.log("[js] skipped (enable_js_analysis=false)")
        return
    logger.log("[js] Analyzing in-scope JavaScript endpoints...")
    endpoints = Endpoint.objects.filter(program=program, example__icontains='.js').order_by('-score')[:limit]
    for ep in endpoints:
        if scan_run.id in CANCEL_REQUESTS:
            return
        u = ep.example
        if not scope.url_allowed(u):
            continue
        time.sleep(1.0 / max(1, scope.rate))
        try:
            req = urllib.request.Request(u, headers={"User-Agent": "Mozilla/5.0 (shrecon)", **scope.headers})
            body = urllib.request.urlopen(req, timeout=15).read(2_000_000).decode("utf-8", "ignore")
        except Exception:
            continue
        base = urllib.parse.urlparse(u)
        host = base.hostname
        for path in set(recon_plugins.JS_PATH.findall(body)):
            full = f"{base.scheme}://{base.netloc}{path}"
            shape, params = recon.normalize_url(full)
            if scope.url_allowed(full):
                upsert_endpoint_orm(program, scan_run, prev_run, shape, full, params)
        for name, rx in recon_plugins.JS_SECRETS.items():
            for m in set(rx.findall(body)) if rx.groups else set(rx.findall(body)):
                val = m if isinstance(m, str) else m[0]
                masked_val = recon_plugins._mask(val)
                key = f"{u}|{name}|{val[:8]}"
                upsert_signal_orm(
                    program, scan_run, key, host, f"js-{name}", "needs-review",
                    f"{u} -> {masked_val} (lead: verify manually)"
                )
    logger.log("[js] Completed.")


def p_screens_django(scope, program, scan_run, logger):
    if scan_run.id in CANCEL_REQUESTS:
        return
    if not scope.cfg.get("allow_screens", True):
        logger.log("[gowitness] skipped (allow_screens=false)")
        return
    urls = [a.url for a in Asset.objects.filter(program=program) if a.url and scope.url_allowed(a.url)]
    if urls:
        logger.log(f"[gowitness] Taking screenshots of {len(urls)} live URLs...")
        run_cmd(recon.build(scope, "gowitness"), scope.timeout * 2, stdin="\n".join(urls), scan_run_id=scan_run.id, logger=logger)
        logger.log("[gowitness] Completed.")


def send_scan_notifications(program, scan_run, logger, min_score=5):
    tok, chat = os.getenv("TG_TOKEN"), os.getenv("TG_CHAT")
    if not (tok and chat):
        return
    new_assets = Asset.objects.filter(program=program, first_run=scan_run, score__gte=min_score)
    new_endpoints = Endpoint.objects.filter(program=program, first_run=scan_run, score__gte=min_score)[:20]
    new_signals = Signal.objects.filter(program=program, last_run=scan_run)
    lines = [f"shrecon run {scan_run.run_id} finished for {program.name}"]
    for a in new_assets:
        lines.append(f"[asset {a.score}] {a.host} {a.status or ''} {a.title or ''}")
    for ep in new_endpoints:
        lines.append(f"[endpoint {ep.score}] {ep.example} ({ep.why})")
    for s in new_signals:
        lines.append(f"[signal {s.severity}] {s.host} {s.template}")
    text = "\n".join(lines)[:4000]
    try:
        recon_plugins.notify(text)
        logger.log("[Notify] Telegram notification sent.")
    except Exception as e:
        logger.log(f"[Notify] Telegram failed: {e}")


def _run_scan_worker(scan_run_id):
    connection.close()  # Clean connection for the thread
    try:
        scan_run = ScanRun.objects.get(id=scan_run_id)
        if scan_run_id in CANCEL_REQUESTS:
            scan_run.status = 'stopped'
            scan_run.completed_at = dj_timezone.now()
            scan_run.save(update_fields=['status', 'completed_at'])
            return

        scan_run.status = 'running'
        scan_run.started_at = dj_timezone.now()
        scan_run.save(update_fields=['status', 'started_at'])

        logger = RunLogger(scan_run)
        program = scan_run.program
        scope = ScopeBridge(program)

        logger.log(f"--- Starting {scan_run.get_scan_type_display()} (Run ID: {scan_run.run_id}) ---")

        prev_run = ScanRun.objects.filter(
            program=program,
            status='completed'
        ).exclude(id=scan_run.id).order_by('-completed_at').first()

        if scan_run.scan_type == 'wide':
            wide_collect_django(scope, program, scan_run, prev_run, logger)
        elif scan_run.scan_type == 'narrow':
            if not scan_run.target:
                raise ValueError("Target URL is required for Narrow Recon.")
            narrow_collect_django(scope, program, scan_run, prev_run, scan_run.target, logger)
        elif scan_run.scan_type == 'full':
            wide_collect_django(scope, program, scan_run, prev_run, logger)
            p_dnsx_django(scope, program, scan_run, logger)
            p_naabu_django(scope, program, scan_run, logger)
            # Run narrow on top scored live assets
            top_assets = Asset.objects.filter(program=program).order_by('-score')[:5]
            for a in top_assets:
                if scan_run_id in CANCEL_REQUESTS:
                    break
                if a.url:
                    narrow_collect_django(scope, program, scan_run, prev_run, a.url, logger)
            p_js_django(scope, program, scan_run, prev_run, logger)
            p_ffuf_django(scope, program, scan_run, prev_run, logger)
            p_x8_django(scope, program, scan_run, logger)
            p_arjun_django(scope, program, scan_run, logger)
            p_nuclei_django(scope, program, scan_run, logger)
            p_screens_django(scope, program, scan_run, logger)
            send_scan_notifications(program, scan_run, logger)

        if scan_run_id in CANCEL_REQUESTS:
            scan_run.status = 'stopped'
            scan_run.completed_at = dj_timezone.now()
            logger.log(f"--- {scan_run.get_scan_type_display()} stopped by user ---")
            scan_run.save(update_fields=['status', 'completed_at', 'log_output'])
        else:
            scan_run.status = 'completed'
            scan_run.completed_at = dj_timezone.now()
            logger.log(f"--- {scan_run.get_scan_type_display()} finished successfully ---")
            scan_run.save(update_fields=['status', 'completed_at', 'log_output'])
    except Exception as e:
        import traceback
        err = traceback.format_exc()
        try:
            scan_run = ScanRun.objects.get(id=scan_run_id)
            if scan_run_id in CANCEL_REQUESTS:
                scan_run.status = 'stopped'
            else:
                scan_run.status = 'failed'
            scan_run.completed_at = dj_timezone.now()
            scan_run.error_message = str(e)
            scan_run.log_output += f"\n[ERROR] {err}"
            scan_run.save(update_fields=['status', 'completed_at', 'error_message', 'log_output'])
        except Exception:
            pass
    finally:
        ACTIVE_THREADS.pop(scan_run_id, None)
        ACTIVE_PROCESSES.pop(scan_run_id, None)
        CANCEL_REQUESTS.discard(scan_run_id)
        connection.close()


def trigger_scan(program, scan_type, target=None):
    CANCEL_REQUESTS.discard(None)
    run_id = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    scan_run = ScanRun.objects.create(
        program=program,
        run_id=run_id,
        scan_type=scan_type,
        target=target,
        status='pending'
    )
    t = threading.Thread(
        target=_run_scan_worker,
        args=(scan_run.id,),
        name=f"recon-{scan_run.id}",
        daemon=True
    )
    ACTIVE_THREADS[scan_run.id] = t
    t.start()
    return scan_run
