import json
import shutil
from django.shortcuts import render, get_object_or_404, redirect
from django.http import JsonResponse, HttpResponse
from django.views.decorators.http import require_POST
from django.contrib import messages
import recon
from .models import Program, ScanRun, Asset, Endpoint, Port, Signal
from .services.runner import trigger_scan, stop_scan, ACTIVE_THREADS


def program_list(request):
    programs = Program.objects.all().order_by('-created_at')
    recent_runs = ScanRun.objects.all().order_by('-created_at')[:8]
    return render(request, 'scanner/program_list.html', {
        'programs': programs,
        'recent_runs': recent_runs,
    })


def program_create(request):
    if request.method == 'POST':
        name = request.POST.get('name', '').strip()
        description = request.POST.get('description', '').strip()
        in_scope = request.POST.get('in_scope', '').strip()
        out_of_scope = request.POST.get('out_of_scope', '').strip()
        rate_limit = int(request.POST.get('rate_limit', 5))
        concurrency = int(request.POST.get('concurrency', 2))
        timeout = int(request.POST.get('timeout', 300))
        strict_headers = request.POST.get('strict_headers') == 'on'
        allow_portscan = request.POST.get('allow_portscan') == 'on'
        allow_active = request.POST.get('allow_active') == 'on'
        allow_screens = request.POST.get('allow_screens') == 'on'
        enable_katana = request.POST.get('enable_katana') == 'on'
        enable_gau = request.POST.get('enable_gau') == 'on'
        enable_ffuf = request.POST.get('enable_ffuf') == 'on'
        enable_js_analysis = request.POST.get('enable_js_analysis') == 'on'
        enable_param_discovery = request.POST.get('enable_param_discovery') == 'on'
        enable_nuclei = request.POST.get('enable_nuclei') == 'on'

        raw_headers = request.POST.get('headers', '{}').strip()
        try:
            headers = json.loads(raw_headers) if raw_headers else {}
        except json.JSONDecodeError:
            headers = {}

        if not name or not in_scope:
            messages.error(request, "Name and In-Scope patterns are required.")
            return render(request, 'scanner/program_form.html')

        program = Program.objects.create(
            name=name,
            description=description,
            in_scope=in_scope,
            out_of_scope=out_of_scope,
            rate_limit=rate_limit,
            concurrency=concurrency,
            timeout=timeout,
            headers=headers,
            strict_headers=strict_headers,
            allow_portscan=allow_portscan,
            allow_active=allow_active,
            allow_screens=allow_screens,
            enable_katana=enable_katana,
            enable_gau=enable_gau,
            enable_ffuf=enable_ffuf,
            enable_js_analysis=enable_js_analysis,
            enable_param_discovery=enable_param_discovery,
            enable_nuclei=enable_nuclei,
        )
        messages.success(request, f"Program '{program.name}' created successfully.")
        return redirect('program_detail', pk=program.pk)

    return render(request, 'scanner/program_form.html', {'is_edit': False})


def program_edit(request, pk):
    program = get_object_or_404(Program, pk=pk)
    if request.method == 'POST':
        program.name = request.POST.get('name', '').strip()
        program.description = request.POST.get('description', '').strip()
        program.in_scope = request.POST.get('in_scope', '').strip()
        program.out_of_scope = request.POST.get('out_of_scope', '').strip()
        program.rate_limit = int(request.POST.get('rate_limit', 5))
        program.concurrency = int(request.POST.get('concurrency', 2))
        program.timeout = int(request.POST.get('timeout', 300))
        program.strict_headers = request.POST.get('strict_headers') == 'on'
        program.allow_portscan = request.POST.get('allow_portscan') == 'on'
        program.allow_active = request.POST.get('allow_active') == 'on'
        program.allow_screens = request.POST.get('allow_screens') == 'on'
        program.enable_katana = request.POST.get('enable_katana') == 'on'
        program.enable_gau = request.POST.get('enable_gau') == 'on'
        program.enable_ffuf = request.POST.get('enable_ffuf') == 'on'
        program.enable_js_analysis = request.POST.get('enable_js_analysis') == 'on'
        program.enable_param_discovery = request.POST.get('enable_param_discovery') == 'on'
        program.enable_nuclei = request.POST.get('enable_nuclei') == 'on'

        raw_headers = request.POST.get('headers', '{}').strip()
        try:
            program.headers = json.loads(raw_headers) if raw_headers else {}
        except json.JSONDecodeError:
            pass

        program.save()
        messages.success(request, f"Program '{program.name}' updated successfully.")
        return redirect('program_detail', pk=program.pk)

    headers_str = json.dumps(program.headers, indent=2) if program.headers else "{}"
    return render(request, 'scanner/program_form.html', {
        'program': program,
        'headers_str': headers_str,
        'is_edit': True
    })


def program_detail(request, pk):
    program = get_object_or_404(Program, pk=pk)
    tab = request.GET.get('tab', 'assets')

    # Quick stats
    total_assets = program.assets.count()
    total_endpoints = program.endpoints.count()
    total_signals = program.signals.count()
    total_ports = program.ports.count()
    
    last_run = program.runs.filter(status='completed').first()
    new_assets_count = program.assets.filter(first_run=last_run).count() if last_run else 0
    react_assets_count = program.assets.filter(react_run=last_run).count() if last_run else 0

    # Querysets according to tab
    search_q = request.GET.get('q', '').strip()
    status_filter = request.GET.get('status', '').strip()

    assets = program.assets.all()
    if search_q:
        assets = assets.filter(host__icontains=search_q)
    if status_filter:
        assets = assets.filter(status=status_filter)

    endpoints = program.endpoints.all()
    if search_q and tab == 'endpoints':
        endpoints = endpoints.filter(shape__icontains=search_q)

    signals = program.signals.all()
    ports = program.ports.all()
    runs = program.runs.all()[:20]

    return render(request, 'scanner/program_detail.html', {
        'program': program,
        'tab': tab,
        'total_assets': total_assets,
        'total_endpoints': total_endpoints,
        'total_signals': total_signals,
        'total_ports': total_ports,
        'new_assets_count': new_assets_count,
        'react_assets_count': react_assets_count,
        'last_run': last_run,
        'assets': assets[:150],
        'endpoints': endpoints[:150],
        'signals': signals[:100],
        'ports': ports[:100],
        'runs': runs,
        'search_q': search_q,
        'status_filter': status_filter,
    })


@require_POST
def trigger_scan_view(request, pk):
    program = get_object_or_404(Program, pk=pk)
    scan_type = request.POST.get('scan_type', 'wide')
    target = request.POST.get('target', '').strip() or None

    if scan_type not in ('wide', 'narrow', 'full'):
        messages.error(request, "Invalid scan type specified.")
        return redirect('program_detail', pk=program.pk)

    if scan_type == 'narrow' and not target:
        messages.error(request, "Target URL is required for Narrow Recon.")
        return redirect('program_detail', pk=program.pk)

    if scan_type == 'narrow' and target and not program.is_url_allowed(target):
        messages.error(request, f"Target '{target}' is OUT OF SCOPE according to program rules.")
        return redirect('program_detail', pk=program.pk)

    scan_run = trigger_scan(program, scan_type, target)
    messages.success(request, f"Started {scan_run.get_scan_type_display()} (Run ID: {scan_run.run_id}) in the background.")
    return redirect('scan_run_detail', pk=scan_run.pk)


@require_POST
def stop_scan_view(request, pk):
    scan_run = get_object_or_404(ScanRun, pk=pk)
    stop_scan(scan_run.pk)
    messages.warning(request, f"Scan {scan_run.run_id} has been stopped.")
    next_url = request.POST.get('next')
    if next_url:
        return redirect(next_url)
    return redirect('scan_run_detail', pk=scan_run.pk)


def scan_run_detail(request, pk):
    scan_run = get_object_or_404(ScanRun, pk=pk)
    is_active = scan_run.pk in ACTIVE_THREADS or scan_run.status in ('pending', 'running')
    return render(request, 'scanner/scan_run_detail.html', {
        'scan_run': scan_run,
        'is_active': is_active,
    })


def scan_run_logs_api(request, pk):
    scan_run = get_object_or_404(ScanRun, pk=pk)
    return JsonResponse({
        'status': scan_run.status,
        'completed': scan_run.status in ('completed', 'failed', 'stopped'),
        'log_output': scan_run.log_output,
        'error_message': scan_run.error_message,
        'completed_at': scan_run.completed_at.strftime('%Y-%m-%d %H:%M:%S') if scan_run.completed_at else None,
    })


def export_scope_json(request, pk):
    program = get_object_or_404(Program, pk=pk)
    data = {
        "in_scope": program.get_in_scope_patterns(),
        "out_of_scope": program.get_out_of_scope_patterns(),
        "rate_limit": program.rate_limit,
        "concurrency": program.concurrency,
        "timeout": program.timeout,
        "headers": program.headers,
        "strict_headers": program.strict_headers,
        "allow_portscan": program.allow_portscan,
        "allow_active": program.allow_active,
        "allow_screens": program.allow_screens,
    }
    response = HttpResponse(json.dumps(data, indent=2), content_type="application/json")
    response['Content-Disposition'] = f'attachment; filename="scope_{program.name.lower().replace(" ", "_")}.json"'
    return response



def export_report_markdown(request, pk):
    from django.utils import timezone as tz
    program = get_object_or_404(Program, pk=pk)
    assets = program.assets.order_by('-score')
    endpoints = program.endpoints.order_by('-score')[:200]
    signals = program.signals.all()
    ports = program.ports.all()
    runs = program.runs.all()[:5]

    now_str = tz.now().strftime("%Y-%m-%d %H:%M UTC")
    slug = program.name.lower().replace(" ", "_")

    lines = []
    lines.append(f"# Recon Audit Report: {program.name}")
    lines.append(f"")
    lines.append(f"> Generated: {now_str}  |  Tool: shrecon  |  Scope: {', '.join(program.get_in_scope_patterns())}")
    lines.append(f"")

    # Executive summary
    lines.append("## Executive Summary")
    lines.append("")
    lines.append(f"| Metric | Count |")
    lines.append(f"|--------|-------|")
    lines.append(f"| Live Assets | {assets.count()} |")
    lines.append(f"| Endpoints | {endpoints.count()} |")
    lines.append(f"| Signals (leads) | {signals.count()} |")
    lines.append(f"| Open Ports | {ports.count()} |")
    lines.append(f"| Total Scan Runs | {runs.count()} |")
    lines.append("")

    # Recent scan runs
    if runs:
        lines.append("## Recent Scan Runs")
        lines.append("")
        lines.append("| Run ID | Type | Status | Started |")
        lines.append("|--------|------|--------|---------|")
        for r in runs:
            started = r.started_at.strftime("%Y-%m-%d %H:%M") if r.started_at else "—"
            lines.append(f"| `{r.run_id}` | {r.get_scan_type_display()} | {r.status} | {started} |")
        lines.append("")

    # High-Risk signals
    high_signals = signals.filter(severity__in=['high', 'critical', 'needs-review'])
    if high_signals.exists():
        lines.append("## 🔴 High-Priority Signals (Manual Review Required)")
        lines.append("")
        lines.append("> These are **leads**, not confirmed vulnerabilities. Human analysis is mandatory.")
        lines.append("")
        lines.append("| Severity | Host | Template | Matched |")
        lines.append("|----------|------|----------|---------|")
        for s in high_signals:
            matched_short = (s.matched or "")[:80].replace("|", "\\|")
            lines.append(f"| `{s.severity}` | `{s.host}` | {s.template} | {matched_short} |")
        lines.append("")

    # All signals
    other_signals = signals.exclude(severity__in=['high', 'critical', 'needs-review'])
    if other_signals.exists():
        lines.append("## 🟡 Informational Signals")
        lines.append("")
        lines.append("| Severity | Host | Template | Matched |")
        lines.append("|----------|------|----------|---------|")
        for s in other_signals:
            matched_short = (s.matched or "")[:80].replace("|", "\\|")
            lines.append(f"| `{s.severity}` | `{s.host}` | {s.template} | {matched_short} |")
        lines.append("")

    # Live Assets
    lines.append("## 🌐 Live Assets")
    lines.append("")
    lines.append("| Score | Host | Status | Title | Tech |")
    lines.append("|-------|------|--------|-------|------|")
    for a in assets:
        tech_str = ", ".join(a.tech or [])[:60]
        title_short = (a.title or "")[:60].replace("|", "\\|")
        lines.append(f"| {a.score} | `{a.host}` | {a.status or '—'} | {title_short} | {tech_str} |")
    lines.append("")

    # Open Ports
    if ports.exists():
        lines.append("## 🔌 Open Ports")
        lines.append("")
        lines.append("| Host | Port |")
        lines.append("|------|------|")
        for p in ports:
            lines.append(f"| `{p.host}` | {p.port} |")
        lines.append("")

    # Top Endpoints
    lines.append("## 🔗 Top Scored Endpoints")
    lines.append("")
    lines.append("| Score | Why | URL |")
    lines.append("|-------|-----|-----|")
    for ep in endpoints:
        why_short = (ep.why or "")[:50]
        example_short = ep.example[:120].replace("|", "\\|")
        lines.append(f"| {ep.score} | {why_short} | {example_short} |")
    lines.append("")

    lines.append("---")
    lines.append("")
    lines.append("> ⚠️ **Disclaimer:** All findings are recon leads for authorized testing only. No exploitation was performed. Verify every lead manually before acting.")
    lines.append("")

    md_content = "\n".join(lines)
    response = HttpResponse(md_content, content_type="text/markdown; charset=utf-8")
    response["Content-Disposition"] = f'attachment; filename="recon_report_{slug}.md"'
    return response


def tools_status_view(request):
    tools_list = []
    roles = {
        'subfinder': 'Subdomain discovery (Passive DNS & Certs)',
        'httpx': 'Live host probing, tech stack & status detection',
        'katana': 'Deep active web crawling & JS endpoint extraction',
        'gau': 'Historical archive URL retrieval (Wayback / CommonCrawl)',
        'dnsx': 'DNS resolving & external CNAME checks',
        'naabu': 'TCP port scanning (requires allow_portscan)',
        'nuclei': 'Tech-routed safe vulnerability & misconfig templates',
        'arjun': 'Hidden HTTP parameter discovery on top endpoints',
        'gowitness': 'Visual web screenshots of responsive hosts',
        'ffuf': 'High-performance web fuzzing for hidden directories & sensitive files',
        'x8': 'Blazing-fast hidden parameter discovery (Rust-based)',
    }
    install_commands = {
        'katana': 'go install github.com/projectdiscovery/katana/cmd/katana@latest',
        'naabu': 'go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest',
        'arjun': 'sudo apt install arjun',
        'gowitness': 'sudo apt install gowitness',
        'subfinder': 'go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest',
        'httpx': 'sudo apt install httpx-toolkit',
        'gau': 'go install github.com/lc/gau/v2/cmd/gau@latest',
        'dnsx': 'go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest',
        'nuclei': 'go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest',
        'ffuf': 'sudo apt install ffuf',
        'x8': 'wget https://github.com/Sh1Yo/x8/releases/latest/download/x86_64-linux-x8.gz && gzip -d x86_64-linux-x8.gz && chmod +x x86_64-linux-x8 && sudo mv x86_64-linux-x8 /usr/bin/x8',
    }
    for name, t in recon.load_tools().items():
        b = t.get("bin", name)
        path = shutil.which(b)
        tools_list.append({
            'name': name,
            'bin': b,
            'installed': bool(path),
            'path': path or 'Not found in PATH',
            'role': roles.get(name, 'Recon tool'),
            'install_cmd': install_commands.get(name, f'go install github.com/.../{name}@latest')
        })
    return render(request, 'scanner/tools_status.html', {'tools': tools_list})
