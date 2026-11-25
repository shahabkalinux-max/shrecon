from django.db import models
from django.utils import timezone
import fnmatch
from urllib.parse import urlparse


class Program(models.Model):
    name = models.CharField(max_length=200, unique=True, verbose_name="Program Name")
    description = models.TextField(blank=True, verbose_name="Description")
    
    # Scope definitions
    in_scope = models.TextField(
        help_text="In-scope domains/wildcard patterns, one per line or comma-separated (e.g. *.example.com, example.com)"
    )
    out_of_scope = models.TextField(
        blank=True,
        help_text="Out-of-scope patterns to exclude, one per line or comma-separated (e.g. admin.example.com)"
    )
    
    # Rate and concurrency limits
    rate_limit = models.PositiveIntegerField(default=5, help_text="Requests per second limit")
    concurrency = models.PositiveIntegerField(default=2, help_text="Concurrency / thread factor")
    timeout = models.PositiveIntegerField(default=300, help_text="Timeout in seconds for tools")
    
    # Headers
    headers = models.JSONField(
        default=dict,
        blank=True,
        help_text="Custom HTTP headers dict (e.g. {\"X-Bug-Bounty\": \"hunter\"})"
    )
    strict_headers = models.BooleanField(
        default=False,
        help_text="Refuse to run HTTP tools that do not support custom headers"
    )
    
    # Safety flags
    allow_portscan = models.BooleanField(
        default=False,
        help_text="Allow port scanning (naabu)"
    )
    allow_active = models.BooleanField(
        default=False,
        help_text="Allow active probing (nuclei, arjun, ffuf, katana)"
    )
    allow_screens = models.BooleanField(
        default=True,
        help_text="Allow gowitness screenshots"
    )

    # Granular stage selection
    enable_katana = models.BooleanField(
        default=True,
        verbose_name="Katana Web Crawling",
        help_text="Crawl live web pages to find endpoints, forms, and JS files (active)"
    )
    enable_gau = models.BooleanField(
        default=True,
        verbose_name="Archive URLs (gau)",
        help_text="Retrieve historical endpoints from Wayback Machine & archives (passive)"
    )
    enable_ffuf = models.BooleanField(
        default=True,
        verbose_name="Content Discovery (ffuf)",
        help_text="Targeted discovery of sensitive paths (.env, .git, admin, swagger) (active)"
    )
    enable_js_analysis = models.BooleanField(
        default=True,
        verbose_name="JavaScript Analysis & Secret Mining",
        help_text="Extract hidden API endpoints and secret/token patterns from JS files"
    )
    enable_param_discovery = models.BooleanField(
        default=True,
        verbose_name="Parameter Discovery (arjun/x8)",
        help_text="Find hidden query/POST parameters on top endpoints (active)"
    )
    enable_nuclei = models.BooleanField(
        default=True,
        verbose_name="Nuclei Safe Templates",
        help_text="Run tech-routed low-noise templates for misconfigurations and exposures (active)"
    )
    
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ['name']

    def __str__(self):
        return self.name

    def get_in_scope_patterns(self):
        raw = self.in_scope.replace(',', '\n')
        return [line.strip().lower() for line in raw.splitlines() if line.strip()]

    def get_out_of_scope_patterns(self):
        raw = self.out_of_scope.replace(',', '\n')
        return [line.strip().lower() for line in raw.splitlines() if line.strip()]

    def get_roots(self):
        return sorted({p.lstrip("*.") for p in self.get_in_scope_patterns() if p})

    def is_host_allowed(self, host):
        host = (host or "").lower().split(":")[0]
        if not host:
            return False
        # Invariant: out_of_scope always takes precedence!
        for exc in self.get_out_of_scope_patterns():
            if fnmatch.fnmatch(host, exc):
                return False
        for inc in self.get_in_scope_patterns():
            if fnmatch.fnmatch(host, inc):
                return True
        return False

    def is_url_allowed(self, url):
        return self.is_host_allowed(urlparse(url).hostname)


class ScanRun(models.Model):
    SCAN_TYPES = (
        ('wide', 'Wide Recon'),
        ('narrow', 'Narrow Recon'),
        ('full', 'Full Pipeline'),
    )
    STATUS_CHOICES = (
        ('pending', 'Pending'),
        ('running', 'Running'),
        ('completed', 'Completed'),
        ('failed', 'Failed'),
        ('stopped', 'Stopped'),
    )
    program = models.ForeignKey(Program, on_delete=models.CASCADE, related_name='runs')
    run_id = models.CharField(max_length=64, unique=True, db_index=True)
    scan_type = models.CharField(max_length=32, choices=SCAN_TYPES)
    target = models.CharField(max_length=512, blank=True, null=True, help_text="Target URL (for narrow recon)")
    status = models.CharField(max_length=32, choices=STATUS_CHOICES, default='pending')
    started_at = models.DateTimeField(null=True, blank=True)
    completed_at = models.DateTimeField(null=True, blank=True)
    log_output = models.TextField(blank=True)
    error_message = models.TextField(blank=True)
    
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ['-created_at']

    def __str__(self):
        return f"{self.program.name} - {self.run_id} ({self.get_scan_type_display()})"


class Asset(models.Model):
    program = models.ForeignKey(Program, on_delete=models.CASCADE, related_name='assets')
    host = models.CharField(max_length=255, db_index=True)
    url = models.CharField(max_length=1024, blank=True, null=True)
    status = models.IntegerField(null=True, blank=True)
    title = models.CharField(max_length=1024, blank=True, null=True)
    tech = models.JSONField(default=list, blank=True)
    score = models.IntegerField(default=0, db_index=True)
    why = models.CharField(max_length=512, blank=True)
    first_seen = models.DateTimeField(auto_now_add=True)
    last_seen = models.DateTimeField(auto_now=True)
    first_run = models.ForeignKey(ScanRun, on_delete=models.SET_NULL, null=True, blank=True, related_name='first_seen_assets')
    last_run = models.ForeignKey(ScanRun, on_delete=models.SET_NULL, null=True, blank=True, related_name='last_seen_assets')
    react_run = models.ForeignKey(ScanRun, on_delete=models.SET_NULL, null=True, blank=True, related_name='reactivated_assets')

    class Meta:
        unique_together = ('program', 'host')
        ordering = ['-score', 'host']

    def __str__(self):
        return f"{self.host} (Score: {self.score})"


class Endpoint(models.Model):
    program = models.ForeignKey(Program, on_delete=models.CASCADE, related_name='endpoints')
    shape = models.TextField(db_index=True)
    example = models.TextField()
    params = models.CharField(max_length=1024, blank=True)
    score = models.IntegerField(default=0, db_index=True)
    why = models.CharField(max_length=512, blank=True)
    first_seen = models.DateTimeField(auto_now_add=True)
    last_seen = models.DateTimeField(auto_now=True)
    first_run = models.ForeignKey(ScanRun, on_delete=models.SET_NULL, null=True, blank=True, related_name='first_seen_endpoints')
    last_run = models.ForeignKey(ScanRun, on_delete=models.SET_NULL, null=True, blank=True, related_name='last_seen_endpoints')
    react_run = models.ForeignKey(ScanRun, on_delete=models.SET_NULL, null=True, blank=True, related_name='reactivated_endpoints')

    class Meta:
        unique_together = ('program', 'shape')
        ordering = ['-score', '-last_seen']

    def __str__(self):
        return f"{self.shape} (Score: {self.score})"


class Port(models.Model):
    program = models.ForeignKey(Program, on_delete=models.CASCADE, related_name='ports')
    host = models.CharField(max_length=255, db_index=True)
    port = models.IntegerField()
    first_seen = models.DateTimeField(auto_now_add=True)
    last_run = models.ForeignKey(ScanRun, on_delete=models.SET_NULL, null=True, blank=True, related_name='ports')

    class Meta:
        unique_together = ('program', 'host', 'port')
        ordering = ['host', 'port']

    def __str__(self):
        return f"{self.host}:{self.port}"


class Signal(models.Model):
    program = models.ForeignKey(Program, on_delete=models.CASCADE, related_name='signals')
    key = models.CharField(max_length=512, db_index=True)
    host = models.CharField(max_length=255, db_index=True)
    template = models.CharField(max_length=255)
    severity = models.CharField(max_length=64, blank=True)
    matched = models.TextField(blank=True)
    first_seen = models.DateTimeField(auto_now_add=True)
    last_run = models.ForeignKey(ScanRun, on_delete=models.SET_NULL, null=True, blank=True, related_name='signals')

    class Meta:
        unique_together = ('program', 'key')
        ordering = ['-first_seen']

    def __str__(self):
        return f"[{self.severity}] {self.host} - {self.template}"
