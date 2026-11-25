from django.contrib import admin
from .models import Program, ScanRun, Asset, Endpoint, Port, Signal


@admin.register(Program)
class ProgramAdmin(admin.ModelAdmin):
    list_display = ('name', 'rate_limit', 'concurrency', 'allow_portscan', 'allow_active', 'allow_screens', 'created_at')
    search_fields = ('name', 'in_scope', 'description')
    fieldsets = (
        ('Basic Information', {
            'fields': ('name', 'description')
        }),
        ('Scope Rules', {
            'fields': ('in_scope', 'out_of_scope')
        }),
        ('Rate Limiting & Safety', {
            'fields': ('rate_limit', 'concurrency', 'timeout', 'headers', 'strict_headers')
        }),
        ('Plugin Permission Flags', {
            'fields': ('allow_portscan', 'allow_active', 'allow_screens')
        }),
    )


@admin.register(ScanRun)
class ScanRunAdmin(admin.ModelAdmin):
    list_display = ('run_id', 'program', 'scan_type', 'status', 'started_at', 'completed_at')
    list_filter = ('status', 'scan_type', 'program')
    search_fields = ('run_id', 'target', 'log_output', 'error_message')
    readonly_fields = ('run_id', 'started_at', 'completed_at', 'log_output', 'error_message')


@admin.register(Asset)
class AssetAdmin(admin.ModelAdmin):
    list_display = ('host', 'program', 'status', 'score', 'why', 'title', 'first_seen', 'last_seen', 'last_run', 'react_run')
    list_filter = ('program', 'status', 'score')
    search_fields = ('host', 'title', 'tech', 'why')
    readonly_fields = ('first_seen', 'last_seen')


@admin.register(Endpoint)
class EndpointAdmin(admin.ModelAdmin):
    list_display = ('shape', 'program', 'score', 'why', 'params', 'last_seen', 'last_run', 'react_run')
    list_filter = ('program', 'score')
    search_fields = ('shape', 'example', 'params', 'why')
    readonly_fields = ('first_seen', 'last_seen')


@admin.register(Port)
class PortAdmin(admin.ModelAdmin):
    list_display = ('host', 'port', 'program', 'first_seen', 'last_run')
    list_filter = ('program', 'port')
    search_fields = ('host',)
    readonly_fields = ('first_seen',)


@admin.register(Signal)
class SignalAdmin(admin.ModelAdmin):
    list_display = ('host', 'severity', 'template', 'program', 'first_seen', 'last_run')
    list_filter = ('program', 'severity', 'template')
    search_fields = ('host', 'template', 'matched')
    readonly_fields = ('first_seen',)
