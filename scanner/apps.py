from django.apps import AppConfig
import sys


class ScannerConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'scanner'

    def ready(self):
        # When Django server starts up, mark any orphaned scans from previous killed session as 'stopped'
        is_server_run = any(cmd in sys.argv for cmd in ['runserver', 'gunicorn', 'uwsgi', 'daphne'])
        if is_server_run:
            try:
                from .models import ScanRun
                from django.utils import timezone
                orphans = ScanRun.objects.filter(status__in=['pending', 'running'])
                count = orphans.count()
                if count > 0:
                    orphans.update(
                        status='stopped',
                        completed_at=timezone.now(),
                        error_message="Process was stopped because the server was shut down or restarted."
                    )
                    print(f"[*] Reset {count} orphaned scan run(s) from previous session to 'stopped'.")
            except Exception:
                pass
