from django.core.management.base import BaseCommand, CommandError
from scanner.models import Program, ScanRun
from scanner.services.runner import trigger_scan, ACTIVE_THREADS
import time


class Command(BaseCommand):
    help = "Run Wide, Narrow, or Full recon on a program from the command line"

    def add_arguments(self, parser):
        parser.add_argument("--program", type=str, required=True, help="Program name or ID")
        parser.add_argument("--type", type=str, choices=["wide", "narrow", "full"], default="wide", help="Scan type")
        parser.add_argument("--target", type=str, default=None, help="Target URL (required for narrow scan)")
        parser.add_argument("--wait", action="store_true", help="Wait for the background scan to finish and stream output")

    def handle(self, *args, **options):
        prog_ident = options["program"]
        if prog_ident.isdigit():
            program = Program.objects.filter(id=int(prog_ident)).first()
        else:
            program = Program.objects.filter(name__iexact=prog_ident).first()

        if not program:
            raise CommandError(f"Program '{prog_ident}' not found.")

        scan_type = options["type"]
        target = options["target"]

        if scan_type == "narrow" and not target:
            raise CommandError("--target is required for narrow recon.")

        if scan_type == "narrow" and target and not program.is_url_allowed(target):
            raise CommandError(f"Target '{target}' is OUT OF SCOPE for program '{program.name}'.")

        self.stdout.write(self.style.NOTICE(f"Triggering {scan_type} recon on '{program.name}'..."))
        scan_run = trigger_scan(program, scan_type, target)
        self.stdout.write(self.style.SUCCESS(f"Started Run ID: {scan_run.run_id} (ScanRun PK: {scan_run.pk})"))

        if options["wait"]:
            self.stdout.write("Waiting for scan to complete...")
            last_len = 0
            while True:
                time.sleep(2)
                scan_run.refresh_from_db()
                curr_log = scan_run.log_output or ""
                if len(curr_log) > last_len:
                    diff = curr_log[last_len:]
                    self.stdout.write(diff, ending="")
                    last_len = len(curr_log)
                if scan_run.status in ("completed", "failed", "stopped"):
                    break
            self.stdout.write(self.style.SUCCESS(f"\nScan finished with status: {scan_run.status}"))
