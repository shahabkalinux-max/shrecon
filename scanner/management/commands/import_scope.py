import json
import os
from django.core.management.base import BaseCommand, CommandError
from scanner.models import Program


class Command(BaseCommand):
    help = "Import a scope.json file into a Django Program model"

    def add_argument(self, parser):
        pass

    def add_arguments(self, parser):
        parser.add_argument("scope_file", type=str, help="Path to scope.json")
        parser.add_argument("--name", type=str, default=None, help="Name for the program (defaults to filename)")

    def handle(self, *args, **options):
        path = options["scope_file"]
        if not os.path.exists(path):
            raise CommandError(f"Scope file '{path}' not found.")

        with open(path) as f:
            try:
                data = json.load(f)
            except Exception as e:
                raise CommandError(f"Invalid JSON in {path}: {e}")

        name = options["name"] or os.path.splitext(os.path.basename(path))[0].capitalize()
        in_scope = "\n".join(data.get("in_scope", []))
        out_of_scope = "\n".join(data.get("out_of_scope", []))

        program, created = Program.objects.update_or_create(
            name=name,
            defaults={
                "in_scope": in_scope,
                "out_of_scope": out_of_scope,
                "rate_limit": int(data.get("rate_limit", 5)),
                "concurrency": int(data.get("concurrency", 2)),
                "timeout": int(data.get("timeout", 300)),
                "headers": data.get("headers", {}),
                "strict_headers": bool(data.get("strict_headers", False)),
                "allow_portscan": bool(data.get("allow_portscan", False)),
                "allow_active": bool(data.get("allow_active", False)),
                "allow_screens": bool(data.get("allow_screens", True)),
            }
        )

        status_str = "Created" if created else "Updated"
        self.stdout.write(self.style.SUCCESS(f"{status_str} Program '{program.name}' (ID: {program.id}) from {path}"))
