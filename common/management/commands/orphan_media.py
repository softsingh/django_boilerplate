import os
from django.conf import settings
from django.core.management.base import BaseCommand
from django.apps import apps
from django.db.models import FileField, ImageField


class Command(BaseCommand):
    help = "List or delete orphaned files in MEDIA_ROOT not referenced in any model."

    def add_arguments(self, parser):
        parser.add_argument(
            "-l", "--list", action="store_true", help="List orphaned media files"
        )
        parser.add_argument(
            "-d", "--delete", action="store_true", help="Delete orphaned media files"
        )
        parser.add_argument(
            "--yes", action="store_true", help="Skip delete confirmation"
        )

    def handle(self, *args, **options):
        list_only = options["list"]
        delete_files = options["delete"]

        if not list_only and not delete_files:
            self.stdout.write(
                self.style.WARNING("Please provide an action: --list/-l or --delete/-d")
            )
            return

        media_root = os.path.abspath(settings.MEDIA_ROOT or "")
        if not media_root or not os.path.exists(media_root):
            self.stdout.write(self.style.ERROR(f"Invalid MEDIA_ROOT: {media_root}"))
            return

        def is_under(root: str, path: str) -> bool:
            root = os.path.realpath(root)
            path = os.path.realpath(path)
            return path == root or path.startswith(root + os.sep)

        self.stdout.write("Collecting referenced files from the database...")
        referenced_files = set()

        for model in apps.get_models():
            for field in model._meta.fields:
                if isinstance(field, (FileField, ImageField)):
                    try:
                        for obj in model.objects.iterator(chunk_size=2000):
                            file_field = getattr(obj, field.name)
                            if not file_field:
                                continue
                            try:
                                p = os.path.realpath(file_field.path)
                            except (ValueError, OSError):
                                # Path not available or invalid
                                continue
                            if os.path.exists(p) and is_under(media_root, p):
                                referenced_files.add(p)
                    except Exception as e:
                        self.stdout.write(
                            self.style.ERROR(
                                f"Error scanning model {model.__name__}: {e}"
                            )
                        )

        self.stdout.write("Scanning media directory for orphan files...")
        orphan_files = []
        scanned_count = 0

        try:
            for root, dirs, files in os.walk(media_root):
                for filename in files:
                    file_path = os.path.realpath(os.path.join(root, filename))
                    scanned_count += 1
                    if file_path not in referenced_files:
                        orphan_files.append(file_path)
        except Exception as e:
            self.stdout.write(self.style.ERROR(f"Error scanning {media_root}: {e}"))
            return

        if list_only:
            if orphan_files:
                self.stdout.write(
                    self.style.WARNING(f"{len(orphan_files)} orphaned files found:")
                )
                for f in orphan_files:
                    self.stdout.write(f)
            else:
                self.stdout.write(self.style.SUCCESS("No orphaned files found."))

        if delete_files:
            if orphan_files:
                if not options["yes"]:
                    confirm = input(
                        f"Delete {len(orphan_files)} files? Type 'yes' to confirm: "
                    )
                    if confirm.lower() != "yes":
                        self.stdout.write(self.style.WARNING("Aborted."))
                        return

                deleted_count = 0
                for f in orphan_files:
                    if not is_under(media_root, f):
                        self.stdout.write(
                            self.style.ERROR(f"Skipping suspicious path: {f}")
                        )
                        continue
                    try:
                        os.remove(f)
                        deleted_count += 1
                        self.stdout.write(self.style.WARNING(f"Deleted: {f}"))
                    except Exception as e:
                        self.stdout.write(self.style.ERROR(f"Error deleting {f}: {e}"))
                self.stdout.write(
                    self.style.SUCCESS(f"Deleted {deleted_count} orphan files.")
                )
            else:
                self.stdout.write(self.style.SUCCESS("No orphaned files to delete."))

        self.stdout.write(
            self.style.SUCCESS(f"Scan complete: {scanned_count} files checked.")
        )
