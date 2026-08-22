import os

from django.conf import settings
from django.core.management.base import BaseCommand

from accounts.services.keys import generate_rsa_keypair


class Command(BaseCommand):
    help = "Generate RSA private/public key pair for RS256 JWT signing."

    def add_arguments(self, parser):
        parser.add_argument(
            "--force",
            action="store_true",
            help="Overwrite existing keys.",
        )

    def handle(self, *args, **options):
        private_path = settings.JWT_PRIVATE_KEY_PATH
        public_path = settings.JWT_PUBLIC_KEY_PATH

        if not options["force"]:
            for path in (private_path, public_path):
                if os.path.exists(path):
                    self.stderr.write(self.style.ERROR(f"Key already exists: {path} (use --force to overwrite)"))
                    return

        generate_rsa_keypair(private_path, public_path)
        self.stdout.write(self.style.SUCCESS(f"Private key written to {private_path}"))
        self.stdout.write(self.style.SUCCESS(f"Public key written to {public_path}"))
