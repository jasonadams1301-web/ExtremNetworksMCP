"""Secret lookup: systemd credentials first, environment variable as a local-testing fallback.

Under systemd, LoadCredential= places each secret as a file in $CREDENTIALS_DIRECTORY (a private
tmpfs visible only to this service). The file name is the lowercased setting name,
e.g. SNMP_AUTH_PASSWORD -> snmp_auth_password.
"""
import os


def get_secret(name: str) -> str | None:
    cred_dir = os.environ.get("CREDENTIALS_DIRECTORY")
    if cred_dir:
        path = os.path.join(cred_dir, name.lower())
        if os.path.isfile(path):
            with open(path, encoding="utf-8") as f:
                value = f.read().strip()
            if value:
                return value
    return os.environ.get(name) or None
