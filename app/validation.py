"""Inventory allowlist and input validation. Nothing reaches a switch unless it passes here."""
import re
from dataclasses import dataclass

import yaml

PORT_RE = re.compile(r"[0-9]{1,3}(:[0-9]{1,3})?")  # EXOS port: 48 or 1:48
NAME_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}")


class ValidationError(ValueError):
    pass


@dataclass(frozen=True)
class Switch:
    name: str
    management_ip: str
    platform: str
    site: str
    protocols: tuple[str, ...]


class Inventory:
    def __init__(self, switches: list[Switch]):
        self._by_name = {s.name.lower(): s for s in switches}

    @classmethod
    def load(cls, path: str) -> "Inventory":
        with open(path, encoding="utf-8") as f:
            data = yaml.safe_load(f) or {}
        switches = [
            Switch(
                name=str(e["name"]),
                management_ip=str(e["management_ip"]),
                platform=str(e.get("platform", "exos")),
                site=str(e.get("site", "")),
                protocols=tuple(e.get("protocols", [])),
            )
            for e in data.get("switches", [])
            if e.get("mcp_enabled") is True
        ]
        return cls(switches)

    def all(self) -> list[Switch]:
        return sorted(self._by_name.values(), key=lambda s: s.name)

    def resolve(self, name: str, protocol: str = "snmpv3") -> Switch:
        """Resolve a switch by inventory name only. IPs and arbitrary hostnames are rejected."""
        if not isinstance(name, str) or not NAME_RE.fullmatch(name):
            raise ValidationError("invalid switch name")
        sw = self._by_name.get(name.lower())
        if sw is None:
            raise ValidationError("switch is not in the approved inventory")
        if protocol not in sw.protocols:
            raise ValidationError(f"{protocol} is not enabled for this switch")
        return sw


def validate_port(port: str) -> str:
    if not isinstance(port, str) or not PORT_RE.fullmatch(port):
        raise ValidationError("invalid port; expected e.g. 48 or 1:48")
    return port
