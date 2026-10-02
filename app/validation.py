"""Inventory allowlist and input validation. Nothing reaches a switch unless it passes here."""
import re
from dataclasses import dataclass

import yaml

# Port label formats per platform: Fabric Engine 1/1 or 1/1/1 (channelized); Switch Engine (EXOS) 48 or 1:48
PORT_RES = {
    "fabric": re.compile(r"[0-9]{1,3}/[0-9]{1,3}(/[0-9]{1,2})?"),
    "exos": re.compile(r"[0-9]{1,3}(:[0-9]{1,3})?"),
}
PLATFORM_ALIASES = {"fabric": "fabric", "fabric-engine": "fabric", "voss": "fabric",
                    "exos": "exos", "switch-engine": "exos"}
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
    snmp_security: str = "authpriv"      # "authpriv" (default), or an explicit per-switch opt-in: "authnopriv" / "noauth"


SNMP_SECURITY = {"authpriv": "authpriv", "authnopriv": "authnopriv", "noauth": "noauth", "noauthnopriv": "noauth"}


def _snmp_security(raw, name: str) -> str:
    key = str(raw if raw is not None else "authpriv").lower().replace("-", "").replace("_", "").replace(" ", "")
    if key not in SNMP_SECURITY:
        raise ValueError(f"switch {name}: snmp_security must be 'authpriv', 'authnopriv' or 'noauth', not {raw!r}")
    return SNMP_SECURITY[key]


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
                platform=PLATFORM_ALIASES[str(e.get("platform", "fabric")).lower()],
                site=str(e.get("site", "")),
                protocols=tuple(e.get("protocols", [])),
                snmp_security=_snmp_security(e.get("snmp_security"), str(e["name"])),
            )
            for e in data.get("switches", [])
            if e.get("mcp_enabled") is True
        ]
        return cls(switches)

    def ip_of(self, name: str) -> str | None:
        sw = self._by_name.get(name.lower()) if isinstance(name, str) else None
        return sw.management_ip if sw else None

    def snmp_levels(self) -> dict[str, str]:
        """Management IP -> level for switches explicitly marked authnopriv/noauth. Everything else is authPriv."""
        return {s.management_ip: s.snmp_security for s in self._by_name.values() if s.snmp_security != "authpriv"}

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


def validate_port(port: str, platform: str = "fabric") -> str:
    rx = PORT_RES.get(platform)
    if rx is None or not isinstance(port, str) or not rx.fullmatch(port):
        example = "1/1 or 1/1/1" if platform == "fabric" else "48 or 1:48"
        raise ValidationError(f"invalid port; expected e.g. {example}")
    return port
