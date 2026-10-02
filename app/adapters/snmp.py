"""SNMPv3 (authPriv) read-only adapter. Only GET and bulk-walk are implemented; there is no SET.

Credentials (SNMP_USERNAME, SNMP_AUTH_PASSWORD, SNMP_PRIV_PASSWORD) come from systemd credentials and never
appear in results or logs. Every OID must fall under an approved prefix.
"""
import os

from pysnmp.hlapi.v3arch.asyncio import (
    ContextData, ObjectIdentity, ObjectType, SnmpEngine, UdpTransportTarget, UsmUserData,
    bulk_walk_cmd, get_cmd,
    usmAesCfb128Protocol, usmAesCfb256Protocol,
    usmHMACMD5AuthProtocol, usmHMACSHAAuthProtocol, usmHMAC192SHA256AuthProtocol,
)

from app.secrets import get_secret

# Approved read-only subtrees: SNMPv2-MIB system, IF-MIB, ENTITY-MIB/sensors, LLDP-MIB, Extreme enterprise.
ALLOWED_PREFIXES = (
    "1.3.6.1.2.1.1.",       # system
    "1.3.6.1.2.1.2.",       # ifTable
    "1.3.6.1.2.1.31.1.1.",  # ifXTable
    "1.3.6.1.2.1.47.",      # ENTITY-MIB
    "1.0.8802.1.1.2.",      # LLDP-MIB
    "1.3.6.1.4.1.1916.",    # Extreme enterprise (Switch Engine / EXOS)
    "1.3.6.1.4.1.2272.",    # Rapid City enterprise (Fabric Engine / VOSS)
)
AUTH = {"md5": usmHMACMD5AuthProtocol, "sha": usmHMACSHAAuthProtocol, "sha256": usmHMAC192SHA256AuthProtocol}
PRIV = {"aes": usmAesCfb128Protocol, "aes256": usmAesCfb256Protocol}


class SnmpError(RuntimeError):
    pass


def check_oid(oid: str) -> str:
    o = oid.strip(".") + "."
    if not any(o.startswith(p) for p in ALLOWED_PREFIXES):
        raise SnmpError("OID outside approved MIB view")
    return oid


def _proto(table: dict, name: str, what: str):
    try:
        return table[name.lower()]
    except KeyError:
        raise SnmpError(f"unknown {what} protocol {name!r}; choose from {', '.join(sorted(table))}") from None


class SnmpClient:
    def __init__(self, levels: dict[str, str] | None = None):
        # ip -> "noauth" | "authnopriv" for switches the inventory explicitly opts in. Everything else is authPriv.
        self.levels = dict(levels or {})
        self.timeout = int(os.environ.get("SNMP_TIMEOUT_SECONDS", "5"))
        self.retries = int(os.environ.get("SNMP_RETRIES", "1"))
        self.engine = SnmpEngine()

    def _user(self, ip: str | None = None) -> UsmUserData:
        level = self.levels.get(ip, "authpriv") if ip is not None else "authpriv"
        if level in ("noauth", "authnopriv"):
            # Legacy account for switches without an authPriv user. Only used for switches the inventory explicitly marks
            # with snmp_security; a failed authPriv query never falls back to this.
            user = get_secret("SNMP_LEGACY_USERNAME")
            if not user:
                raise SnmpError("SNMPv3 legacy account username is not configured")
            if level == "noauth":
                return UsmUserData(user)                                    # noAuthNoPriv
            pw = get_secret("SNMP_LEGACY_AUTH_PASSWORD")
            if not pw:
                raise SnmpError("SNMPv3 legacy account auth password is not configured")
            return UsmUserData(user, authKey=pw,                           # authNoPriv
                               authProtocol=_proto(AUTH, os.environ.get("SNMP_LEGACY_AUTH_PROTOCOL", "sha"), "auth"))
        user, auth, priv = (get_secret(n) for n in ("SNMP_USERNAME", "SNMP_AUTH_PASSWORD", "SNMP_PRIV_PASSWORD"))
        if not (user and auth and priv):  # authPriv needs all three; never downgrade
            raise SnmpError("SNMPv3 credentials are not configured")
        return UsmUserData(
            user, authKey=auth, privKey=priv,
            authProtocol=_proto(AUTH, os.environ.get("SNMP_AUTH_PROTOCOL", "sha"), "auth"),
            privProtocol=_proto(PRIV, os.environ.get("SNMP_PRIV_PROTOCOL", "aes"), "privacy"),
        )

    async def _target(self, ip: str):
        return await UdpTransportTarget.create((ip, 161), timeout=self.timeout, retries=self.retries)

    async def get(self, ip: str, oids: list[str]) -> dict[str, str]:
        for o in oids:
            check_oid(o)
        err, status, _idx, binds = await get_cmd(
            self.engine, self._user(ip), await self._target(ip), ContextData(),
            *[ObjectType(ObjectIdentity(o)) for o in oids])
        if err or status:
            raise SnmpError(str(err or status.prettyPrint()))
        return {str(n): v.prettyPrint() for n, v in binds}

    async def walk(self, ip: str, oid: str, limit: int = 500) -> dict[str, str]:
        check_oid(oid)
        out: dict[str, str] = {}
        async for err, status, _idx, binds in bulk_walk_cmd(
                self.engine, self._user(ip), await self._target(ip), ContextData(),
                0, 25, ObjectType(ObjectIdentity(oid)), lexicographicMode=False):
            if err or status:
                raise SnmpError(str(err or status.prettyPrint()))
            for n, v in binds:
                out[str(n)] = v.prettyPrint()
            if len(out) >= limit:
                break
        return out
