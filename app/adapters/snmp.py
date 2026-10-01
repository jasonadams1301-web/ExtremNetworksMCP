"""SNMPv3 (authPriv) read-only adapter. Only GET and bulk-walk are implemented; there is no SET.

Credentials (SNMP_USERNAME, SNMP_AUTH_PASSWORD, SNMP_PRIV_PASSWORD) come from systemd credentials and never
appear in results or logs. Every OID must fall under an approved prefix.
"""
import os

from pysnmp.hlapi.v3arch.asyncio import (
    ContextData, ObjectIdentity, ObjectType, SnmpEngine, UdpTransportTarget, UsmUserData,
    bulk_walk_cmd, get_cmd,
    usmAesCfb128Protocol, usmAesCfb256Protocol,
    usmHMACSHAAuthProtocol, usmHMAC192SHA256AuthProtocol,
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
AUTH = {"sha": usmHMACSHAAuthProtocol, "sha256": usmHMAC192SHA256AuthProtocol}
PRIV = {"aes": usmAesCfb128Protocol, "aes256": usmAesCfb256Protocol}


class SnmpError(RuntimeError):
    pass


def check_oid(oid: str) -> str:
    o = oid.strip(".") + "."
    if not any(o.startswith(p) for p in ALLOWED_PREFIXES):
        raise SnmpError("OID outside approved MIB view")
    return oid


class SnmpClient:
    def __init__(self):
        self.timeout = int(os.environ.get("SNMP_TIMEOUT_SECONDS", "5"))
        self.retries = int(os.environ.get("SNMP_RETRIES", "1"))
        self.engine = SnmpEngine()

    def _user(self) -> UsmUserData:
        user, auth, priv = (get_secret(n) for n in ("SNMP_USERNAME", "SNMP_AUTH_PASSWORD", "SNMP_PRIV_PASSWORD"))
        if not (user and auth and priv):  # authPriv needs all three; never downgrade
            raise SnmpError("SNMPv3 credentials are not configured")
        return UsmUserData(
            user, authKey=auth, privKey=priv,
            authProtocol=AUTH[os.environ.get("SNMP_AUTH_PROTOCOL", "sha")],
            privProtocol=PRIV[os.environ.get("SNMP_PRIV_PROTOCOL", "aes")],
        )

    async def _target(self, ip: str):
        return await UdpTransportTarget.create((ip, 161), timeout=self.timeout, retries=self.retries)

    async def get(self, ip: str, oids: list[str]) -> dict[str, str]:
        for o in oids:
            check_oid(o)
        err, status, _idx, binds = await get_cmd(
            self.engine, self._user(), await self._target(ip), ContextData(),
            *[ObjectType(ObjectIdentity(o)) for o in oids])
        if err or status:
            raise SnmpError(str(err or status.prettyPrint()))
        return {str(n): v.prettyPrint() for n, v in binds}

    async def walk(self, ip: str, oid: str, limit: int = 500) -> dict[str, str]:
        check_oid(oid)
        out: dict[str, str] = {}
        async for err, status, _idx, binds in bulk_walk_cmd(
                self.engine, self._user(), await self._target(ip), ContextData(),
                0, 25, ObjectType(ObjectIdentity(oid)), lexicographicMode=False):
            if err or status:
                raise SnmpError(str(err or status.prettyPrint()))
            for n, v in binds:
                out[str(n)] = v.prettyPrint()
            if len(out) >= limit:
                break
        return out
