"""One sanitized JSON audit event per tool call (no credentials, no raw SNMP payloads)."""
import functools
import json
import logging
import time
import uuid
from datetime import datetime, timezone

log = logging.getLogger("extreme-mcp.audit")
REQUESTER = "openclaw-network-agent"  # OCE gives no caller identity over loopback HTTP


class Audit:
    def __init__(self, path: str | None):
        self._path = path

    def emit(self, event: dict) -> None:
        line = json.dumps(event, separators=(",", ":"))
        log.info(line)
        if self._path:
            with open(self._path, "a", encoding="utf-8") as f:
                f.write(line + "\n")

    def tool(self, name: str, backend: str):
        """Decorator for an async tool(**params). Params named `switch` become the audit target."""
        def deco(fn):
            @functools.wraps(fn)
            async def wrapper(**params):
                start = time.monotonic()
                result = "success"
                try:
                    return await fn(**params)
                except Exception as e:
                    result = f"error:{type(e).__name__}"
                    raise
                finally:
                    self.emit({
                        "timestamp": datetime.now(timezone.utc).isoformat(timespec="seconds"),
                        "request_id": uuid.uuid4().hex,
                        "requester": REQUESTER,
                        "tool": name,
                        "target": params.get("switch"),
                        "parameters": {k: v for k, v in params.items() if k != "switch"},
                        "backend": backend,
                        "result": result,
                        "duration_ms": int((time.monotonic() - start) * 1000),
                    })
            return wrapper
        return deco
