"""Running configuration tool (Fabric Engine). Needs privileged mode, so it runs `enable` in its own session and then
only `show running-config`.

By default the COMPLETE configuration is returned, unfiltered, because the readers are network administrators.
Redaction (app/redact.py) is available as an opt-in: set CONFIG_REDACT=true in the service environment. The section
list and the section/search/offset options help an agent with a small context window read part of a long config."""
import os
import re

from app.adapters.ssh import SshClient
from app.redact import redact_config
from app.tools.ssh_tools import CONTAINS_RE, _fabric_ssh
from app.validation import Inventory, ValidationError

HEADER = re.compile(r"^#\s*([A-Z][A-Z0-9 /_.,()-]{3,})\s*$")        # e.g. '# SNMP CONFIGURATION'
NOISE = ("****", "Command Execution Time", "Preparing to Display Configuration")
MAX_LIMIT = 4000
BIG = 900000


def redaction_enabled() -> bool:
    return os.environ.get("CONFIG_REDACT", "false").strip().lower() in ("1", "true", "yes", "on")


def clean_config(text: str) -> list[str]:
    lines = [ln.rstrip() for ln in text.splitlines() if not ln.lstrip().startswith(NOISE)]
    while lines and not lines[0].strip():
        lines.pop(0)
    while lines and not lines[-1].strip():
        lines.pop()
    return lines


def split_sections(lines: list[str]) -> list[dict]:
    heads = [(i, HEADER.match(ln).group(1).strip()) for i, ln in enumerate(lines) if HEADER.match(ln)]
    out = []
    for n, (i, name) in enumerate(heads):
        end = heads[n + 1][0] if n + 1 < len(heads) else len(lines)
        out.append({"name": name, "first_line": i + 1, "last_line": end, "line_count": end - i})
    return out


def _numbered(lines: list[str], indexes) -> list[str]:
    return [f"{i + 1}: {lines[i]}" for i in indexes]


async def get_running_config(inv: Inventory, ssh: SshClient, switch: str, section: str | None = None,
                             search: str | None = None, context: int = 2, offset: int | None = None,
                             limit: int = MAX_LIMIT) -> dict:
    sw = _fabric_ssh(inv, switch)
    if not isinstance(limit, int) or isinstance(limit, bool) or not 1 <= limit <= MAX_LIMIT:
        raise ValidationError(f"limit must be 1-{MAX_LIMIT}")
    if not isinstance(context, int) or isinstance(context, bool) or not 0 <= context <= 5:
        raise ValidationError("context must be 0-5")
    if offset is not None and (not isinstance(offset, int) or isinstance(offset, bool) or offset < 0):
        raise ValidationError("offset must be 0 or more")
    for label, val in (("section", section), ("search", search)):
        if val is not None and not CONTAINS_RE.fullmatch(val):
            raise ValidationError(f"{label}: up to 64 letters, digits, space and . _ : / -")

    raw = (await ssh.run_many(sw.management_ip, [{"key": "running_config", "max_chars": BIG}], timeout=180))[0]
    if redaction_enabled():
        text, redactions = redact_config(raw)
    else:
        text, redactions = raw, None
    lines = clean_config(text)
    sections = split_sections(lines)
    out = {"switch": sw.name, "total_lines": len(lines), "redacted": redactions is not None,
           "sections": [{k: s[k] for k in ("name", "first_line", "line_count")} for s in sections]}
    if redactions is not None:
        out["redactions"] = redactions

    if section:
        hits = [s for s in sections if section.lower() in s["name"].lower()]
        idx = [i for s in hits for i in range(s["first_line"] - 1, s["last_line"])]
        out.update({"mode": "section", "matched_sections": [s["name"] for s in hits], "matched_lines": len(idx),
                    "lines": _numbered(lines, idx[:limit])})
        if len(idx) > limit:
            out["truncated"] = f"{len(idx) - limit} more lines; raise limit (max {MAX_LIMIT})"
    elif search:
        needle = search.lower()
        found = [i for i, ln in enumerate(lines) if needle in ln.lower()]
        keep = sorted({j for i in found for j in range(max(0, i - context), min(len(lines), i + context + 1))})
        out.update({"mode": "search", "matches": len(found), "lines": _numbered(lines, keep[:limit])})
        if len(keep) > limit:
            out["truncated"] = f"{len(keep) - limit} more lines; narrow the search or reduce context"
        if not found:
            out["note_search"] = "no line contains that text; the setting may be absent (or named differently)"
    elif offset is not None:
        out.update({"mode": "lines", "lines": _numbered(lines, range(offset, min(len(lines), offset + limit)))})
    else:
        out["mode"] = "full"
        out["config"] = "\n".join(lines[:limit])
        if len(lines) > limit:
            out["truncated"] = f"{len(lines) - limit} more lines; read the rest with offset={limit}"
    if not lines and raw.strip():
        out["parse_warnings"] = ["no configuration lines recognised"]
    out["note"] = ("running configuration (may differ from the saved boot configuration)"
                   + ("; secrets are redacted on a best-effort basis" if redactions is not None
                      else "; returned unfiltered, so it may contain sensitive values"))
    return out
