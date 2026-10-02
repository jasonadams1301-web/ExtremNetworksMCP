"""Small helpers for reading Fabric Engine's fixed-width text tables."""
import re

BANNER_PREFIXES = ("*", "=", "-", "Command Execution")


def body_lines(text: str) -> list[str]:
    """Output lines without the asterisk banner, '=' and '-' rules (blank lines kept: they end wrapped cells)."""
    return [ln.rstrip() for ln in text.splitlines()
            if not ln.strip().startswith(BANNER_PREFIXES)]


def column_starts(header: str, names: list[str]) -> list[int]:
    """Start offsets of each named column in a header line (names may contain spaces; searched left to right)."""
    starts, pos = [], 0
    for name in names:
        i = header.find(name, pos)
        if i < 0:
            raise ValueError(f"column {name!r} not found in header")
        starts.append(i)
        pos = i + len(name)
    return starts


def slice_row(line: str, starts: list[int]) -> list[str]:
    cells = []
    for i, st in enumerate(starts):
        end = starts[i + 1] if i + 1 < len(starts) else len(line) + 1
        cells.append(line[st:end].strip())
    return cells


def count_ports(spec: str) -> int | None:
    """Number of ports in a range list such as '1/1-1/2,1/5-1/45,1/48'. None if it cannot be counted."""
    if not spec.strip():
        return 0
    total = 0
    for tok in spec.replace(" ", "").split(","):
        if not tok:
            continue
        m = re.fullmatch(r"(\d+)/(\d+)(?:-(\d+)/(\d+))?", tok)
        if not m:
            return None
        if m.group(3) is None:
            total += 1
        elif m.group(1) == m.group(3):
            total += int(m.group(4)) - int(m.group(2)) + 1
        else:
            return None            # spans slots/units: leave uncounted rather than guess
    return total
