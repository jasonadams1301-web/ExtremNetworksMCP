"""Interactive CLI session driver, using the transcript shape captured from a Fabric Engine 9.3 switch:
prompt 'HOST:1>', echoed command, '--More-- (q = quit) ' pager, backspace erasure after a key press."""
import asyncio

import pytest

from app.adapters.ssh import SshError, clean_output, drive_session

PROMPT = "SWITCH-1:1>"
ERASE = "\x08 \x08" * 20


class _Out:
    def __init__(self, chunks):
        self.q = list(chunks)

    async def read(self, n):
        while not self.q:
            await asyncio.sleep(0.01)
        return self.q.pop(0)


class _In:
    def __init__(self, on_write):
        self.written, self._cb = [], on_write

    def write(self, data):
        self.written.append(data)
        self._cb(data)


class FakeProc:
    """Scripted switch: shows the prompt, answers the command page by page, honours space / q."""

    def __init__(self, pages):
        self.pages = pages
        self.stdout = _Out(["\r\r\n" + PROMPT])
        self.stdin = _In(self._on_write)
        self.i = 0

    @staticmethod
    def _more():
        return "\r\n--More-- (q = quit) "

    def _on_write(self, data):
        if data.startswith("show"):
            self.stdout.q.append(data.strip() + "\r\r\n" + self.pages[0] + self._more())
            self.i = 1
        elif data == " ":
            last = self.i == len(self.pages) - 1
            self.stdout.q.append(ERASE + self.pages[self.i] + ("\r\n" + PROMPT if last else self._more()))
            self.i += 1
        elif data == "q":
            self.stdout.q.append(ERASE + PROMPT)  # real switch: prompt follows the erasure, no newline


PAGES = ["\r\n".join(f"1 2026-10-01T10:0{p}:0{n}.000-04:00 SW1 CP1 - 0x1 - 0 Mgmt SW INFO line {p}-{n}"
                     for n in range(5)) for p in range(3)]


async def test_driver_pages_through_whole_output_and_cleans_it():
    proc = FakeProc(PAGES)
    out = await drive_session(proc, "show logging file tail", want_lines=None, max_chars=100000, timeout=5)
    assert proc.stdin.written == ["show logging file tail\n", " ", " "]  # only the command and pager keys
    lines = out.splitlines()
    assert len(lines) == 15 and lines[0].endswith("line 0-0") and lines[-1].endswith("line 2-4")
    assert "--More--" not in out and "\x08" not in out and PROMPT not in out and "show logging" not in out


async def test_driver_quits_pager_once_enough_lines():
    proc = FakeProc(PAGES)
    out = await drive_session(proc, "show logging file tail", want_lines=4, max_chars=100000, timeout=5)
    assert proc.stdin.written == ["show logging file tail\n", "q"]
    assert len(out.splitlines()) == 5


async def test_driver_quits_pager_at_character_cap():
    proc = FakeProc(PAGES)
    await drive_session(proc, "show logging file tail", want_lines=None, max_chars=100, timeout=5)
    assert proc.stdin.written == ["show logging file tail\n", "q"]


async def test_driver_times_out_when_switch_goes_silent():
    class Silent(FakeProc):
        def _on_write(self, data):
            pass

    with pytest.raises(SshError, match="timed out"):
        await drive_session(Silent(PAGES), "show sys-info", None, 1000, timeout=0.3)


def test_clean_output_strips_echo_prompt_and_erasures():
    raw = "show sys-info\r\r\nA\r\nB --More-- (q = quit) " + ERASE + "C\r\n" + PROMPT
    assert clean_output(raw, "show sys-info") == "A\nB C"
