"""802.1X (EAPOL) client counts and RADIUS reachability. Any line mentioning a password is masked: the switch
prints its reachability test credentials, and secrets must never be passed on."""
import re

from app.adapters.ssh import SshClient
from app.tools.ssh_tools import _fabric_ssh
from app.validation import Inventory

COUNT = re.compile(r"^\s*(.+?\(total\)):\s*(\d+)\s*$")
KV = re.compile(r"^\s*([A-Za-z][A-Za-z0-9 _/-]*?)\s*:\s*(.*?)\s*$")
SECRETISH = re.compile(r"pass(word|wd)?|secret|key|community", re.I)


def parse_eapol(text: str) -> dict[str, int]:
    out = {}
    for ln in text.splitlines():
        m = COUNT.match(ln)
        if m:
            out[re.sub(r"\s*\(total\)", "", m.group(1)).strip()] = int(m.group(2))
    return out


def parse_reachability(text: str) -> dict[str, str]:
    out = {}
    for ln in text.splitlines():
        if ln.strip().startswith(("*", "Command Execution")):
            continue
        m = KV.match(ln)
        if m:
            key, val = m.group(1).strip(), m.group(2)
            out[key] = "<hidden>" if SECRETISH.search(key) else val
    return out


async def get_auth_status(inv: Inventory, ssh: SshClient, switch: str) -> dict:
    sw = _fabric_ssh(inv, switch)
    eap_t, rad_t = await ssh.run_many(sw.management_ip, [{"key": "eapol_summary"}, {"key": "radius_reachability"}])
    eapol, rad = parse_eapol(eap_t), parse_reachability(rad_t)
    status = next((v for k, v in rad.items() if "reachability status" in k.lower()), None)
    out = {"switch": sw.name, "eapol_clients": eapol, "radius_reachability": rad,
           "attention": ([f"RADIUS reachability is '{status}'"] if status and status.lower() != "reachable" else []),
           "note": "this reports the switch's own 802.1X/RADIUS reachability test; it does not cover RADIUS used for "
                   "management logins. Credential fields are hidden."}
    if not eapol and not rad and (eap_t.strip() or rad_t.strip()):
        out["parse_warnings"] = ["could not parse 802.1X / RADIUS output; raw output attached"]
        out["raw_output"] = {"eapol": SECRETISH.sub("<hidden>", eap_t)[:1500], "radius": "<withheld: may contain credentials>"}
    return out
