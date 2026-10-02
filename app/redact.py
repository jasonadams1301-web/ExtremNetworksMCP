"""Best-effort secret redaction for switch configuration text.

A running configuration holds SNMP communities, RADIUS/TACACS keys, password hashes, authentication keys and
certificate material. None of that may reach the agent (or OCE's logs), so the config tool redacts before returning
anything. The approach is deliberately blunt: it over-redacts rather than risk a leak, and it can never be perfect, so
callers must still treat the output as sensitive.
"""
import re

REDACTED = "<redacted>"

# words whose NEXT token is always a secret
STRONG = r"(?:password|passwd|passphrase|secret|community|psk|pre-shared-key|token|credentials?)"
# any other word containing 'key' (authentication-key, message-digest-key, encryption-key, key-chain, key ...)
KEYISH = r"[\w-]*key[\w-]*"
# an algorithm word followed by a quoted string is a hashed/encrypted secret (snmp users, ntp keys, ospf digests)
ALGO = r"(?:md5|sha|sha1|sha2|sha224|sha256|sha384|sha512|hmac-[\w-]+|aes|aes128|aes192|aes256|des|3des)"
# SNMP v1/v2c host entries carry the community right after the version word
SNMPVER = r"(?:v1|v2c|v2|v3)"

TOKEN = r'(?:"[^"]*"|\'[^\']*\'|\S+)'

STRONG_RX = re.compile(rf"(?i)(\b{STRONG}\b)(\s+)({TOKEN})")
SNMPVER_RX = re.compile(rf"(?i)(\b{SNMPVER}\b)(\s+)({TOKEN})")
KEYISH_RX = re.compile(rf"(?i)(\b{KEYISH}\b)(\s+)({TOKEN})")
ALGO_RX = re.compile(rf'(?i)(\b{ALGO}\b)(\s+)("[^"]*"|\'[^\']*\')')
QUOTED_BLOB_RX = re.compile(r'"[A-Za-z0-9+/=_.:$-]{16,}"')         # a long quoted token with no spaces
BARE_HEX_RX = re.compile(r"\b[0-9A-Fa-f]{32,}\b")                    # long bare hex (hashes, keys)
CRYPT_RX = re.compile(r"\$[0-9a-z]{1,2}\$[^\s]+")                     # $1$..., $6$... crypt hashes
PEM_BEGIN = re.compile(r"-----BEGIN [A-Z ]+-----")
PEM_END = re.compile(r"-----END [A-Z ]+-----")
SHORT_NUMBER = re.compile(r"\d{1,5}")


def _sub_token(m, count):
    if m.group(3).strip("\"'") == REDACTED:          # already redacted: leave it and do not count it again
        return m.group(0)
    count[0] += 1
    quote = '"' if m.group(3).startswith('"') else ("'" if m.group(3).startswith("'") else "")
    return f"{m.group(1)}{m.group(2)}{quote}{REDACTED}{quote}"


def redact_line(line: str, count: list[int]) -> str:
    out = line
    out = STRONG_RX.sub(lambda m: _sub_token(m, count), out)

    def snmpver(m):
        # after 'v3' the next word is normally a security level (noauth/auth/priv), which is not a secret
        if m.group(1).lower() == "v3" and m.group(3).lower() in ("noauth", "auth", "authpriv", "priv", "authnopriv"):
            return m.group(0)
        return _sub_token(m, count)

    out = SNMPVER_RX.sub(snmpver, out)

    def keyish(m):
        tok = m.group(3)
        # a short plain number after a *-key word is a key id or a length (key-length 2048), not a secret
        if SHORT_NUMBER.fullmatch(tok) and not re.search(r"(?i)password|community|secret", m.group(1)):
            return m.group(0)
        if tok.lower() == REDACTED.lower() or tok.strip("\"'") == REDACTED:
            return m.group(0)
        return _sub_token(m, count)

    out = KEYISH_RX.sub(keyish, out)
    out = ALGO_RX.sub(lambda m: _sub_token(m, count), out)

    def blob(m):
        count[0] += 1
        return f'"{REDACTED}"'

    out = QUOTED_BLOB_RX.sub(blob, out)
    out = BARE_HEX_RX.sub(lambda m: (count.__setitem__(0, count[0] + 1) or REDACTED), out)
    out = CRYPT_RX.sub(lambda m: (count.__setitem__(0, count[0] + 1) or REDACTED), out)
    return out


def redact_config(text: str) -> tuple[str, int]:
    """Return (redacted text, number of redactions). PEM certificate/key blocks are removed entirely."""
    count = [0]
    out, in_pem = [], False
    for line in text.splitlines():
        if in_pem:
            if PEM_END.search(line):
                in_pem = False
            continue
        if PEM_BEGIN.search(line):
            in_pem = not PEM_END.search(line)
            count[0] += 1
            out.append("<redacted: certificate or key block>")
            continue
        out.append(redact_line(line, count))
    return "\n".join(out), count[0]
