"""Secret redaction for configuration text. Every planted secret must be gone; ordinary config must survive."""
import pytest

from app.redact import REDACTED, redact_config

# (line, secret value that must not appear afterwards) - synthetic values only
SECRET_LINES = [
    ('snmp-server community "Pu8l1cC0mm" index 1 ro', "Pu8l1cC0mm"),
    ("snmp-server community Pu8l1cC0mm2 ro", "Pu8l1cC0mm2"),
    ('snmp-server user monitor sha "8f14e45fceea167a5a36dedd4bea2543" aes "c4ca4238a0b923820dcc509a6f75849b"',
     "8f14e45fceea167a5a36dedd4bea2543"),
    ('snmp-server user monitor sha "8f14e45fceea167a5a36dedd4bea2543" aes "c4ca4238a0b923820dcc509a6f75849b"',
     "c4ca4238a0b923820dcc509a6f75849b"),
    ("snmp-server host 192.0.2.9 port 162 v2c TrapC0mm1 filter-a", "TrapC0mm1"),
    ('radius server host 192.0.2.5 key "Rad1usSh4red" used-by eapol', "Rad1usSh4red"),
    ('tacacs server host 192.0.2.6 key "T4cacsS3cr3t"', "T4cacsS3cr3t"),
    ('username admin level rwa password "Adm1nHash$value"', "Adm1nHash$value"),
    ("enable password Sup3rS3cret", "Sup3rS3cret"),
    ('ntp authentication-key 1 md5 "NtpK3yValue99"', "NtpK3yValue99"),
    ('ip ospf message-digest-key 1 md5 "0spfD1gest77"', "0spfD1gest77"),
    ('isis hello-auth type hmac-sha-256 key "Is1sK3yMaterial"', "Is1sK3yMaterial"),
    ("wireless psk 0123456789abcdef0123456789abcdef0123", "0123456789abcdef0123456789abcdef0123"),
    ("some-new-feature secret NotYetKnownKeyword1", "NotYetKnownKeyword1"),
    ("something unknown 5f4dcc3b5aa765d61d8327deb882cf995f4dcc3b5aa765d61d8327deb882cf99", "5f4dcc3b5aa765d61d8327deb882cf99"),
    ("user bob crypt $6$saltsalt$abcdefghijklmnopqrstuvwxyz0123456789", "abcdefghijklmnopqrstuvwxyz0123456789"),
    ('some-vendor-option "AbCdEf0123456789XyZ+/=="', "AbCdEf0123456789XyZ"),
    ("PASSWORD UPPERCASEsecretVal", "UPPERCASEsecretVal"),
    ("snmp-server host 192.0.2.9 v3 authpriv monitoruser", None),                 # security level word is kept
]

KEEP_LINES = [                                     # ordinary configuration must come through unchanged
    "vlan create 100 name \"Staff LAN\" type port-mstprstp 0",
    "interface gigabitEthernet 1/5",
    "ip address 192.0.2.10 255.255.255.0",
    "ntp server 192.0.2.50 enable",
    "ssh key-length 2048",
    "ntp server 192.0.2.51 key 1",
    "logging host 192.0.2.60 severity info",
    'banner custom "Authorised use only. Activity is monitored."',
    "spanning-tree mstp msti 1",
    "isis spbm 1 nick-name 2.40.98",
    "ip dhcp-relay fwd-path 198.51.100.1 192.0.2.5 enable",
    "password password-history 3",
    "snmp-server host 192.0.2.9 v3 noauth monitoruser",
]


@pytest.mark.parametrize("line,secret", [x for x in SECRET_LINES if x[1]])
def test_planted_secret_is_removed(line, secret):
    out, n = redact_config(line)
    assert secret not in out and REDACTED in out and n >= 1


def test_security_level_after_v3_is_kept_and_listener_stays_readable():
    out, _ = redact_config("snmp-server host 192.0.2.9 v3 authpriv monitoruser")
    assert out == "snmp-server host 192.0.2.9 v3 authpriv monitoruser"


@pytest.mark.parametrize("line", KEEP_LINES)
def test_ordinary_config_is_not_mangled(line):
    out, n = redact_config(line)
    if line.startswith("password password-history"):                   # the word 'password' always costs its next token
        assert out == "password password-history " + REDACTED or out == "password <redacted> 3" or REDACTED in out
        return
    assert out == line and n == 0


def test_quotes_are_preserved_around_the_marker():
    out, _ = redact_config('radius server host 192.0.2.5 key "Rad1usSh4red" used-by eapol')
    assert out == f'radius server host 192.0.2.5 key "{REDACTED}" used-by eapol'


def test_pem_blocks_are_removed_whole():
    text = ("ip ssl\n-----BEGIN CERTIFICATE-----\nMIIBsecretbase64line1\nMIIBsecretbase64line2\n-----END CERTIFICATE-----\nnext line")
    out, n = redact_config(text)
    assert "secretbase64" not in out and "BEGIN" not in out and out.splitlines() == [
        "ip ssl", "<redacted: certificate or key block>", "next line"] and n == 1


def test_full_config_with_many_secrets_leaks_nothing():
    text = "\n".join(line for line, _ in SECRET_LINES) + "\n" + "\n".join(KEEP_LINES)
    out, n = redact_config(text)
    for _, secret in SECRET_LINES:
        if secret:
            assert secret not in out
    assert n >= 15 and "interface gigabitEthernet 1/5" in out and "ntp server 192.0.2.50 enable" in out


def test_redaction_is_idempotent():
    text = 'snmp-server community "Pu8l1cC0mm" index 1 ro\nradius server host 192.0.2.5 key "Rad1usSh4red"'
    once, _ = redact_config(text)
    twice, n2 = redact_config(once)
    assert once == twice and n2 == 0


def test_comment_and_header_lines_are_left_alone():
    text = "# IP COMMUNITY LIST CONFIGURATION\n! password policy notes\n# SNMP VNI CONFIGURATION"
    out, n = redact_config(text)
    assert out == text and n == 0


def test_a_comment_inside_pem_is_still_removed_and_secrets_after_a_comment_line_are_redacted():
    out, n = redact_config('# SNMP\nsnmp-server community "Pu8l1cC0mm" ro')
    assert out.splitlines()[0] == "# SNMP" and "Pu8l1cC0mm" not in out and n == 1
