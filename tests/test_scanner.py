from anywifi.scan.scanner import (
    normalize_encryption,
    parse_airodump_csv,
    parse_wash,
)

AIRODUMP_CSV = """\
BSSID, First time seen, Last time seen, channel, Speed, Privacy, Cipher, Authentication, Power, # beacons, # IV, LAN IP, ID-length, ESSID, Key

AA:BB:CC:DD:EE:01, 2025-01-01 10:00:00, 2025-01-01 10:05:00,  6,  54, WPA2, CCMP, PSK, -45,  100,   10,   0.  0.  0.  0,   7, HomeNet,
AA:BB:CC:DD:EE:02, 2025-01-01 10:00:00, 2025-01-01 10:05:00,  1,  54, WEP , WEP , , -70,  50,   200,   0.  0.  0.  0,   6, OldWep,
AA:BB:CC:DD:EE:03, 2025-01-01 10:00:00, 2025-01-01 10:05:00, 11,  54, WPA3, CCMP, SAE, -55,  80,   0,   0.  0.  0.  0,   8, SecureAP,
AA:BB:CC:DD:EE:04, 2025-01-01 10:00:00, 2025-01-01 10:05:00,  6,  54, WPA2 WPA3, CCMP, PSK SAE, -60,  80,   0,   0.  0.  0.  0,   7, MixedAP,
AA:BB:CC:DD:EE:05, 2025-01-01 10:00:00, 2025-01-01 10:05:00,  3,  54, OPN , , , -50,  80,   0,   0.  0.  0.  0,   4, Free,

Station MAC, First time seen, Last time seen, Power, # packets, BSSID, Probed ESSIDs

11:22:33:44:55:66, 2025-01-01 10:00:00, 2025-01-01 10:05:00, -50, 20, AA:BB:CC:DD:EE:01,
11:22:33:44:55:77, 2025-01-01 10:00:00, 2025-01-01 10:05:00, -50, 20, AA:BB:CC:DD:EE:01,
"""


def _by_bssid(nets):
    return {n.bssid: n for n in nets}


def test_parse_airodump_counts():
    nets = parse_airodump_csv(AIRODUMP_CSV)
    assert len(nets) == 5


def test_parse_airodump_fields():
    nets = _by_bssid(parse_airodump_csv(AIRODUMP_CSV))

    wpa2 = nets["AA:BB:CC:DD:EE:01"]
    assert wpa2.essid == "HomeNet"
    assert wpa2.encryption == "WPA2"
    assert wpa2.channel == 6
    assert wpa2.signal == -45
    assert len(wpa2.clients) == 2

    assert nets["AA:BB:CC:DD:EE:02"].encryption == "WEP"
    assert nets["AA:BB:CC:DD:EE:03"].encryption == "WPA3"
    assert nets["AA:BB:CC:DD:EE:03"].pmf == "required"
    assert nets["AA:BB:CC:DD:EE:04"].encryption == "WPA2/WPA3"
    assert nets["AA:BB:CC:DD:EE:04"].is_transition
    assert nets["AA:BB:CC:DD:EE:05"].encryption == "OPEN"


def test_normalize_encryption():
    assert normalize_encryption("OPN") == "OPEN"
    assert normalize_encryption("WEP") == "WEP"
    assert normalize_encryption("WPA2", "PSK") == "WPA2"
    assert normalize_encryption("WPA3", "SAE") == "WPA3"
    assert normalize_encryption("WPA2 WPA3", "PSK SAE") == "WPA2/WPA3"
    assert normalize_encryption("WPA2-Personal", "WPA2-Personal") == "WPA2"


def test_parse_wash():
    text = """\
BSSID               Ch  dBm  WPS  Lck  ESSID
AA:BB:CC:DD:EE:01    6  -45  2.0  No   HomeNet
AA:BB:CC:DD:EE:99    1  -60  1.0  No   Another
"""
    bssids = parse_wash(text)
    assert "AA:BB:CC:DD:EE:01" in bssids
    assert "AA:BB:CC:DD:EE:99" in bssids


def test_parse_wash_excludes_locked():
    # A locked AP advertises WPS but refuses it — must NOT be a WPS target.
    text = """\
BSSID               Ch  dBm  WPS  Lck  ESSID
AA:BB:CC:DD:EE:01    6  -45  2.0  No   OpenWps
AA:BB:CC:DD:EE:02    6  -50  2.0  Yes  LockedWps
"""
    bssids = parse_wash(text)
    assert "AA:BB:CC:DD:EE:01" in bssids
    assert "AA:BB:CC:DD:EE:02" not in bssids


def test_parse_wash_unlocked_if_ever_seen_open():
    # Seen locked once then unlocked → treat as usable.
    text = """\
AA:BB:CC:DD:EE:03    6  -45  2.0  Yes  Flaky
AA:BB:CC:DD:EE:03    6  -45  2.0  No   Flaky
"""
    assert "AA:BB:CC:DD:EE:03" in parse_wash(text)
