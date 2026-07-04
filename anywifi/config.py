"""Constants, defaults and path definitions."""

from __future__ import annotations

import os
from pathlib import Path

APP_NAME = "AnyWifi"
LOOT_DIR = "loot"

# --- Timings (seconds) ---
DEFAULT_SCAN_TIME = 25          # airodump scan duration
PMKID_CAPTURE_TIME = 45         # hcxdumptool PMKID capture duration
HANDSHAKE_CAPTURE_TIME = 60     # handshake wait time
DEAUTH_COUNT = 6                # deauth packets sent per round
WPS_PIXIE_TIMEOUT = 180         # reaver pixie-dust upper bound
WEP_ATTACK_TIME = 600           # WEP IV collection upper bound
DRAGONTIME_DURATION = 90        # dragontime timing measurement duration

# WPA3 Dragonblood timing side-channel (experimental).
# Timing only leaks if the AP enables MODP group 22/23/24 (most don't).
DRAGONTIME_GROUP = 24
DRAGONTIME_WAIT_MS = 250        # -i: wait after a reply
DRAGONTIME_TIMEOUT_MS = 750     # -t: retransmit timeout

# --- Wordlist search paths (tried in order) ---
def _rockyou_candidates() -> list[str]:
    home = Path.home()
    cands = [
        os.environ.get("ANYWIFI_WORDLIST", ""),
        "/usr/share/wordlists/rockyou.txt",
        "/usr/share/wordlists/rockyou.txt.gz",
        "/usr/share/wordlists/rockyou/rockyou.txt",
        "/usr/share/dict/rockyou.txt",
        "/opt/wordlists/rockyou.txt",
        str(home / "rockyou.txt"),
        str(home / "wordlists" / "rockyou.txt"),
        "rockyou.txt",
    ]
    return [c for c in cands if c]


ROCKYOU_PATHS = _rockyou_candidates()

# --- Encryption ease weights (scoring) ---
# Higher = easier to crack = higher priority.
ENCRYPTION_WEIGHTS = {
    "OPEN": 100,
    "WEP": 90,
    "WPA": 55,
    "WPA2": 50,
    "WPA2/WPA3": 40,   # transition (mixed) — the WPA2 side is targetable
    "WPA3": 5,         # pure SAE — offline dictionary infeasible
    "UNKNOWN": 30,
}

# Scoring bonuses
WPS_BONUS = 60          # WPS enabled → chance of pixie-dust
CLIENT_BONUS_EACH = 8   # each connected client (a deauth target for handshakes)
CLIENT_BONUS_MAX = 32

# Signal: map -30 dBm (very strong) .. -90 dBm (weak) onto 0..40
SIGNAL_SCORE_MAX = 40

# Noise floor: networks weaker than this dBm are filtered out by default
MIN_SIGNAL_DBM = -85

# --- External tools ---
AIRCRACK_SUITE = ["airmon-ng", "airodump-ng", "aireplay-ng", "aircrack-ng"]
HCX_TOOLS = ["hcxdumptool", "hcxpcapngtool"]
WPS_TOOLS = ["reaver", "wash"]
OPTIONAL_TOOLS = ["bully", "hashcat", "iw", "wpa_supplicant"]

# hashcat mode: unified WPA-PBKDF2-PMKID+EAPOL
HASHCAT_MODE_22000 = "22000"
