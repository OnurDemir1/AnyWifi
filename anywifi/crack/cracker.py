"""Wordlist resolution and hash/handshake cracking (hashcat 22000 / aircrack-ng)."""

from __future__ import annotations

import gzip
import os
import re
import shutil
import tempfile
from typing import Optional

from anywifi.config import HASHCAT_MODE_22000, ROCKYOU_PATHS
from anywifi.core.runner import Runner

_KEY_FOUND_RE = re.compile(r"KEY FOUND!\s*\[\s*(.+?)\s*\]")


# --------------------------------------------------------------------------
# Wordlist discovery
# --------------------------------------------------------------------------
def _ensure_plain(path: str) -> str:
    """If `.gz`, extract to plain text and return that path; otherwise return as-is."""
    if not path.endswith(".gz"):
        return path
    dest = os.path.join(tempfile.gettempdir(), "anywifi_" + os.path.basename(path)[:-3])
    if not os.path.exists(dest) or os.path.getsize(dest) == 0:
        with gzip.open(path, "rb") as src, open(dest, "wb") as out:
            shutil.copyfileobj(src, out)
    return dest


def find_wordlist(override: Optional[str] = None, prompt: bool = True) -> Optional[str]:
    """Resolve the wordlist: override → known rockyou paths → ask the user."""
    if override:
        if os.path.exists(override):
            return _ensure_plain(override)
        print(f"[!] Wordlist not found: {override}")

    for cand in ROCKYOU_PATHS:
        if cand and os.path.exists(cand):
            return _ensure_plain(cand)

    if not prompt:
        return None

    print("[!] rockyou.txt not found. Enter a wordlist path (empty = cancel):")
    try:
        entered = input("wordlist> ").strip().strip('"')
    except (EOFError, KeyboardInterrupt):
        return None
    if entered and os.path.exists(entered):
        return _ensure_plain(entered)
    if entered:
        print(f"[!] Path not found: {entered}")
    return None


# --------------------------------------------------------------------------
# hashcat mode 22000 (PMKID + EAPOL)
# --------------------------------------------------------------------------
def crack_22000(runner: Runner, hash_file: str, wordlist: str) -> Optional[str]:
    if not runner.has("hashcat") and not runner.dry_run:
        return None
    outfile = hash_file + ".cracked"
    cmd = [
        "hashcat", "-m", HASHCAT_MODE_22000, "-a", "0",
        hash_file, wordlist,
        "-o", outfile, "--outfile-format", "2",
        "--quiet", "--potfile-disable",
    ]
    runner.run(cmd, timeout=None, capture=True)
    return _read_first_line(outfile)


# --------------------------------------------------------------------------
# aircrack-ng (WPA handshake, WEP)
# --------------------------------------------------------------------------
def crack_handshake_aircrack(
    runner: Runner, cap_file: str, bssid: str, wordlist: str
) -> Optional[str]:
    # -b selects the network; input_text="" sends EOF to any interactive prompt.
    cmd = ["aircrack-ng", "-w", wordlist, "-b", bssid, cap_file]
    res = runner.run(cmd, timeout=None, capture=True, input_text="")
    m = _KEY_FOUND_RE.search(res.stdout or "")
    return m.group(1) if m else None


def crack_wep(runner: Runner, cap_file: str, bssid: str) -> Optional[str]:
    """WEP: derive the key from captured IVs (no wordlist needed)."""
    cmd = ["aircrack-ng", "-b", bssid, cap_file]
    res = runner.run(cmd, timeout=None, capture=True, input_text="")
    m = _KEY_FOUND_RE.search(res.stdout or "")
    if m:
        return m.group(1).replace(":", "")
    return None


def _read_first_line(path: str) -> Optional[str]:
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            line = fh.readline().strip()
            return line or None
    except OSError:
        return None
