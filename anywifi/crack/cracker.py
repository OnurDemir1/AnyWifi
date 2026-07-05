"""Wordlist resolution and hash/handshake cracking (hashcat 22000 / aircrack-ng)."""

from __future__ import annotations

import gzip
import os
import re
import shutil
import tempfile
from typing import Callable, Optional

from anywifi.config import HASHCAT_MODE_22000, ROCKYOU_PATHS
from anywifi.core.runner import Runner

_KEY_FOUND_RE = re.compile(r"KEY FOUND!\s*\[\s*(.+?)\s*\]")

# Progress callback: (tried, total, speed_str) — any of total/speed may be 0/"".
ProgressCb = Callable[[int, int, str], None]

# hashcat status lines (with --status --status-timer)
_HC_PROGRESS_RE = re.compile(r"Progress\.+:\s*(\d+)/(\d+)")
_HC_SPEED_RE = re.compile(r"Speed\.[#*.\d\s]*:\s*([\d.]+\s*[kMGT]?H/s)")
# aircrack-ng in-place status: "1234/9822768 keys tested (1234.56 k/s)"
_AC_KEYS_RE = re.compile(r"(\d+)\s*/\s*(\d+)\s+keys tested.*?\(\s*([\d.]+)\s*k/s")


def _parse_hashcat(line: str, state: dict) -> bool:
    changed = False
    m = _HC_PROGRESS_RE.search(line)
    if m:
        state["tried"], state["total"] = int(m.group(1)), int(m.group(2))
        changed = True
    m = _HC_SPEED_RE.search(line)
    if m:
        state["speed"] = m.group(1).replace(" ", "")
        changed = True
    return changed


def _parse_aircrack(line: str, state: dict) -> bool:
    m = _AC_KEYS_RE.search(line)
    if not m:
        return False
    state["tried"], state["total"] = int(m.group(1)), int(m.group(2))
    state["speed"] = f"{float(m.group(3)):.0f} k/s"
    return True


def _stream(runner: Runner, cmd: list, on_progress: ProgressCb, parse) -> str:
    """Run `cmd`, parse progress from each line, and return the full output."""
    state = {"tried": 0, "total": 0, "speed": ""}

    def on_line(line: str) -> None:
        if parse(line, state):
            on_progress(state["tried"], state["total"], state["speed"])

    # When stdout is a pipe, glibc full-buffers the child's output, so the live
    # counter would freeze until the buffer fills. Force unbuffered output so
    # progress lines arrive immediately — aircrack updates with '\r' (no '\n'),
    # so we need -o0 (unbuffered), not -oL (line-buffered on '\n').
    run_cmd = list(cmd)
    if shutil.which("stdbuf"):
        run_cmd = ["stdbuf", "-o0", "-e0"] + run_cmd
    return runner.run_stream(run_cmd, on_line, timeout=None).stdout


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
def crack_22000(runner: Runner, hash_file: str, wordlist: str,
                on_progress: Optional[ProgressCb] = None) -> Optional[str]:
    if not runner.has("hashcat") and not runner.dry_run:
        return None
    outfile = hash_file + ".cracked"
    cmd = [
        "hashcat", "-m", HASHCAT_MODE_22000, "-a", "0",
        hash_file, wordlist,
        "-o", outfile, "--outfile-format", "2",
        "--potfile-disable",
    ]
    if on_progress is not None:
        # Emit a periodic status block we can parse for the live counter.
        cmd += ["--status", "--status-timer", "1"]
        _stream(runner, cmd, on_progress, _parse_hashcat)
    else:
        cmd += ["--quiet"]
        runner.run(cmd, timeout=None, capture=True)
    return _read_first_line(outfile)


# --------------------------------------------------------------------------
# aircrack-ng (WPA handshake, WEP)
# --------------------------------------------------------------------------
def crack_handshake_aircrack(
    runner: Runner, cap_file: str, bssid: str, wordlist: str,
    on_progress: Optional[ProgressCb] = None,
) -> Optional[str]:
    # -b selects the network (so aircrack never blocks on the AP-choice prompt).
    cmd = ["aircrack-ng", "-w", wordlist, "-b", bssid, cap_file]
    if on_progress is not None:
        out = _stream(runner, cmd, on_progress, _parse_aircrack)
    else:
        out = runner.run(cmd, timeout=None, capture=True, input_text="").stdout or ""
    m = _KEY_FOUND_RE.search(out)
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
