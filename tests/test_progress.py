"""Live-progress parsing and formatting for the cracking phase."""

from anywifi.core.runner import Result
from anywifi.crack import cracker
from anywifi.report.reporter import Reporter


# --- status-line parsing -------------------------------------------------
def test_parse_hashcat_progress_and_speed():
    state = {"tried": 0, "total": 0, "speed": ""}
    assert cracker._parse_hashcat("Progress.........: 1234000/14344384 (8.60%)", state)
    assert cracker._parse_hashcat("Speed.#1.........:  3021.5 kH/s", state)
    assert state["tried"] == 1234000
    assert state["total"] == 14344384
    assert state["speed"] == "3021.5kH/s"


def test_parse_hashcat_ignores_unrelated_lines():
    state = {"tried": 0, "total": 0, "speed": ""}
    assert cracker._parse_hashcat("Session..........: hashcat", state) is False


def test_parse_aircrack_keys_tested():
    state = {"tried": 0, "total": 0, "speed": ""}
    assert cracker._parse_aircrack("[00:00:07] 1500000/9822768 keys tested (1024.50 k/s)", state)
    assert state["tried"] == 1500000
    assert state["total"] == 9822768
    assert state["speed"] == "1024 k/s"


# --- streaming crack drives the progress callback ------------------------
class StreamRunner:
    """Fake runner whose run_stream replays tool-style progress lines."""

    dry_run = False
    verbose = False

    def __init__(self, secret, lines):
        self.secret = secret
        self.lines = lines

    def has(self, tool):
        return True

    def run_stream(self, cmd, on_line=None, timeout=None):
        # cmd may be prefixed with `stdbuf -o0 -e0` on systems that have it.
        for ln in self.lines:
            if on_line:
                on_line(ln)
        if "hashcat" in cmd:
            outfile = cmd[cmd.index("-o") + 1]
            with open(outfile, "w", encoding="utf-8") as fh:
                fh.write(self.secret + "\n")
        return Result(0, "\n".join(self.lines), "")


def test_crack_22000_streams_progress(tmp_path):
    hashfile = str(tmp_path / "t.22000")
    open(hashfile, "w").write("WPA*01*...\n")
    lines = [
        "Progress.........: 1000000/14344384 (6.9%)",
        "Speed.#1.........:  2000.0 kH/s",
        "Progress.........: 2000000/14344384 (13.9%)",
    ]
    seen = []
    pw = cracker.crack_22000(
        StreamRunner("hunter2", lines), hashfile, "wl.txt",
        on_progress=lambda t, tot, s: seen.append((t, tot, s)))
    assert pw == "hunter2"
    assert seen[-1][0] == 2000000
    assert seen[-1][1] == 14344384


def test_crack_aircrack_streams_progress(tmp_path):
    cap = str(tmp_path / "hs.cap")
    open(cap, "w").write("dummy")
    lines = [
        "[00:00:01] 500000/9822768 keys tested (900.00 k/s)",
        "KEY FOUND! [ correcthorse ]",
    ]
    seen = []
    pw = cracker.crack_handshake_aircrack(
        StreamRunner("correcthorse", lines), cap, "AA:BB:CC:DD:EE:01", "wl.txt",
        on_progress=lambda t, tot, s: seen.append((t, tot, s)))
    assert pw == "correcthorse"
    assert seen and seen[0][0] == 500000


# --- progress formatting -------------------------------------------------
def test_fmt_progress_has_counter_and_bar():
    out = Reporter.fmt_progress(3000000, 14344384, "3.0 MH/s")
    assert "3,000,000 tried" in out
    assert "20.9%" in out
    assert "3.0 MH/s" in out


def test_fmt_progress_without_total():
    out = Reporter.fmt_progress(500, 0, "")
    assert "500 tried" in out
