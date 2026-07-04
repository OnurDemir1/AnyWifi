import gzip
import os

from anywifi.attacks.pmkid import _filter_for_bssid
from anywifi.core.runner import Result
from anywifi.crack import cracker


class FakeRunner:
    """Stand-in for real hashcat/aircrack that simulates a successful crack."""

    def __init__(self, secret: str):
        self.dry_run = False
        self.secret = secret

    def has(self, tool):
        return True

    def run(self, cmd, timeout=None, capture=True, input_text=None):
        cmd = list(cmd)
        tool = os.path.basename(cmd[0])
        if tool == "hashcat":
            # ... HASH WORDLIST -o OUTFILE ...  → wordlist is right before -o
            oi = cmd.index("-o")
            outfile = cmd[oi + 1]
            wordlist = cmd[oi - 1]
            words = _read(wordlist)
            if self.secret in words:
                with open(outfile, "w", encoding="utf-8") as fh:
                    fh.write(self.secret + "\n")   # --outfile-format 2 (plain password)
            return Result(0, "", "")
        if tool == "aircrack-ng":
            wordlist = cmd[cmd.index("-w") + 1]
            if self.secret in _read(wordlist):
                return Result(0, f"KEY FOUND! [ {self.secret} ]", "")
            return Result(0, "Passphrase not in dictionary", "")
        return Result(0, "", "")


def _read(path):
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        return [l.strip() for l in fh]


def _wordlist(tmp_path, words):
    p = tmp_path / "wl.txt"
    p.write_text("\n".join(words) + "\n", encoding="utf-8")
    return str(p)


def test_crack_22000_success(tmp_path):
    wl = _wordlist(tmp_path, ["wrong1", "letmein123", "wrong2"])
    hashfile = str(tmp_path / "target.22000")
    open(hashfile, "w").write("WPA*01*deadbeef*aabbccddee01*...\n")
    pw = cracker.crack_22000(FakeRunner("letmein123"), hashfile, wl)
    assert pw == "letmein123"


def test_crack_22000_failure(tmp_path):
    wl = _wordlist(tmp_path, ["nope", "nada"])
    hashfile = str(tmp_path / "target.22000")
    open(hashfile, "w").write("WPA*01*deadbeef*aabbccddee01*...\n")
    pw = cracker.crack_22000(FakeRunner("letmein123"), hashfile, wl)
    assert pw is None


def test_crack_handshake_aircrack(tmp_path):
    wl = _wordlist(tmp_path, ["a", "correcthorse", "b"])
    cap = str(tmp_path / "hs.cap")
    open(cap, "w").write("dummy")
    pw = cracker.crack_handshake_aircrack(
        FakeRunner("correcthorse"), cap, "AA:BB:CC:DD:EE:01", wl)
    assert pw == "correcthorse"


def test_find_wordlist_override_and_gz(tmp_path):
    gz = tmp_path / "list.txt.gz"
    with gzip.open(gz, "wt", encoding="utf-8") as fh:
        fh.write("password1\npassword2\n")
    resolved = cracker.find_wordlist(override=str(gz), prompt=False)
    assert resolved and resolved.endswith(".txt")
    assert "password1" in _read(resolved)


def test_find_wordlist_missing_no_prompt(tmp_path, monkeypatch):
    monkeypatch.delenv("ANYWIFI_WORDLIST", raising=False)
    monkeypatch.setattr(cracker, "ROCKYOU_PATHS", [str(tmp_path / "yok.txt")])
    assert cracker.find_wordlist(override=None, prompt=False) is None


def test_filter_for_bssid_pmkid(tmp_path):
    hashfile = str(tmp_path / "all.22000")
    with open(hashfile, "w", encoding="utf-8") as fh:
        fh.write("WPA*01*hashA*aabbccddee01*sta*essid***\n")   # hedef PMKID
        fh.write("WPA*02*hashB*aabbccddee01*sta*essid***\n")   # EAPOL (not PMKID)
        fh.write("WPA*01*hashC*ffffffffffff*sta*essid***\n")   # different AP
    out = _filter_for_bssid(hashfile, "AA:BB:CC:DD:EE:01", pmkid_only=True)
    lines = _read(out)
    assert len(lines) == 1
    assert "aabbccddee01" in lines[0].lower()
    assert lines[0].lower().startswith("wpa*01*")
