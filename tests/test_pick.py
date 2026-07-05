"""Target picker robustness + handshake hash validation."""

import builtins

import pytest

from anywifi.attacks.handshake import _has_wpa_hash
from anywifi.cli import Engine, build_parser
from anywifi.model import Network


def _engine():
    args = build_parser().parse_args(["--no-color", "--dry-run"])
    return Engine(args)


def _nets(n):
    return [Network(bssid=f"00:00:00:00:00:{i:02d}", essid=f"n{i}",
                    encryption="WPA2", channel=6) for i in range(1, n + 1)]


def _pick(monkeypatch, typed, displayed):
    it = iter(typed)
    monkeypatch.setattr(builtins, "input", lambda *a: next(it))
    return _engine()._interactive_pick(displayed, auto_list=displayed)


def test_pick_valid_number(monkeypatch):
    d = _nets(14)
    got = _pick(monkeypatch, ["8"], d)
    assert got == [d[7]]


def test_pick_multiple(monkeypatch):
    d = _nets(14)
    got = _pick(monkeypatch, ["1,3"], d)
    assert got == [d[0], d[2]]


def test_pick_enter_is_auto_all(monkeypatch):
    d = _nets(5)
    assert _pick(monkeypatch, [""], d) == d


def test_pick_quit(monkeypatch):
    d = _nets(5)
    assert _pick(monkeypatch, ["q"], d) == []


def test_pick_typo_reprompts_not_attack_all(monkeypatch):
    d = _nets(5)
    # First a garbage token, then a valid one — must pick the valid one only,
    # never fan out to every network.
    got = _pick(monkeypatch, ["99x", "2"], d)
    assert got == [d[1]]


def test_pick_out_of_range_reprompts(monkeypatch):
    d = _nets(5)
    got = _pick(monkeypatch, ["9", "5"], d)
    assert got == [d[4]]


def test_pick_all_invalid_quits(monkeypatch):
    d = _nets(5)
    # Three bad answers → give up and attack nothing (not everything).
    assert _pick(monkeypatch, ["x", "y", "z"], d) == []


def test_has_wpa_hash(tmp_path):
    good = tmp_path / "g.22000"
    good.write_text("WPA*02*deadbeef*aabbccddee01*...\n", encoding="utf-8")
    assert _has_wpa_hash(str(good)) is True

    empty = tmp_path / "e.22000"
    empty.write_text("", encoding="utf-8")
    assert _has_wpa_hash(str(empty)) is False

    assert _has_wpa_hash(str(tmp_path / "missing.22000")) is False
