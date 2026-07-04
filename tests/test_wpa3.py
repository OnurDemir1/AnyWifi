from pathlib import Path

from anywifi.attacks.wpa3 import Wpa3Attack, _parse_dragonforce
from anywifi.core.runner import Result
from anywifi.model import AttackContext, Network


class FakeRunner:
    def __init__(self, tools=()):
        self.dry_run = False
        self._tools = set(tools)

    def has(self, tool):
        return tool in self._tools

    def run(self, *a, **k):
        return Result(0, "", "")

    def run_timed(self, *a, **k):
        return Result(0, "", "")


def _ctx(runner, only=None):
    return AttackContext(interface="wlan0mon", output_dir=Path("loot"),
                         runner=runner, dry_run=False, only=only)


def _wpa3():
    return Network(bssid="99:88:77:66:55:06", essid="Sec", encryption="WPA3",
                   channel=36, pmf="required")


def test_wpa3_default_skips_with_reason():
    res = Wpa3Attack().run(_wpa3(), _ctx(FakeRunner()))
    assert res.skipped and not res.success
    assert "transition" in res.message.lower()


def test_wpa3_explicit_without_tools_guides():
    res = Wpa3Attack().run(_wpa3(), _ctx(FakeRunner(), only={"wpa3"}))
    assert res.skipped
    assert "dragontime" in res.message.lower()


def test_wpa3_applicable_only_pure_sae():
    assert Wpa3Attack().applicable(_wpa3()) is True
    transition = Network(bssid="F0:0D:CA:FE:00:05", encryption="WPA2/WPA3", channel=6)
    assert Wpa3Attack().applicable(transition) is False


def test_parse_dragonforce():
    assert _parse_dragonforce("Password found: hunter2") == "hunter2"
    assert _parse_dragonforce("nothing here") is None
