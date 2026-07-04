from anywifi.core import interface
from anywifi.core.runner import Result

IW_DEV = """\
phy#1
\tInterface wlan1
\t\tifindex 5
\t\twdev 0x100000001
\t\taddr 11:22:33:44:55:66
\t\ttype managed
phy#0
\tInterface wlan0mon
\t\tifindex 4
\t\twdev 0x2
\t\taddr aa:bb:cc:dd:ee:ff
\t\ttype monitor
\t\tchannel 10 (2457 MHz), width: 20 MHz
\t\ttxpower 20.00 dBm
"""


class FakeRunner:
    def __init__(self, stdout):
        self._stdout = stdout

    def run(self, cmd, timeout=None, capture=True, input_text=None):
        return Result(0, self._stdout, "")


def test_iw_interfaces_pairs():
    pairs = interface.iw_interfaces(FakeRunner(IW_DEV))
    assert ("wlan1", "managed") in pairs
    assert ("wlan0mon", "monitor") in pairs


def test_monitor_iface_finds_monitor_not_channel():
    # Regression: must return the monitor interface, never a channel number etc.
    assert interface.monitor_iface(FakeRunner(IW_DEV)) == "wlan0mon"


def test_monitor_iface_prefers_related():
    assert interface.monitor_iface(FakeRunner(IW_DEV), prefer="wlan0") == "wlan0mon"


def test_monitor_iface_none_when_no_monitor():
    managed_only = "phy#0\n\tInterface wlan0\n\t\ttype managed\n"
    assert interface.monitor_iface(FakeRunner(managed_only)) is None


def test_list_wireless():
    assert set(interface.list_wireless(FakeRunner(IW_DEV))) == {"wlan1", "wlan0mon"}
