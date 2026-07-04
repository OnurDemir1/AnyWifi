"""Wireless interface management: listing, monitor mode on/off, cleanup."""

from __future__ import annotations

import re
from typing import Optional

from anywifi.core.runner import Runner

_IFACE_RE = re.compile(r"^\s*Interface\s+(\S+)", re.MULTILINE)
_MON_ENABLED_RE = re.compile(r"on\s+\[[^\]]+\](\w+)\)")


def list_wireless(runner: Runner) -> list[str]:
    """Return wireless interfaces (`iw dev`)."""
    res = runner.run(["iw", "dev"])
    if res.ok and res.stdout:
        return _IFACE_RE.findall(res.stdout)
    return []


def _monitor_iface_from_iw(runner: Runner) -> Optional[str]:
    """Find the first interface with type=monitor in `iw dev`."""
    res = runner.run(["iw", "dev"])
    if not res.ok:
        return None
    # scan each "Interface X ... type Y" block
    blocks = re.split(r"(?=^\s*Interface\s+)", res.stdout, flags=re.MULTILINE)
    for blk in blocks:
        name = re.search(r"Interface\s+(\S+)", blk)
        typ = re.search(r"type\s+(\S+)", blk)
        if name and typ and typ.group(1) == "monitor":
            return name.group(1)
    return None


class InterfaceManager:
    """Enables monitor mode and restores the original state on exit."""

    def __init__(self, runner: Runner):
        self.runner = runner
        self.base_iface: Optional[str] = None
        self.monitor_iface: Optional[str] = None
        self._killed_services = False

    def enable_monitor(self, iface: str, kill_conflicts: bool = True) -> Optional[str]:
        """Put `iface` into monitor mode and return the monitor interface name."""
        self.base_iface = iface
        if kill_conflicts:
            # Stop NetworkManager/wpa_supplicant conflicts
            self.runner.run(["airmon-ng", "check", "kill"])
            self._killed_services = True

        res = self.runner.run(["airmon-ng", "start", iface])
        mon = None
        if res.ok and res.stdout:
            m = _MON_ENABLED_RE.search(res.stdout)
            if m:
                mon = m.group(1)
        # If airmon-ng didn't rename the interface, confirm via iw
        if not mon:
            mon = _monitor_iface_from_iw(self.runner)
        if not mon and self.runner.dry_run:
            mon = iface + "mon"
        if not mon:
            # Last resort: enable monitor mode manually with iw
            mon = self._manual_monitor(iface)
        self.monitor_iface = mon
        return mon

    def _manual_monitor(self, iface: str) -> Optional[str]:
        self.runner.run(["ip", "link", "set", iface, "down"])
        self.runner.run(["iw", "dev", iface, "set", "type", "monitor"])
        self.runner.run(["ip", "link", "set", iface, "up"])
        mon = _monitor_iface_from_iw(self.runner)
        return mon or (iface if self.runner.dry_run else None)

    def set_channel(self, channel: int) -> None:
        if self.monitor_iface and channel:
            self.runner.run(["iw", "dev", self.monitor_iface, "set", "channel", str(channel)])

    def cleanup(self) -> None:
        """Disable monitor mode and bring network services back."""
        if self.monitor_iface:
            self.runner.run(["airmon-ng", "stop", self.monitor_iface])
            self.monitor_iface = None
        if self._killed_services:
            # Gently restart NetworkManager (if present)
            if self.runner.has("systemctl"):
                self.runner.run(["systemctl", "restart", "NetworkManager"])
            elif self.runner.has("service"):
                self.runner.run(["service", "network-manager", "restart"])
            self._killed_services = False
