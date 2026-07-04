"""Wireless interface management: listing, monitor mode on/off, cleanup."""

from __future__ import annotations

import re
from typing import Optional

from anywifi.core.runner import Runner

_IFACE_RE = re.compile(r"^\s*Interface\s+(\S+)", re.MULTILINE)


def list_wireless(runner: Runner) -> list[str]:
    """Return wireless interface names (`iw dev`)."""
    res = runner.run(["iw", "dev"])
    if res.ok and res.stdout:
        return _IFACE_RE.findall(res.stdout)
    return []


def iw_interfaces(runner: Runner) -> list[tuple]:
    """Return (name, type) pairs from `iw dev`, e.g. ('wlan0mon', 'monitor')."""
    res = runner.run(["iw", "dev"])
    pairs: list[tuple] = []
    name: Optional[str] = None
    for line in (res.stdout or "").splitlines():
        m = re.match(r"\s*Interface\s+(\S+)", line)
        if m:
            name = m.group(1)
            continue
        t = re.match(r"\s*type\s+(\S+)", line)
        if t and name:
            pairs.append((name, t.group(1)))
    return pairs


def monitor_iface(runner: Runner, prefer: Optional[str] = None) -> Optional[str]:
    """Find an interface currently in monitor mode; prefer one related to `prefer`."""
    monitors = [name for name, typ in iw_interfaces(runner) if typ == "monitor"]
    if not monitors:
        return None
    if prefer:
        for m in monitors:
            if m == prefer or m.startswith(prefer) or prefer.startswith(m):
                return m
    return monitors[0]


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

        self.runner.run(["airmon-ng", "start", iface])

        # Authoritative check: ask iw which interface is actually in monitor mode.
        mon = monitor_iface(self.runner, prefer=iface)
        if not mon:
            # airmon-ng didn't do it — try manually with iw
            mon = self._manual_monitor(iface)
        if not mon and self.runner.dry_run:
            mon = iface + "mon"
        self.monitor_iface = mon
        return mon

    def _manual_monitor(self, iface: str) -> Optional[str]:
        self.runner.run(["ip", "link", "set", iface, "down"])
        self.runner.run(["iw", "dev", iface, "set", "type", "monitor"])
        self.runner.run(["ip", "link", "set", iface, "up"])
        mon = monitor_iface(self.runner, prefer=iface)
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
