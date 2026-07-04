"""OS / environment detection. AnyWifi only runs on Linux."""

from __future__ import annotations

import os
import platform as _platform
from dataclasses import dataclass


@dataclass
class SystemInfo:
    os_name: str                 # linux / windows / darwin
    is_root: bool
    is_wsl: bool = False

    @property
    def is_linux(self) -> bool:
        return self.os_name == "linux"


def is_wsl() -> bool:
    """Are we running under WSL (Windows Subsystem for Linux)?"""
    if os.environ.get("WSL_DISTRO_NAME") or os.environ.get("WSL_INTEROP"):
        return True
    for path in ("/proc/version", "/proc/sys/kernel/osrelease"):
        try:
            with open(path, "r", encoding="utf-8", errors="ignore") as fh:
                if "microsoft" in fh.read().lower():
                    return True
        except OSError:
            continue
    return False


def is_root() -> bool:
    if hasattr(os, "geteuid"):
        try:
            return os.geteuid() == 0
        except Exception:
            return False
    return False


def detect() -> SystemInfo:
    system = _platform.system().lower()
    if system.startswith("win"):
        os_name = "windows"
    elif system == "darwin":
        os_name = "darwin"
    else:
        os_name = "linux"

    wsl = is_wsl() if os_name == "linux" else False
    return SystemInfo(os_name=os_name, is_root=is_root(), is_wsl=wsl)
