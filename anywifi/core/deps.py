"""Dependency checking and automatic install via the OS package manager."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

from anywifi.core.runner import Runner

# External binaries the tool uses.
CORE_BINARIES = [
    "airmon-ng", "airodump-ng", "aireplay-ng", "aircrack-ng",  # aircrack-ng suite
    "hcxdumptool", "hcxpcapngtool",                            # PMKID
    "reaver", "wash",                                          # WPS
    "hashcat",                                                 # cracking (22000)
    "iw",                                                      # interface management
]
OPTIONAL_BINARIES = ["bully", "wpa_supplicant", "macchanger",
                     "dragontime", "dragonforce"]   # WPA3 Dragonblood (not in apt)

# binary -> package name (per package manager)
BINARY_PACKAGE = {
    "airmon-ng":   {"apt": "aircrack-ng", "pacman": "aircrack-ng", "dnf": "aircrack-ng", "zypper": "aircrack-ng"},
    "airodump-ng": {"apt": "aircrack-ng", "pacman": "aircrack-ng", "dnf": "aircrack-ng", "zypper": "aircrack-ng"},
    "aireplay-ng": {"apt": "aircrack-ng", "pacman": "aircrack-ng", "dnf": "aircrack-ng", "zypper": "aircrack-ng"},
    "aircrack-ng": {"apt": "aircrack-ng", "pacman": "aircrack-ng", "dnf": "aircrack-ng", "zypper": "aircrack-ng"},
    "hcxdumptool": {"apt": "hcxdumptool", "pacman": "hcxdumptool", "dnf": "hcxdumptool", "zypper": "hcxdumptool"},
    "hcxpcapngtool": {"apt": "hcxtools", "pacman": "hcxtools", "dnf": "hcxtools", "zypper": "hcxtools"},
    "reaver":      {"apt": "reaver", "pacman": "reaver", "dnf": "reaver", "zypper": "reaver"},
    "wash":        {"apt": "reaver", "pacman": "reaver", "dnf": "reaver", "zypper": "reaver"},
    "hashcat":     {"apt": "hashcat", "pacman": "hashcat", "dnf": "hashcat", "zypper": "hashcat"},
    "iw":          {"apt": "iw", "pacman": "iw", "dnf": "iw", "zypper": "iw"},
    "bully":       {"apt": "bully", "pacman": "bully", "dnf": "bully"},
    "wpa_supplicant": {"apt": "wpasupplicant", "pacman": "wpa_supplicant", "dnf": "wpa_supplicant", "zypper": "wpa_supplicant"},
    "macchanger":  {"apt": "macchanger", "pacman": "macchanger", "dnf": "macchanger"},
}

# Linux package-manager install command templates
INSTALL_CMD = {
    "apt":    lambda pkgs: ["apt-get", "install", "-y", *pkgs],
    "pacman": lambda pkgs: ["pacman", "-S", "--noconfirm", *pkgs],
    "dnf":    lambda pkgs: ["dnf", "install", "-y", *pkgs],
    "zypper": lambda pkgs: ["zypper", "--non-interactive", "install", *pkgs],
}


@dataclass
class DepReport:
    manager: Optional[str]
    missing_core: list[str] = field(default_factory=list)
    missing_optional: list[str] = field(default_factory=list)
    present: list[str] = field(default_factory=list)


def detect_pkg_manager(runner: Runner) -> Optional[str]:
    for mgr in ("apt-get", "pacman", "dnf", "zypper"):
        if runner.has(mgr):
            return "apt" if mgr == "apt-get" else mgr
    return None


def check(runner: Runner) -> DepReport:
    mgr = detect_pkg_manager(runner)
    report = DepReport(manager=mgr)
    for b in CORE_BINARIES:
        (report.present if runner.has(b) else report.missing_core).append(b)
    for b in OPTIONAL_BINARIES:
        if not runner.has(b):
            report.missing_optional.append(b)
        else:
            report.present.append(b)
    return report


def _packages_for(binaries: list[str], manager: str) -> list[str]:
    pkgs: list[str] = []
    for b in binaries:
        pkg = BINARY_PACKAGE.get(b, {}).get(manager)
        if pkg and pkg not in pkgs:
            pkgs.append(pkg)
    return pkgs


def install(runner: Runner, binaries: list[str], manager: str) -> bool:
    """Install the missing binaries. Returns success (True on dry-run)."""
    if manager not in INSTALL_CMD:
        return False
    pkgs = _packages_for(binaries, manager)
    if not pkgs:
        return True
    # For apt, refresh the index first (quietly; don't fail hard).
    if manager == "apt":
        runner.run(["apt-get", "update"], timeout=180)
    res = runner.run(INSTALL_CMD[manager](pkgs), timeout=900, capture=False)
    return res.ok
