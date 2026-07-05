"""Data models: Network, AttackResult, AttackContext."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Optional


@dataclass
class Network:
    """An access point (AP) found during scanning."""

    bssid: str
    essid: str = ""
    channel: int = 0
    encryption: str = "UNKNOWN"     # OPEN / WEP / WPA / WPA2 / WPA2/WPA3 / WPA3
    cipher: str = ""                # CCMP / TKIP / WEP ...
    auth: str = ""                  # PSK / SAE / MGT (enterprise) ...
    wps: bool = False
    signal: int = -100              # dBm (higher = stronger)
    beacons: int = 0
    clients: list[str] = field(default_factory=list)
    pmf: str = "unknown"            # required / capable / disabled / unknown

    # --- protocol helpers ---
    @property
    def is_open(self) -> bool:
        return self.encryption == "OPEN"

    @property
    def is_wep(self) -> bool:
        return self.encryption == "WEP"

    @property
    def is_wpa3(self) -> bool:
        return self.encryption == "WPA3"

    @property
    def is_transition(self) -> bool:
        """WPA3-Transition (mixed): WPA2 + WPA3 broadcast together."""
        return self.encryption == "WPA2/WPA3"

    @property
    def is_enterprise(self) -> bool:
        return self.auth.upper() in {"MGT", "802.1X", "EAP"}

    @property
    def pmf_required(self) -> bool:
        return self.pmf == "required"

    @property
    def has_clients(self) -> bool:
        return len(self.clients) > 0

    @property
    def safe_essid(self) -> str:
        return self.essid or "<hidden>"

    def label(self) -> str:
        return f"{self.safe_essid} [{self.bssid}] ch{self.channel} {self.encryption} {self.signal}dBm"


@dataclass
class AttackResult:
    """The outcome of one attack vector."""

    network: Network
    vector: str                     # wep / wps-pixie / pmkid / handshake ...
    success: bool = False
    password: Optional[str] = None
    hash_file: Optional[str] = None      # captured hash/handshake file path
    capture_file: Optional[str] = None   # raw .cap/.pcapng
    message: str = ""
    skipped: bool = False

    @property
    def cracked(self) -> bool:
        return self.success and self.password is not None


@dataclass
class AttackContext:
    """Runtime context passed to attacks."""

    interface: str                  # monitor interface (e.g. wlan0mon)
    output_dir: Path
    runner: "object"                # core.runner.Runner
    wordlist: Optional[str] = None
    dry_run: bool = False
    only: Optional[set[str]] = None  # only these vectors (None = all)
    on_status: Optional[Callable[[str], None]] = None  # live progress detail sink

    def wants(self, vector: str) -> bool:
        return self.only is None or vector in self.only

    def status(self, text: str) -> None:
        """Report a short live-status update for the current step (best effort)."""
        if self.on_status is not None:
            try:
                self.on_status(text)
            except Exception:
                pass
