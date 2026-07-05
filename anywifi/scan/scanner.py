"""Network scanning: airodump-ng CSV parsing + WPS detection (wash)."""

from __future__ import annotations

import glob
import os
import re
import tempfile

from anywifi.config import DEFAULT_SCAN_TIME
from anywifi.core.runner import Runner
from anywifi.model import Network


# --------------------------------------------------------------------------
# Encryption normalization
# --------------------------------------------------------------------------
def normalize_encryption(privacy: str, auth: str = "") -> str:
    """Map the airodump Privacy/Authentication field to a standard label."""
    p = (privacy or "").upper().replace("-", " ").strip()
    a = (auth or "").upper()
    tokens = set(p.split())
    if not p or "OPN" in tokens or p == "OPEN":
        return "OPEN"
    if "WEP" in tokens:
        return "WEP"
    has3 = "WPA3" in tokens or a == "SAE"
    has2 = "WPA2" in tokens
    has1 = "WPA" in tokens and not has2 and not has3
    if has3 and has2:
        return "WPA2/WPA3"        # transition (mixed) mode
    if has3:
        return "WPA3"
    if has2:
        return "WPA2"
    if has1:
        return "WPA"
    if "WPA" in p:
        return "WPA2"
    return "UNKNOWN"


def _infer_pmf(encryption: str) -> str:
    if encryption == "WPA3":
        return "required"
    if encryption == "WPA2/WPA3":
        return "capable"
    return "unknown"


# --------------------------------------------------------------------------
# airodump-ng CSV parser (pure, unit-testable function)
# --------------------------------------------------------------------------
def parse_airodump_csv(text: str) -> list[Network]:
    """Parse airodump-ng `--output-format csv` output into a list of Networks."""
    lines = text.splitlines()
    # Two sections: APs and clients. Delimiter: the "Station MAC" header.
    split_idx = None
    for i, line in enumerate(lines):
        if line.strip().startswith("Station MAC"):
            split_idx = i
            break

    ap_lines = lines[:split_idx] if split_idx is not None else lines
    st_lines = lines[split_idx:] if split_idx is not None else []

    networks: dict[str, Network] = {}

    for line in ap_lines:
        if not line.strip() or line.lstrip().startswith("BSSID"):
            continue
        fields = [f.strip() for f in line.split(",")]
        if len(fields) < 14:
            continue
        bssid = fields[0].upper()
        if not re.match(r"^([0-9A-F]{2}:){5}[0-9A-F]{2}$", bssid):
            continue
        # ESSID may contain commas → join fields 13..(-1)
        essid = fields[13] if len(fields) == 15 else ",".join(fields[13:-1]).strip()
        enc = normalize_encryption(fields[5], fields[7])
        networks[bssid] = Network(
            bssid=bssid,
            essid=essid,
            channel=_to_int(fields[3]),
            encryption=enc,
            cipher=fields[6],
            auth=fields[7],
            signal=_to_int(fields[8], default=-100),
            beacons=_to_int(fields[9]),
            pmf=_infer_pmf(enc),
        )

    # Attach clients to their APs
    for line in st_lines:
        if not line.strip() or line.lstrip().startswith("Station MAC"):
            continue
        fields = [f.strip() for f in line.split(",")]
        if len(fields) < 6:
            continue
        station = fields[0].upper()
        ap = fields[5].upper()
        if ap in networks and re.match(r"^([0-9A-F]{2}:){5}[0-9A-F]{2}$", station):
            if station not in networks[ap].clients:
                networks[ap].clients.append(station)

    return list(networks.values())


def _to_int(value: str, default: int = 0) -> int:
    try:
        return int(value.strip())
    except (ValueError, AttributeError):
        return default


# --------------------------------------------------------------------------
# WPS detection (wash)
# --------------------------------------------------------------------------
def parse_wash_entries(text: str) -> dict[str, bool]:
    """Parse wash output into {bssid: locked}.

    wash columns after the BSSID are: Ch  dBm  WPS(version)  Lck  ESSID.
    An AP is treated as locked only if *every* sighting reports it locked.
    """
    entries: dict[str, bool] = {}
    for line in text.splitlines():
        m = re.match(r"^\s*([0-9A-Fa-f]{2}(?::[0-9A-Fa-f]{2}){5})\s+(.*)$", line)
        if not m:
            continue
        bssid = m.group(1).upper()
        fields = m.group(2).split()
        locked = len(fields) >= 4 and fields[3].strip().lower() in ("yes", "locked")
        entries[bssid] = entries.get(bssid, True) and locked
    return entries


def parse_wash(text: str) -> set[str]:
    """BSSIDs whose WPS is actually usable (advertised *and not locked*).

    Locked APs refuse the WPS exchange, so attacking them (Pixie-Dust / PIN)
    only wastes time — they are excluded here and won't get a WPS vector."""
    return {b for b, locked in parse_wash_entries(text).items() if not locked}


# --------------------------------------------------------------------------
# Scanner
# --------------------------------------------------------------------------
class Scanner:
    def __init__(self, runner: Runner):
        self.runner = runner

    def scan(self, interface: str, seconds: int = DEFAULT_SCAN_TIME,
             band: str = "") -> list[Network]:
        return self.scan_linux(interface, seconds, band=band)

    def scan_linux(self, interface: str, seconds: int, band: str = "") -> list[Network]:
        tmpdir = tempfile.mkdtemp(prefix="anywifi_scan_")
        prefix = os.path.join(tmpdir, "scan")
        cmd = [
            "airodump-ng", interface,
            "--output-format", "csv",
            "--write-interval", "1",
            "-w", prefix,
        ]
        # 5 GHz sweep is opt-in: `--band abg` makes some 2.4-only adapters
        # abort the scan (finding nothing), so only add it when asked.
        if band:
            cmd += ["--band", band]
        self.runner.run_timed(cmd, duration=seconds, capture=True)

        networks: list[Network] = []
        csvs = sorted(glob.glob(prefix + "*.csv"))
        if csvs:
            try:
                with open(csvs[-1], "r", encoding="utf-8", errors="replace") as fh:
                    networks = parse_airodump_csv(fh.read())
            except OSError:
                networks = []

        # WPS detection (optional)
        wps_set = self.scan_wps(interface, seconds=min(seconds, 15))
        for net in networks:
            if net.bssid in wps_set:
                net.wps = True
        return networks

    def scan_wps(self, interface: str, seconds: int = 15) -> set[str]:
        if not self.runner.has("wash") and not self.runner.dry_run:
            return set()
        res = self.runner.run_timed(["wash", "-i", interface], duration=seconds, capture=True)
        return parse_wash(res.stdout)
