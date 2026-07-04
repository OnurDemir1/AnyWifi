"""Terminal output (rich) and JSON reporting."""

from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from typing import Optional

from anywifi import __version__
from anywifi.model import AttackResult, Network
from anywifi.target.selector import attack_score

try:
    from rich.console import Console
    from rich.table import Table
    from rich.text import Text
    _HAS_RICH = True
except Exception:  # fall back to plain text if rich is missing
    _HAS_RICH = False


BANNER = r"""
    _                __        ___  __ _
   / \   _ __  _   _\ \      / (_)/ _(_)
  / _ \ | '_ \| | | |\ \ /\ / /| | |_| |
 / ___ \| | | | |_| | \ V  V / | |  _| |
/_/   \_\_| |_|\__, |  \_/\_/  |_|_| |_|
               |___/   autonomous wifi pentest
"""


class Reporter:
    def __init__(self, no_color: bool = False):
        self.console = Console(no_color=no_color, highlight=False) if _HAS_RICH else None

    # --- low-level output ---
    def log(self, msg: str, style: str = "") -> None:
        if self.console:
            self.console.print(msg, style=style or None)
        else:
            print(msg)

    def rule(self, title: str = "") -> None:
        if self.console:
            self.console.rule(title)
        else:
            print(f"\n=== {title} ===")

    def banner(self) -> None:
        if self.console:
            self.console.print(BANNER, style="bold cyan")
            self.console.print(f"  v{__version__} — use only on networks you own or are authorized to test.\n",
                               style="yellow")
        else:
            print(BANNER)
            print(f"  v{__version__} — use only on networks you own or are authorized to test.\n")

    # --- scan table ---
    def scan_table(self, networks: list[Network]) -> None:
        ordered = sorted(networks, key=attack_score, reverse=True)
        if not self.console:
            for i, n in enumerate(ordered, 1):
                print(f"{i:2}. {n.label()} wps={n.wps} clients={len(n.clients)} "
                      f"score={attack_score(n):.0f}")
            return
        table = Table(title="Discovered Networks (easiest first)", show_lines=False)
        table.add_column("#", justify="right", style="dim")
        table.add_column("ESSID")
        table.add_column("BSSID", style="dim")
        table.add_column("Ch", justify="right")
        table.add_column("Security")
        table.add_column("WPS", justify="center")
        table.add_column("Signal", justify="right")
        table.add_column("Clients", justify="right")
        table.add_column("Score", justify="right")
        for i, n in enumerate(ordered, 1):
            table.add_row(
                str(i), n.safe_essid, n.bssid, str(n.channel),
                _enc_text(n.encryption),
                "✓" if n.wps else "",
                f"{n.signal}",
                str(len(n.clients)),
                f"{attack_score(n):.0f}",
            )
        self.console.print(table)

    # --- attack step / result ---
    def attack_step(self, net: Network, vector_label: str) -> None:
        self.log(f"  → trying {vector_label}: {net.safe_essid} [{net.bssid}]", "cyan")

    def result(self, res: AttackResult) -> None:
        if res.cracked:
            self.log(f"  [+] CRACKED: {res.network.safe_essid} password: {res.password}", "bold green")
        elif res.success:
            self.log(f"  [+] {res.message}", "green")
        elif res.skipped:
            self.log(f"  [-] {res.message}", "yellow")
        else:
            self.log(f"  [x] {res.message}", "red")

    # --- summary + JSON ---
    def summary(self, results: list[AttackResult]) -> None:
        cracked = [r for r in results if r.cracked]
        self.rule("Summary")
        if not cracked:
            self.log("No networks cracked.", "yellow")
        for r in cracked:
            self.log(f"  {r.network.safe_essid} [{r.network.bssid}] "
                     f"({r.vector}) → {r.password}", "bold green")

    def save_json(self, results: list[AttackResult], out_dir: Path) -> Optional[Path]:
        out_dir.mkdir(parents=True, exist_ok=True)
        path = out_dir / f"report_{datetime.now():%Y%m%d_%H%M%S}.json"
        data = {
            "tool": "AnyWifi",
            "version": __version__,
            "timestamp": datetime.now().isoformat(timespec="seconds"),
            "results": [
                {
                    "essid": r.network.safe_essid,
                    "bssid": r.network.bssid,
                    "encryption": r.network.encryption,
                    "vector": r.vector,
                    "success": r.success,
                    "cracked": r.cracked,
                    "password": r.password,
                    "hash_file": r.hash_file,
                    "capture_file": r.capture_file,
                    "message": r.message,
                }
                for r in results
            ],
        }
        path.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
        return path


def _enc_text(enc: str):
    colors = {
        "OPEN": "bright_green", "WEP": "green", "WPA": "yellow",
        "WPA2": "yellow", "WPA2/WPA3": "magenta", "WPA3": "red",
    }
    if not _HAS_RICH:
        return enc
    return Text(enc, style=colors.get(enc, "white"))
