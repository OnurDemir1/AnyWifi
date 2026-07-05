"""Terminal output (rich) and JSON reporting."""

from __future__ import annotations

import json
import threading
import time
from datetime import datetime
from pathlib import Path
from typing import Optional

from anywifi import __version__
from anywifi.model import AttackResult, Network
from anywifi.target.selector import attack_score

try:
    from rich.console import Console
    from rich.live import Live
    from rich.table import Table
    from rich.text import Text
    _HAS_RICH = True
except Exception:  # fall back to plain text if rich is missing
    _HAS_RICH = False

_SPINNER = "⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏"


def _fmt_elapsed(seconds: float) -> str:
    s = int(seconds)
    return f"{s // 60}m{s % 60:02d}s" if s >= 60 else f"{s}s"


class Activity:
    """A live one-line status: spinner + phase label + elapsed timer + detail.

    While running it shows an animated line (so the user can see the tool is
    working and not frozen); on exit the line is cleared and the caller prints
    a permanent outcome line. Falls back to a single static line when there is
    no live-capable terminal (piped output, --verbose, --dry-run)."""

    def __init__(self, console, label: str, live: bool = True):
        self.console = console
        self.label = label
        self._live_ok = live
        self._detail = ""
        self._start = time.monotonic()
        self._stop = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self._live: Optional["Live"] = None
        self._frame = 0

    # called from the worker (main) thread while the step runs
    def detail(self, text: str) -> None:
        self._detail = text or ""

    def _render(self):
        self._frame = (self._frame + 1) % len(_SPINNER)
        t = Text()
        t.append(f"  {_SPINNER[self._frame]} ", style="cyan")
        t.append(self.label, style="cyan")
        t.append(f"   {_fmt_elapsed(time.monotonic() - self._start)}", style="dim")
        if self._detail:
            t.append("   ·  ", style="dim")
            t.append(self._detail, style="dim")
        return t

    def _loop(self) -> None:
        while not self._stop.wait(0.12):
            try:
                if self._live is not None:
                    self._live.update(self._render())
            except Exception:
                break

    def __enter__(self) -> "Activity":
        if not self._live_ok:
            # Non-live fallback: announce the phase once.
            if self.console:
                self.console.print(f"  → {self.label} …", style="cyan")
            else:
                print(f"  → {self.label} …")
            return self
        self._live = Live(self._render(), console=self.console,
                          transient=True, refresh_per_second=12)
        self._live.start()
        self._thread = threading.Thread(target=self._loop, daemon=True)
        self._thread.start()
        return self

    def __exit__(self, *exc) -> bool:
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=1)
        if self._live is not None:
            try:
                self._live.stop()
            except Exception:
                pass
        return False


BANNER = r"""
    _                __        ___  __ _
   / \   _ __  _   _\ \      / (_)/ _(_)
  / _ \ | '_ \| | | |\ \ /\ / /| | |_| |
 / ___ \| | | | |_| | \ V  V / | |  _| |
/_/   \_\_| |_|\__, |  \_/\_/  |_|_| |_|
               |___/   autonomous wifi pentest
"""


class Reporter:
    def __init__(self, no_color: bool = False, live: bool = True):
        # markup=False: never interpret "[...]" in SSIDs/messages as rich markup
        # (prevents crashes/format injection from odd network names).
        self.console = (
            Console(no_color=no_color, highlight=False, markup=False)
            if _HAS_RICH else None
        )
        # Live animations need a real terminal; disable for piped/verbose/dry-run.
        self._live_ok = bool(live and self.console and self.console.is_terminal)

    # --- live activity (spinner + elapsed timer + detail) ---
    def activity(self, label: str) -> Activity:
        return Activity(self.console, label, live=self._live_ok)

    @staticmethod
    def fmt_progress(tried: int, total: int, speed: str) -> str:
        """Render a compact cracking-progress detail line."""
        if total > 0:
            pct = min(100.0, tried / total * 100)
            filled = int(pct / 100 * 12)
            bar = "█" * filled + "░" * (12 - filled)
            head = f"{bar} {pct:4.1f}%  ·  {tried:,} tried"
        else:
            head = f"{tried:,} tried"
        return f"{head}  ·  {speed}" if speed else head

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

    # --- attack target header / result ---
    def target_header(self, net: Network) -> None:
        self.log(f"\n▶ {net.safe_essid} [{net.bssid}]  ·  {net.encryption} "
                 f"·  ch{net.channel}  ·  {net.signal}dBm", "bold")

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
