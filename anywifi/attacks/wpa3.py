"""Realistic assessment and limited vectors for pure WPA3-SAE networks.

Since clear WPA3 info is scarce, this models the modern realities:

* SAE (Dragonfly) is a PAKE → an **offline dictionary attack is not possible**
  from captured traffic. So cracking a handshake/PMKID is meaningless for pure WPA3.
* 802.11w (PMF) is mandatory in WPA3 → **classic deauth does not work**.
* The practical path is WPA3-Transition (mixed) mode; those networks are already
  labelled `WPA2/WPA3` and are targeted on the WPA2 side via PMKID/handshake.
* Dragonblood-class (CVE-2019-9494/9496 etc.) side-channel/downgrade issues: if
  PoC tools (dragondrain/dragontime) are present, they are noted for manual use.
"""

from __future__ import annotations

from anywifi.attacks.base import Attack
from anywifi.model import AttackContext, AttackResult, Network

_DRAGONBLOOD_TOOLS = ["dragondrain", "dragontime", "dragonslayer", "dragonforce"]


class Wpa3Attack(Attack):
    vector = "wpa3"
    label = "WPA3-SAE (limited / informational)"

    def applicable(self, net: Network) -> bool:
        # Only pure WPA3-SAE. Transition mode is handled by the WPA2 vectors.
        return net.is_wpa3

    def run(self, net: Network, ctx: AttackContext) -> AttackResult:
        runner = ctx.runner
        available = [t for t in _DRAGONBLOOD_TOOLS if runner.has(t)]

        reasons = [
            "SAE PAKE → offline dictionary attack is infeasible",
            "PMF (802.11w) is mandatory → deauth/handshake capture won't work",
        ]
        if available:
            hint = f"Dragonblood PoC available: {', '.join(available)} (run manually)"
        else:
            hint = "no Dragonblood PoC found; only WPA3-Transition networks are practical targets"

        return self._result(
            net, success=False, skipped=True,
            message="WPA3-SAE skipped — " + "; ".join(reasons) + ". " + hint,
        )
