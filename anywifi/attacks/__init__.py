"""Attack engine — vectors ordered easy → hard."""

from __future__ import annotations

from anywifi.attacks.base import Attack
from anywifi.attacks.handshake import HandshakeAttack
from anywifi.attacks.pmkid import PmkidAttack
from anywifi.attacks.wep import WepAttack
from anywifi.attacks.wpa3 import Wpa3Attack
from anywifi.attacks.wps import WpsPinAttack, WpsPixieAttack
from anywifi.model import Network

# Attack chain, ordered easy → hard.
ATTACK_ORDER: list[type[Attack]] = [
    WepAttack,        # 1 — WEP (trivial)
    WpsPixieAttack,   # 2 — WPS pixie-dust (offline, fast)
    PmkidAttack,      # 3 — WPA/WPA2 PMKID (clientless)
    HandshakeAttack,  # 4 — WPA/WPA2 4-way handshake (deauth)
    WpsPinAttack,     # 5 — WPS PIN bruteforce (slow)
    Wpa3Attack,       # 6 — pure WPA3-SAE (informational / limited)
]


def chain_for(net: Network) -> list[Attack]:
    """Return the applicable attacks for a network, in order."""
    chain: list[Attack] = []
    for cls in ATTACK_ORDER:
        attack = cls()
        if attack.applicable(net):
            chain.append(attack)
    return chain


__all__ = ["Attack", "chain_for", "ATTACK_ORDER"]
