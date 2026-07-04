"""Target scoring and ranking — the 'easiest to hack' filter."""

from __future__ import annotations

from anywifi.config import (
    CLIENT_BONUS_EACH,
    CLIENT_BONUS_MAX,
    ENCRYPTION_WEIGHTS,
    MIN_SIGNAL_DBM,
    SIGNAL_SCORE_MAX,
    WPS_BONUS,
)
from anywifi.model import Network

# Signal mapping range (dBm)
_SIGNAL_BEST = -30
_SIGNAL_WORST = -90


def signal_score(signal: int) -> float:
    """Map a dBm signal onto the 0..SIGNAL_SCORE_MAX range."""
    # airodump reports -1 (or 0/positive) when it couldn't measure the signal;
    # treat that as "unknown" — a modest score, never the maximum.
    if signal >= -1:
        return SIGNAL_SCORE_MAX * 0.25
    span = _SIGNAL_BEST - _SIGNAL_WORST
    frac = (signal - _SIGNAL_WORST) / span
    frac = max(0.0, min(1.0, frac))
    return frac * SIGNAL_SCORE_MAX


def attack_score(net: Network) -> float:
    """A network's 'ease' score. Higher = higher-priority target."""
    base = ENCRYPTION_WEIGHTS.get(net.encryption, ENCRYPTION_WEIGHTS["UNKNOWN"])
    score = float(base)
    score += signal_score(net.signal)

    # WPS only adds ease for WPA/WPA2
    if net.wps and net.encryption in ("WPA", "WPA2", "WPA2/WPA3"):
        score += WPS_BONUS

    # Connected clients make handshake capture easier
    if net.encryption in ("WPA", "WPA2", "WPA2/WPA3"):
        score += min(len(net.clients) * CLIENT_BONUS_EACH, CLIENT_BONUS_MAX)

    return score


def is_attackable(net: Network) -> bool:
    """Can a meaningful attack (with this tool) be attempted on this network?"""
    if net.is_enterprise:
        return False                      # 802.1X — PSK cracking out of scope
    if net.signal < MIN_SIGNAL_DBM:
        return False                      # signal too weak
    return True


def rank(
    networks: list[Network],
    include_open: bool = True,
    min_signal: int = MIN_SIGNAL_DBM,
) -> list[Network]:
    """Return attackable networks sorted by ease score, descending."""
    targets = []
    for net in networks:
        if net.is_enterprise:
            continue
        if net.channel <= 0:
            continue                      # unknown channel — can't target it
        if net.signal != -1 and net.signal < min_signal:
            continue                      # too weak (but keep unknown signal = -1)
        if net.is_open and not include_open:
            continue
        targets.append(net)
    return sorted(targets, key=attack_score, reverse=True)
