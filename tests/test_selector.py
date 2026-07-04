from anywifi.attacks import chain_for
from anywifi.model import Network
from anywifi.target import selector


def net(bssid, enc, signal=-50, wps=False, clients=0, auth="", channel=6):
    return Network(
        bssid=bssid, essid=enc, encryption=enc, signal=signal, channel=channel,
        wps=wps, clients=[f"c{i}" for i in range(clients)], auth=auth,
    )


def test_unknown_signal_not_ranked_top():
    # airodump power -1 means "unknown" — must not beat a strong known signal
    unknown = net("00:00:00:00:00:01", "WPA2", signal=-1)
    strong = net("00:00:00:00:00:02", "WPA2", signal=-40)
    assert selector.attack_score(strong) > selector.attack_score(unknown)


def test_rank_excludes_unknown_channel():
    bad = net("00:00:00:00:00:01", "WPA2", channel=0)
    good = net("00:00:00:00:00:02", "WPA2", channel=6)
    ranked = selector.rank([bad, good])
    assert good in ranked
    assert bad not in ranked


def test_rank_keeps_unknown_signal():
    unknown = net("00:00:00:00:00:01", "WPA2", signal=-1, channel=6)
    assert unknown in selector.rank([unknown])


def test_score_ordering_open_and_wep_highest():
    wpa2 = net("00:00:00:00:00:01", "WPA2")
    wep = net("00:00:00:00:00:02", "WEP")
    openn = net("00:00:00:00:00:03", "OPEN")
    wpa3 = net("00:00:00:00:00:04", "WPA3")
    ranked = selector.rank([wpa2, wep, openn, wpa3])
    encs = [n.encryption for n in ranked]
    # OPEN and WEP at the top, WPA3 at the bottom
    assert encs[0] in ("OPEN", "WEP")
    assert encs[-1] == "WPA3"


def test_wps_boosts_wpa2():
    plain = net("00:00:00:00:00:01", "WPA2")
    with_wps = net("00:00:00:00:00:02", "WPA2", wps=True)
    assert selector.attack_score(with_wps) > selector.attack_score(plain)


def test_clients_boost_wpa2():
    lonely = net("00:00:00:00:00:01", "WPA2")
    busy = net("00:00:00:00:00:02", "WPA2", clients=3)
    assert selector.attack_score(busy) > selector.attack_score(lonely)


def test_enterprise_filtered_out():
    ent = net("00:00:00:00:00:09", "WPA2", auth="MGT")
    assert ent.is_enterprise
    assert selector.rank([ent]) == []


def test_weak_signal_filtered():
    weak = net("00:00:00:00:00:09", "WPA2", signal=-95)
    assert selector.rank([weak]) == []


def test_chain_for_wpa2_has_pmkid_and_handshake():
    n = net("00:00:00:00:00:01", "WPA2", clients=1)
    vectors = [a.vector for a in chain_for(n)]
    assert "pmkid" in vectors
    assert "handshake" in vectors


def test_chain_for_wep():
    n = net("00:00:00:00:00:02", "WEP")
    vectors = [a.vector for a in chain_for(n)]
    assert vectors == ["wep"]


def test_chain_for_wpa3_pure():
    n = net("00:00:00:00:00:03", "WPA3")
    vectors = [a.vector for a in chain_for(n)]
    # Pure WPA3: only the informational vector (no deauth/pmkid applied)
    assert vectors == ["wpa3"]


def test_chain_for_transition_uses_wpa2_vectors():
    n = net("00:00:00:00:00:04", "WPA2/WPA3", clients=1)
    vectors = [a.vector for a in chain_for(n)]
    assert "pmkid" in vectors  # the WPA2 side is targeted
