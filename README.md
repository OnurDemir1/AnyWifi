# AnyWifi

An autonomous WiFi pentest tool for the command line. It scans the nearby
networks, picks the easiest one to break, and attacks them from easiest to
hardest. If it captures a handshake or PMKID, it cracks it with your wordlist.

**Linux only.** Real WiFi attacks need monitor mode and packet injection, so you
need Linux (Kali is easiest) with a compatible adapter, run as root.

**Use it only on your own networks or networks you have permission to test.**

## Install

Clone it and run the installer. This puts a global `anywifi` command in
`/usr/local/bin`, so you can run it from any directory. No pip needed.

```
git clone https://github.com/OnurDemir1/AnyWifi
cd AnyWifi
sudo ./install.sh
```

For colored output, optionally install rich (it works without it too):

```
sudo apt install -y python3-rich
```

To uninstall: `sudo rm /usr/local/bin/anywifi`.

(No-install alternative: just run `sudo python3 -m anywifi` from inside the
cloned folder.)

## Usage

Just run it, from anywhere:

```
sudo anywifi
```

It finds the interface, offers to install any missing tools, and scans (2.4 and
5 GHz). Then it shows the networks and asks which one(s) to attack — press
**Enter** to auto-attack the easiest first, or type a number (e.g. `1` or `1,3`)
to pick.

While it works you get a clean, live view: each phase (PMKID, handshake,
cracking…) shows as a single line with a spinner and a running timer, so you can
always tell it's still going and how long it's taken. During cracking it shows a
progress bar with how many passwords have been tried and the current speed.

Other options:

```
sudo anywifi -y                  hands-off: auto-attack all, no questions
sudo anywifi --target <BSSID>    attack one specific network
sudo anywifi -w mylist.txt       use your own wordlist
sudo anywifi --5ghz              also scan 5 GHz (needs a 5 GHz-capable adapter)
sudo anywifi -v                  verbose: also print the raw tool commands
anywifi --dry-run                show the commands without running them
```

Full list: `anywifi --help`.

## How it works

1. Scans nearby networks and scores them (encryption, signal, WPS, clients).
2. Starts with the easiest and tries attacks in order:
   - Open — nothing to crack
   - WEP — recover the key from captured traffic
   - WPS — Pixie-Dust, then PIN bruteforce
   - WPA/WPA2 — PMKID (no client needed) or 4-way handshake via deauth
   - WPA3 — see below
3. Cracks any captured handshake/PMKID with `rockyou.txt` or your wordlist.
4. Saves captures and cracked passwords under `loot/`.

## WPA3

WPA3 is handled realistically (no evil-twin / captive-portal — that's social
engineering and out of scope):

- **Transition (mixed) mode** — the practical WPA3 attack. These APs broadcast
  WPA2 + WPA3 under one SSID, so the tool automatically targets the **WPA2 side**
  (PMKID / 4-way handshake) and cracks it offline. This runs by default.
- **Pure WPA3-SAE** — SAE can't be cracked offline and PMF blocks deauth, so it's
  skipped by default. There's an **opt-in, experimental** Dragonblood timing
  side-channel (`sudo anywifi --only wpa3`) using `dragontime` + `dragonforce`. It
  only works if the AP enables MODP group 22/23/24 (most don't) and needs an
  Atheros card with the `ath_masker` module — see
  [dragondrain-and-time](https://github.com/vanhoefm/dragondrain-and-time).

## Requirements

- Linux (Kali recommended), run with `sudo`
- A WiFi adapter that supports monitor mode + injection
- Python 3.9+

The tool uses aircrack-ng, hcxdumptool, hcxtools, reaver and hashcat. It will
offer to install anything that's missing on first run, or run
`sudo anywifi --install-deps`.

## Wordlist

It looks for `rockyou.txt` automatically (the usual Kali paths, your home folder,
the current folder). If it can't find one, it asks you for a path. Use `-w` to
set your own.

## License

MIT © OnurDemir1
