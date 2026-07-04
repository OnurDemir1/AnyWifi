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

That's all. It finds the interface, offers to install any missing tools, scans,
and attacks the easiest target automatically.

Other options:

```
sudo anywifi -y                  run without asking any questions
sudo anywifi --interactive       choose the target yourself
sudo anywifi --target <BSSID>    attack one specific network
sudo anywifi -w mylist.txt       use your own wordlist
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
   - WPA3 — targets the WPA2 side on mixed networks; pure WPA3 is skipped
     (it can't be cracked offline)
3. Cracks any captured handshake/PMKID with `rockyou.txt` or your wordlist.
4. Saves captures and cracked passwords under `loot/`.

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
