# ldn-beacon

A real Switch's local play (LDN: Wi-Fi action frames plus a WPA2 network) bridged into a multiplayer room in the
protocol Citra, yuzu and Eden rooms speak (nxrecomp's `tools/room/room_server.c`, ours). The desktop runs the room
(and the recomp games, Eden, ...); the beacon runs next to the Switch on a Linux machine with a suitable Wi-Fi card,
joins the room as one member, and forwards everything between the air and the room. The recomp needs no change: to
the room the Switch is one more member. Started 2026-11-06 for Pokemon Violet's Tera raids (see
`../pokemon-violet/CLAUDE.md`, "Local multiplayer"). Local git repo for now (no GitHub remote yet).

Rules (the workspace's, `../CLAUDE.md`): nothing derived from a game or a console goes in this repo (keys stay in
`../keys/`, captures in `captures/`, git-ignored). kinnay's LDN documentation and library, Eden's sources and
Ryujinx are for behaviour only: our own implementation.

## Layout

| Path | What |
|---|---|
| `src/room.c`, `room.h` | room client (ENet + zstd), single-threaded and portable; from nxrecomp's `runtime/net/room.c` |
| `src/ldn.h` | LDN structures as the room carries them (NetworkInfo 0x480, NodeInfo 0x40; as nxrecomp's `ldn_net.c`) |
| `src/roomtest.c` | joins a room, `--scan` broadcasts LDN Scans and prints the networks hosts answer with; any OS |
| `scripts/radio-check.sh` | first radio test on the laptop: card modes, a capture on channels 1 / 6 / 11 |
| `build.bat` / `CMakeLists.txt` | Windows (roomtest only: clang-cl via `../nxrecomp/tools/vcenv.bat`, vcpkg enet zstd); Linux: `cmake -B build && cmake --build build` (pacman: base-devel cmake enet zstd) |

Checked 2026-11-06: two roomtest clients in our room_server (192.168.1.1 / .2), Scans relayed.

## Design

Hardware: the user's laptop (HP Omen MAX 16, MediaTek MT7925, mt7925e / mt76: AP + monitor) from a CachyOS live
USB (Ventoy, persistence), wired to the LAN (the radio is the LDN network). Fallbacks: a Pi 4 with a USB mt76
adapter (MT7921AU / MT7612U); an ESP32-S3 as a USB radio for the desktop (see below).

Both directions, the first one first:
1. **Room hosts, Switch joins.** A member's network (ScanResp / SyncNetwork NetworkInfo) is advertised on the air
   as a console would (action frames, OUI 00:22:AA, channel 1 / 6 / 11) and hosted as a WPA2 access point
   (hostapd, nl80211); the Switch associates; its Connect becomes an LDN Connect to the host member, SyncNetwork
   comes back and is sent to it on the air.
2. **Switch hosts, room joins.** The beacon listens for the Switch's advertisement, answers room Scans with it, and
   for each member that Connects joins the Switch's network as one more station (a virtual interface per member,
   limited by the card's interface combinations).
Data: the games' UDP (Pia) passes through unchanged (end-to-end encrypted by the games). Addresses are translated:
the Switch's address on its LDN network <-> the beacon's room address; each remote member's room address <-> an
address on the LDN network (the beacon answers ARP for them and injects / captures frames with AF_PACKET).

Captures (`captures/<date>/`, git-ignored; `scripts/capture.sh` makes them, `radio-check.sh` is the older version):
- 2026-11-06, Omen (MT7925, mt7925e, CachyOS live 260809), wlan0 itself switched to monitor: 19 records per channel
  in 45 s, all the laptop's own outgoing packets (its IP was still set), not one received frame (no beacons). The
  card lists AP and monitor modes. Next: capture.sh `vif` (separate mon0, NetworkManager / wpa_supplicant stopped),
  else the ZBook (Intel; monitor mode known to work there).
- On the live ISO, `pacman -Sy tcpdump` alone left an older libpcap (undefined symbol pcap_findalldevs_ex): install
  libpcap with it.

Open: the network's WPA2 key and the advertisement's encryption (derived from console keys: from `prod.keys`?), the
advertisement frame layout (the capture from radio-check.sh is the reference), whether mt7925e sends action frames
from an AP interface, how many station interfaces it allows.

## ESP32-S3 instead of a laptop (option, not started)

The S3 (2.4 GHz 802.11n: channels 1 / 6 / 11 are what LDN uses) could be a dumb radio on USB to the desktop: the
room client and translation run on the desktop, the S3 sends and receives 802.11 frames (esp_wifi_80211_tx for
action frames, promiscuous mode for receiving, SoftAP with vendor IEs for the network). Unknowns: whether its
SoftAP takes the LDN key as a raw PMK (its config takes a passphrase), and it has one station interface, so
"Switch hosts" could carry one remote player at most. ESP-IDF is a new download (ask first).
