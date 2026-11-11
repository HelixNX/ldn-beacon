# ldn-beacon

A real Switch's local play (LDN: Wi-Fi action frames plus its own network) bridged into a multiplayer room in the
protocol Citra, yuzu and Eden rooms speak (`../room`, ours). The desktop runs the room and the recomp; the radio
next to the Switch is an ESP32-S3 on USB (or, on Linux, a Wi-Fi card with monitor + AP modes); the beacon joins the
room as one member and forwards everything between the air and the room. To the room the Switch is one more
member. Started 2026-11-06 for Pokemon Violet's Tera raids. Local git repo for now (no remote yet). Builds on its
own; runs only with the user's own files (below).

Rules (the workspace's, `../CLAUDE.md`): nothing derived from a game or a console goes in this repo (keys stay in
`../keys/`, captures in `captures/`, git-ignored). kinnay's LDN documentation and library, Eden's sources and
Ryujinx are for behaviour only: our own implementation. **The protocol, the radio work and every run are in
`NOTES.md`** (moved there unchanged on 2026-11-07): grep it before proposing anything; add new runs there.

## Start here

| Do | Command |
|---|---|
| Build (Windows: Visual Studio's clang-cl, `vcpkg install enet zstd zlib`) | `build.bat` (or `..\start.ps1 build beacon`) |
| Build (Linux) | `cmake -B build && cmake --build build` (pacman: base-devel cmake enet zstd zlib iw) |
| A Tera raid with a real Switch | 1. `..\start.ps1 room -Beacon` (both in this console: the room hidden with Violet's game id, the beacon in the foreground; their logs and the pcap in `captures\<time>\`; Ctrl+C stops both; separately: `..\start.ps1 room`, then `..\start.ps1 beacon`) 2. `..\start.ps1 violet -NoBuild -Room 127.0.0.1:24872 -Nick Host`, host a raid with a link code, search for it on the Switch |
| Flash the S3's firmware | in `s3\`, after ESP-IDF's EIM profile (`. <IDF tools dir>\Microsoft.v5.5.6.PowerShell_profile.ps1`): `idf.py build`, `idf.py -p <port> flash` (stop ldnbeacon first: it holds the port) |
| S3 bench without a Switch | `build\s3test [--ap] [--tx]` |
| Check a capture / a log's Pia packets | `build\advdump <pcap>`, `build\piatest ...` (Layout below) |

Keys: nothing of Nintendo's is in the repo. Every tool reads the user's own files (`src/ldnkeys.c`, `src/nxfs.c`):
`prod.keys` (+ `title.keys`), the firmware's NCAs (the LDN input keys are in its `ldn` module, the challenge HMAC key
in `es`) and, for ldnbeacon / ldnjoin, the game's NSPs (its passphrase and Pia key are in its `main`); each constant
is recognised by its SHA-256. `--files <dir>` (repeatable) on every tool: searched for the keys, NSPs, and NCAs in it,
its subfolders and `firmware/` (so a game's package folder works as is); default `.`, `../keys`, `../firmware`,
`../pkmn-violet/rom`, and `~/.switch` for keys. Loading takes ~4 s (scanning the game's code). `--game
scarlet_violet` (ldnbeacon; the only one so far). Stop the beacon only when the user says the raid / session is over.
## Layout

| Path | What |
|---|---|
| `src/room.c`, `room.h` | room client (ENet + zstd), single-threaded and portable; from nxrecomp's `runtime/net/room.c` |
| `src/ldn.h` | LDN structures as the room carries them (NetworkInfo 0x480, NodeInfo 0x40; as nxrecomp's `ldn_net.c`) |
| `src/rd.h` | bounds-checked byte reader / writer: every parse of a frame from the air goes through it |
| `src/crypto.c` | AES-128 (block, CTR) and SHA-256, our own (no crypto library needed) |
| `src/ldnkeys.c` | finds the LDN constants in the user's firmware and game by their SHA-256 (only the hashes are in the source), derives the advertisement / data keks |
| `src/nxfs.c` | the user's NSPs and firmware NCAs read in place (NCA3 header XTS, section CTR, PFS0, NSO LZ4), portable; as nxrecomp's `runtime/nca.c` |
| `src/adv.c` | advertisement decode / encode (CTR, hash check) and to / from a room NetworkInfo |
| `src/advdump.c` | decrypts the advertisements in a pcap (radiotap or bare 802.11), prints them, checks re-encoding; any OS |
| `src/frames.c` | stage 1: the beacon (a Switch's elements) and advertisement for a room network, with the values a console makes up (server random, auth token, nonce, 169.254.X subnet) |
| `src/frametest.c` | writes those frames for a saved NetworkInfo as a pcap (advdump decodes it); any OS |
| `src/radio.h`, `radio.c` | the radio, two kinds (`--radio s3[:port] \| wifi[:iface]`; default: an S3 if one is plugged in, else the built-in card; wifi is Linux only): raw 802.11 send / receive (radiotap in front for the pcap) and an AP for ACKs, authentication and association |
| `src/radio_linux.c` | Linux: mon0 next to the Wi-Fi interface (as capture.sh), services stopped and restored |
| `src/ap.c` | Linux: hostapd for the network (stage 2): hidden SSID as a Switch's, WPA2 with a guessed key (`--psk-mode`), Nintendo's element, debug log with keys |
| `src/radio_s3.c` | any OS: the ESP32-S3 radio on a serial port (Windows: the first USB device with vendor id 303A; Linux: `/dev/serial/by-id/*Espressif*`); its log lines, station events and statistics go into ldnbeacon's log |
| `src/s3proto.h`, `.c` | the S3 link: COBS-framed messages with CRC-16, shared with the firmware; s3prototest checks the framing |
| `s3/` | the S3's firmware (ESP-IDF 5.3+, `idf.py build flash`): SoftAP (placeholder until the beacon names the network), promiscuous receive filtered to our BSSID / probes / Nintendo action frames, `esp_wifi_80211_tx`; station mode for joining a console's network (`S3_JOIN`, protocol version 4); console and ESP-IDF log on UART0, the log also forwarded over USB. A panic saves a core dump to flash (`partitions.csv`): `idf.py -p <port> coredump-info` (stop ldnbeacon / ldnjoin first); the boot log line gives the reset reason and the last breadcrumb (`CRUMB`, RTC memory) |
| `src/ccmp.c` | CCMP (AES-CCM) in software: the Switch uses the data key directly, so no key is in the driver; ccmptest checks it against IEEE's vector and decrypts captures |
| `src/ldnauth.c` | LDN authentication request parse / response build (challenge HMACs); authtest runs it on captured requests |
| `src/bridge.c` | stage 3: IPv4 / UDP / ARP for the room <-> air bridge (checksums); bridgetest checks it |
| `src/ldnbeacon.c` | the beacon (Linux with mon0 + hostapd, or any OS with the S3): joins the room, Scans for a host, hosts its network on the air (advertisements on mon0, hostapd for association), answers the LDN authentication, joins the Switch to the room host, bridges its UDP (Pia re-addressed and rewritten); logs it all, compile time first |
| `src/pia.c` | Pia 6.x in LDN mode: CRC-32, AES-GCM (8-byte tag), session key and nonce, message parse / rewrite of addresses and constant ids (zlib) |
| `src/piatest.c` | GCM against NIST's vector; finds the Pia variant that authenticates a capture's Pia packets (or `pkt:<src ip>:<hex>` packets from a log, capture `-`); prints the first decrypted; `map:` / `as:` round-trip a rewrite and print the result as a `pkt:` input |
| `src/ldnjoin.c` | the S3 joins a real console's network as a station (design item 2's first half): scans 6 / 1 / 11 for an advertisement, joins, sends the LDN authentication request (`ldn_auth_request`), answers ARP, logs every UDP packet from the host and tries each Pia packet against the candidate key / nonce derivations; sends nothing to the game. `build/ldnjoin.exe [--channels 6,1,11] [--pcap file] [--token raw]` |
| `src/roomtest.c` | joins a room, `--scan` broadcasts LDN Scans and prints the networks hosts answer with (`--dump dir`: their raw NetworkInfo); any OS |
| `scripts/radio-check.sh` | first radio test on the laptop: card modes, a capture on channels 1 / 6 / 11 |
| `build.bat` / `CMakeLists.txt` | `ldncore` (crypto, keys, advertisement; no network libraries), `room`, the tools. Windows (everything including ldnbeacon with the S3: clang-cl via `scripts/vcenv.bat`, vcpkg enet zstd zlib); Linux: `cmake -B build && cmake --build build` (pacman: base-devel cmake enet zstd) |

Checked 2026-11-06: two roomtest clients in our room_server (192.168.1.1 / .2), Scans relayed.

## Design

Hardware: the user's laptop (HP Omen MAX 16, MediaTek MT7925, mt7925e / mt76: AP + monitor) from a CachyOS live
USB (Ventoy, persistence), wired to the LAN (the radio is the LDN network). Fallbacks: a Pi 4 with a USB mt76
adapter (MT7921AU / MT7612U); an ESP32-S3 as a USB radio for the desktop (see below).

**Priority (the user, 2026-11-06): the room hosts, a real Switch joins** (a Windows recomp hosts a Tera raid in the
room; raids between two Windows clients already work). Second: the Switch hosts, the room joins.
1. **Room hosts, Switch joins.** The beacon takes the host member's NetworkInfo (room ScanResp / SyncNetwork) and
   hosts it on the air as a console would: beacons with a zeroed SSID, the advertisement action frame every 100 ms,
   then association, LDN authentication (below), and the participant list in later advertisements. The Switch's
   join becomes an LDN Connect to the host member; its UDP becomes proxy packets. kinnay found AP mode unusable for
   hosting (broadcast frames to the AP are not received) and IBSS drops association requests: his library hosts
   with two monitor interfaces (one active, one passive), its own 802.11 handling, and a TAP interface for the data.
   Plan the same unless hostapd turns out to work on the MT7925.
2. **Switch hosts, room joins.** The beacon decrypts the Switch's advertisement into a NetworkInfo for room Scans
   and, for each member that Connects, joins as one more station (802.11 + LDN authentication per member).
Data: the games' UDP (Pia) passes through unchanged. Addresses are translated: the Switch's 169.254.X.Y <-> the
beacon's room address; each remote member's room address <-> a 169.254.X.Y on the LDN network.


## State (2026-11-11)

- **Room hosts, Switch joins: works.** S3 run 12: three complete Tera raids, a real Switch joining the recomp's,
  no drops (the user: "Game is working very well"); Union Circle works (run 8); link trades work (2026-11-11). A
  host tearing its network down (a link-code search hosts and scans in turns) is dropped at once on its DestroyNetwork
  (recomp hosts send it to whoever scanned them), else after 2.5 s without a ScanResp (scans every 0.5 s): a Switch
  joining a dead network gave up after ~515 ms. NOTES.md has the run.
- The S3 hosts the network with its BSSID set to the room host's MAC and the room Connect carries the Switch's real
  MAC, so Pia's constant ids match on both sides (the host's id also rides inside the game's own zlib data); only
  IPs are rewritten. Linux / hostapd cannot change its BSSID per network: there the ids still differ.

## Open

- The Linux Wi-Fi card route (`--radio wifi`, hostapd) is parked: the user moved to the S3, which works on any OS (2026-11-09).
- Several Switches at once (one room member each; the S3's AP takes up to 8).
- The Switch hosting with the room joining (design item 2; `ldnjoin` is its first half).
- nxrecomp's CreateNetwork should make a random security parameter, as a console does.
- Other ESP32 chips (the user asked, 2026-11-07): the radio calls exist on ESP32 / S2 / S3 / C3 / C5 / C6. What
  ties the firmware to the S3: the USB link is the USB-Serial-JTAG peripheral (also on C3 / C5 / C6; classic ESP32
  and USB-UART boards need a UART link, S2 TinyUSB CDC) and the desktop looks for vendor id 303A; one task is
  pinned to core 1 (single-core chips: use tskNO_AFFINITY); `sdkconfig.defaults` targets esp32s3. Untested on others.
- For later (the user, 2026-11-07): the whole room server on the microcontroller with the beacon. Thoughts so far:
  the beacon logic (LDN auth, CCMP, Pia rewrite with zlib) runs on the desktop today and would move to the chip;
  ENet over UDP needs an uplink (station mode to the home network on the same radio, so the home AP's channel
  becomes the LDN channel) or USB networking to the PC; RAM is the question for zlib and the per-member state.