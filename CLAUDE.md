# ldn-beacon

A real Switch's local play (LDN: Wi-Fi action frames plus its own network) bridged into a multiplayer room in the
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
| `src/rd.h` | bounds-checked byte reader / writer: every parse of a frame from the air goes through it |
| `src/crypto.c` | AES-128 (block, CTR) and SHA-256, our own (no crypto library needed) |
| `src/ldnkeys.c` | loads `prod.keys` + `ldn.txt` at run time, derives the advertisement / data keks |
| `src/adv.c` | advertisement decode / encode (CTR, hash check) and to / from a room NetworkInfo |
| `src/advdump.c` | decrypts the advertisements in a pcap (radiotap or bare 802.11), prints them, checks re-encoding; any OS |
| `src/frames.c` | stage 1: the beacon (a Switch's elements) and advertisement for a room network, with the values a console makes up (server random, auth token, nonce, 169.254.X subnet) |
| `src/frametest.c` | writes those frames for a saved NetworkInfo as a pcap (advdump decodes it); any OS |
| `src/radio.c` | Linux: mon0 next to the Wi-Fi interface (as capture.sh), services stopped and restored, raw 802.11 send / receive |
| `src/ap.c` | Linux: hostapd for the network (stage 2): hidden SSID as a Switch's, WPA2 with a guessed key (`--psk-mode`), Nintendo's element, debug log with keys |
| `src/ccmp.c` | CCMP (AES-CCM) in software: the Switch uses the data key directly, so no key is in the driver; ccmptest checks it against IEEE's vector and decrypts captures |
| `src/ldnauth.c` | LDN authentication request parse / response build (challenge HMACs); authtest runs it on captured requests |
| `src/bridge.c` | stage 3: IPv4 / UDP / ARP for the room <-> air bridge (checksums); bridgetest checks it |
| `src/ldnbeacon.c` | Linux, the beacon: joins the room, Scans for a host, puts its network on the air every 100 ms; logs probe requests, joins to us and other consoles |
| `src/roomtest.c` | joins a room, `--scan` broadcasts LDN Scans and prints the networks hosts answer with (`--dump dir`: their raw NetworkInfo); any OS |
| `scripts/radio-check.sh` | first radio test on the laptop: card modes, a capture on channels 1 / 6 / 11 |
| `build.bat` / `CMakeLists.txt` | `ldncore` (crypto, keys, advertisement; no network libraries), `room`, the tools. Windows (roomtest and advdump: clang-cl via `../nxrecomp/tools/vcenv.bat`, vcpkg enet zstd); Linux: `cmake -B build && cmake --build build` (pacman: base-devel cmake enet zstd) |

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

## Protocol (kinnay's NintendoClients wiki: LDN-Protocol, LDN-Passphrases, Local-Wireless-Communication-on-PC; kinnay/LDN README; read 2026-11-06; behaviour only)

Constants (input keys, the challenge HMAC key, Scarlet / Violet's passphrase) are in `../keys/ldn.txt`, not here.
Big-endian unless stated.
- **Advertisement** (vendor action frame to broadcast, every 100 ms): 7f, OUI 00 22 aa, protocol id 4, pad, packet
  type 0x0101, 2 zero, 2 pad; then the payload: session info (32: u64 local communication id, 2 pad, u16 game mode,
  4 pad, 16 SSID bytes), u8 LDN version, u8 encryption (1 plain, 2 AES-CTR, 3 AES-GCM), u16 data size, u32 nonce,
  then (plain / CTR) 32-byte SHA-256 over the whole payload with the hash zeroed, then the data (0x500): 16 server
  random, u16 security level, u8 accept policy, pad, u16 channel | band << 10, u8 max / current participants,
  8 x 56-byte participants (u32 ip, mac, connected, platform 0 Switch / 1 Switch 2, 32 user name, u16 app comm
  version, 10 pad), pad, u16 app data size, 384 app data (Pia's header), pad, 8 auth token at 0x4F8. With CTR the
  hash and the data are encrypted. GCM (mostly Switch 2 games): 16-byte MAC at 0x28, another layout.
- **Keys:** dec(master_key_00, aes_kek_generation_source) -> k1; dec(k1, input key) -> k2;
  dec(k2, aes_key_generation_source) -> k3; key = dec(k3, first 16 bytes of SHA-256(input buffer)). Advertisement:
  input buffer = the 32-byte session info, the advertisement input key. Data frames: input buffer = server random +
  the game's passphrase, the data input key. Verified against the capture 2026-11-06: the "dec" steps are AES-128-ECB; the
  advertisement's CTR counter is the nonce's 4 bytes as sent, then 12 zero bytes (128-bit big-endian counter); the
  hash is SHA-256 over the whole payload (session info .. data) with the hash field zeroed, and it matched. The
  capture's data: security level 1, accept policy 0, channel word 0x080B (11 | band 2 << 10), max 4, current 1.
- **Network:** SSID = 32 random hex digits (the session info's 16 bytes), zeroed in beacons; channels 1 / 6 / 11
  (also 36 / 40 / 44 / 48). Association is open system; our capture's beacon nevertheless has an RSN element
  (WPA2-PSK, CCMP): the data key is probably the PSK / PMK (to verify).
- **Authentication** after associating (EtherType 0x88B7 data frames, "usually encrypted"): 00 22 aa, packet type
  0x0102; LDN version, size, status, request 0 / response 1, size >> 8, pad, session info (little-endian), server
  random, client random (16), then the request (32 user name, u16 app comm version, platform, ...; v3+: a 0x300
  challenge, HMAC-SHA256 over 0x30-0x300) or response (platform, ..., 0x100 challenge response, HMAC over
  0x30-0x100). The station must send it within 5 s; it retries after 700 ms, 3 tries. Status 0 success, 1 denied by
  policy, 2 malformed, 4 bad version, 5 unexpected, 6 bad challenge. Disconnect: packet type 0x0103, reason 3 / 4 / 5.
- **IP:** 169.254.X.Y, X random per network, the host .1, broadcast .255; the host assigns Y on joining; stations
  learn all addresses from the next advertisement's participant list. Frames from the host have FromDS set.
- **Hardware:** iwlwifi drops action frames once joined (Intel: unusable as a station); mt7921e confirmed working
  (the MT7925 is the same family).

Captures (`captures/<date>/`, git-ignored; `scripts/capture.sh` makes them, `radio-check.sh` is the older version):
- MT7925 (mt7925e, CachyOS live 260809, kernel 7.1.6): monitor mode only works on a separate interface
  (`capture.sh ... vif`: mon0, wlan0 down without addresses, NetworkManager / wpa_supplicant stopped); with wlan0
  itself switched to monitor it receives nothing. On the live ISO install libpcap with tcpdump.
- **`captures/20261107-032045-vif/`: a real Switch hosting a Violet local session**, channel 11, MAC
  <the Switch's MAC>: 278 advertisements (1388 bytes, identical: no counter, every ~100 ms; header as above, local
  communication id 0100A3D008C5C000 = Scarlet's title id, shared by both games; LDN version 4, encryption 2 =
  AES-CTR, data size 0x500) and 278 beacons (interval 100, SSID 32 zero bytes, rates 1-54, DS channel 11, RSN
  WPA2-PSK CCMP, HT / HE elements, vendor 00 22 aa 10 01 02, WMM). This is the test vector for the key derivation:
  decrypting it must give a sane NetworkInfo. capture.sh's tcpdump filter for these frames counted 0 although they
  are there: to be replaced by a plain byte search.
  Decrypted 2026-11-06 (`build/advdump captures/20261107-032045-vif/ch11.pcap`): all 278 pass the hash and
  re-encode byte for byte; scene 5, 1 of 4 participants, participant 0 the host at 169.254.27.1 with platform 1
  (a Switch 2), app version 21, app data 0x84 bytes. The app data holds ASCII "1362" at 0x5C, which the user thinks
  was the link code: so a link-code search probably filters scan results on the console (no connection to ask). To
  confirm: two captures with different codes, diffed.
- **A recomp hosting a raid in our room** (2026-11-06, `roomtest --scan --dump`, code 0575): its NetworkInfo's
  advertise data has the same layout as the Switch's app data, the link code in ASCII at 0x5C in both (confirmed:
  the console filters scans on it); they differ only at 5-8 and 0x7D-0x7F (per-session values). The recomp leaves
  security_parameter and random_authentication_id zero and calls itself "Player": so when the room hosts, the
  beacon makes up the server random and auth token itself (the guesses in `adv_to_network_info` do not matter to
  the recomp). Its SSID is Eden's "YuzuFakeSsidForLdn" (the beacon uses the session id's hex). It advertised local
  communication id 01008F6008C5E000 (the title id) where the Switch uses the NACP's 0100A3D008C5C000: a real
  console would not list it. Fixed in nxrecomp's `ldn_net.c` (the NACP's first LocalCommunicationId at 0x30B0),
  checked: the rebuilt recomp advertises 0100A3D008C5C000 (codes 0575, 7718, 2017 all at app data 0x5C).

Stage 1 written 2026-11-06 (ldnbeacon): our frames checked on Windows (frametest -> advdump; the beacon's elements
equal the Switch's but the channel); not yet run on the laptop (now a fresh CachyOS ISO). Test: room server on the
PC, the recomp hosting a raid in it, `sudo ./build/ldnbeacon --room <PC>:24872`, the Switch searches by link code.
Runs 2026-11-06 (Union Circle, the Switch searching by code): our beacon is on the air (the PC's Wi-Fi lists BSSID
<the card's MAC> on 2.4 GHz; mt7925e reports no injected frames back to the monitor interface), but the Switch did
not find it, sent no probe requests with Nintendo's element and nothing to our BSSID (a 68 s recording on channel 6,
`captures/20261106-beacon-run3/`): it scans passively. Our advertisement had our BSSID as addr3; a Switch sends it
with the wildcard BSSID (ff:ff:ff:ff:ff:ff): fixed, now header-for-header as the Switch's. Next run: channel 6, then 11.
Run 4 (channels 11, 6, 1; `captures/20261106-beacon-run4/`): **stage 1 works.** The Switch (<the Switch's MAC>, still
on the home Wi-Fi in the background) sent probe requests on channels 6 and 1 asking for SSID
18d2a425570c10915315dd3b478bff46: the recomp network's session id in hex, which only our advertisement carries. So it
read and decrypted our advertisement, then probed for the network by name to join; we did not answer, so "can't find
the group". Each search sends pairs: a wildcard probe and one for that SSID. Added: probe responses (the beacon's
body with the SSID, no TIM, to the asker). Next: the Switch's authentication / association (stage 2).
Run 5 (channel 11, `captures/20261106-beacon-run5/`): the probe answered, the Switch then sent Open System
authentication (algorithm 0, sequence 1) to our BSSID, 42 times in ~1 s with the retry bit: nothing ACKs it (a monitor
interface does not, and the MT7925 has no ACTIVE_MONITOR extended feature: `iw phy` lists none). So stage 2 cannot be
done with injected frames alone on this card. Plan (asked the user): hostapd AP on the card (hardware ACKs, auth /
association, WPA2 4-way handshake and CCMP; ignore_broadcast_ssid=2 gives the Switch's zero-filled SSID; vendor
elements for Nintendo's), advertisements still injected on mon0, the LDN authentication as EtherType 0x88B7 frames on
the AP interface. Unknown: the WPA2 key (candidate: from the data key); a wrong guess still yields the Switch's
EAPOL message 2 in a capture, to test candidates offline. Alternative: an adapter with active monitor.
Run 7 (`captures/20261106-beacon-run7/`; first --no-ap, which reproduced run 5, then hostapd): with hostapd the
Switch probed, authenticated once (ACKs work), associated (aid 1); hostapd sent 4-way message 1 twice (ACKed) but
**the Switch never answers it: there is no 4-way handshake.** Right after associating it sends CCMP-encrypted QoS data
with **the data key itself as the CCMP key** (ldn_data_key: server random + the game's passphrase; verified: ccmptest
decrypts all 10 frames, MIC ok, no FCS on mon0). They are the LDN authentication request (LLC/SNAP, EtherType 0x88B7),
resent every 200 ms (5 times), then the Switch deauthenticates (reason 3). Request as kinnay documents (re-read
2026-11-06): header 0x0E (OUI, type 0x0102, pad, version 4, size lo 0x64, status, 0 = request, size hi 3, pad 3),
session info little-endian, server random (ours), client random (new per try), payload 0x364: user name, app version
21 (big-endian), platform 1, zeros, then the 0x300 challenge (HMAC-SHA256 at 0x4 over 0x30-0x300 with
ldn_challenge_hmac_key: verified on all 10; P 1, Q 2, flags 2, token = our advertisement's, nonce per try, device id,
16 unknown bytes). Response (ldnauth.c): platform, pad to 0x84, 0x100 challenge response (flags at 0x34, 4 bytes:
copied from the request, a guess; nonce and device id echoed, own device id, the 16 unknown bytes copied; HMAC at 0x4
over 0x30-0x100). authtest builds it from the captured requests and round-trips it through CCMP.
Stage 2b (ldnbeacon): decrypt the Switch's frames, answer the authentication request (QoS data FromDS, CCMP,
injected unicast with ACK / retries), send a room Connect as the beacon's member (the recomp adds a node and sends
SyncNetwork), show the Switch in the advertisement's participant list with its MAC; a deauthentication sends a room
Disconnect. hostapd keeps its unused message 1 going (wpa_pairwise_update_count=100000) instead of kicking the
station. Not yet: the data path (ARP for every room member's 169.254 address, IPv4 / UDP <-> room proxy with address
translation, broadcast frames: their group key is probably the same data key).
Run 8 (`captures/20261106-beacon-run8/`): the Switch's one LDN request (no retry: our response arrived; our frame
is in the capture and decrypts) was answered 1 ms later with status 0; room Connect -> the recomp took it (2 of 4
nodes). 11 ms later the Switch sent an ADDBA response (Block Ack for our QoS data: routine), then nothing until it
deauthenticated (reason 3) 509 ms after our response. So it accepted the frame but left: likely our challenge
response fails its check (the 4-byte flags at 0x34 were a guess: the request's 2), or it waited for something (its
entry in the advertisement should have been there within ~100 ms). Next run: the flags change per join attempt
(2, 1, 0, 3; `--resp-flags` fixes one), the log says which attempt used which and how long the Switch stayed, and
logs the advertised participant list on every change.
Run 9 (`captures/20261106-beacon-run9/`): three joins with response flags 2, 1, 0: each time the room host took the
Switch (node 1, 169.254.X.2, advertised with its MAC and platform 1 right away) and each time the Switch
deauthenticated (reason 3) 510-512 ms after our response. The flags make no difference; a fixed ~510 ms is a
timeout: it waits for something after the response, most likely to see itself in the advertisement. Our
advertisement's nonce never changed within a session (a Switch host's also stays the same while nothing changes), so
a station skipping advertisements by nonce would never see the update: the nonce now changes with the content
(flags back to 2, `--resp-flags` still there). (Reading these logs: hostapd's debug lines interleave with ours, so
grep without anchoring at line start.) The user's second Switch (for a real host + station capture, RUN.txt block 4)
was out of charge.
Run 10 (`captures/20261106-beacon-run10/`): **the nonce fix worked**: the Switch stayed 3.8 s and 4.4 s instead of
510 ms. It took its address from our advertisement (169.254.15.2: a gratuitous ARP), sent IPv6 startup noise, all as
group frames (no DS bits, to broadcast / multicast) **encrypted with the same data key** (key index 1), then left: the
host's game traffic never reached it (the beacon did not forward room packets yet). kinnay's LDN library (read
2026-11-06, behaviour only) agrees: response flags 2, client random echoed, host unk 0x60 zero; the advertisement
nonce is a counter bumped on each change; a station waits up to 1 s for an advertisement with its MAC; data frames
FromDS, one key, key index 0 unicast / 1 broadcast, one PN counter; no ARP (static neighbours from the participant
list), no DHCP, no host timeouts. Two Switches for a reference capture: not possible (one copy of the game).
Stage 3 (bridge.c + ldnbeacon): room proxy datagrams for our member (or broadcast) -> IPv4/UDP from the sender's
169.254.X.(node+1) and advertised MAC (host: BSSID), CCMP, FromDS to the Switch (or broadcast, key index 1); the
Switch's IPv4/UDP (unicast to us or group frames) -> room proxy from our room address to the node's room address
(broadcast for .255 / multicast), protocol number as the host's packets use (3 by default); ARP requests answered with
the advertised MACs; fragments and non-UDP dropped (logged). bridgetest checks the packets.
Run 11 (`captures/20261106-beacon-run11/`, meant for stage 3): **stage 3 never ran.** build.log compiled only
bridge.c and bridgetest.c; ldnbeacon.c (and ccmp.c) kept run 10's object files, and the log's status lines lack the
bridge counters. Cause: zip timestamps are local time (PDT) and the laptop's clock is UTC, so the new sources looked
7 h older than the persistent `build/` and make skipped them. So the run repeats run 10: six joins, each Switch
stay 4.0-4.6 s ending in deauthentication reason 3; in between it sent its gratuitous ARP (169.254.199.2) and IPv6
noise, no IPv4 UDP, and we sent it nothing but the authentication responses (ccmptest with the logged data key: 41
frames decrypt, 6 + 6 LDN, 6 ARP, 23 IPv6). Fixed: RUN.txt builds clean (`unzip -DD`, `rm -rf build`), and ldnbeacon
logs "stage 3 ..., compiled <date time>" at start, so a stale binary shows in the log.
If the Switch lists nothing: it may scan actively (probe requests in the log; answer them), or the card may refuse
injection on mon0 (status line: frames sent / failed).

Next: (3) hosting: two monitor
interfaces as kinnay, or hostapd if it receives what it must; association, the authentication exchange, data.

## Language (open question, for later)

Asked 2026-11-06 whether Rust would suit the beacon better than C; the user chose to continue in C for now and decide
later. For Rust: parsing frames anyone in radio range can send, as root; RustCrypto crates. For C: room.c is shared
with nxrecomp (Rust would keep it through FFI), one toolchain, the hard parts are radio and protocol, not language.
C meanwhile parses only through `src/rd.h`.

## ESP32-S3 instead of a laptop (option, not started)

The S3 (2.4 GHz 802.11n: channels 1 / 6 / 11 are what LDN uses) could be a dumb radio on USB to the desktop: the
room client and translation run on the desktop, the S3 sends and receives 802.11 frames (esp_wifi_80211_tx for
action frames, promiscuous mode for receiving, SoftAP with vendor IEs for the network). Unknowns: whether its
SoftAP takes the LDN key as a raw PMK (its config takes a passphrase), and it has one station interface, so
"Switch hosts" could carry one remote player at most. ESP-IDF is a new download (ask first).
