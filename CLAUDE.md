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
| `src/piatest.c` | GCM against NIST's vector; finds the Pia variant that authenticates a capture's Pia packets; `map:` / `as:` round-trip a rewrite |
| `src/ldnjoin.c` | the S3 joins a real console's network as a station (design item 2's first half): scans 6 / 1 / 11 for an advertisement, joins, sends the LDN authentication request (`ldn_auth_request`), answers ARP, logs every UDP packet from the host and tries each Pia packet against the candidate key / nonce derivations; sends nothing to the game. `build/ldnjoin.exe [--channels 6,1,11] [--pcap file] [--token raw]` |
| `src/roomtest.c` | joins a room, `--scan` broadcasts LDN Scans and prints the networks hosts answer with (`--dump dir`: their raw NetworkInfo); any OS |
| `scripts/radio-check.sh` | first radio test on the laptop: card modes, a capture on channels 1 / 6 / 11 |
| `build.bat` / `CMakeLists.txt` | `ldncore` (crypto, keys, advertisement; no network libraries), `room`, the tools. Windows (everything including ldnbeacon with the S3: clang-cl via `../nxrecomp/tools/vcenv.bat`, vcpkg enet zstd); Linux: `cmake -B build && cmake --build build` (pacman: base-devel cmake enet zstd) |

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

Constants (input keys, the challenge HMAC key, Scarlet / Violet's passphrase and Pia game key) are in `../keys/ldn.txt`, not here.
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
Run 12 (`captures/20261106-beacon-run12/`, stage 3 for real: the "compiled" line is there): three joins, the Switch
left 4.4-4.6 s after each (reason 3), as before. **The room host reacts to the join**: while the Switch is in its
network it broadcasts 108-byte UDP from port 12345 to 192.168.1.255:12345 about twice a second (27 forwarded as group
frames, key index 1; one more dropped right after a leave; never sent before a join), and sends no unicast. **The
Switch never answers**: no IPv4 UDP at all, only its gratuitous ARP and IPv6 noise (ccmptest: 19 frames decrypt).
So it probably does not take our group frames. Our injected group frames are not in the pcap (mt7925e reports only
injected frames that wait for an ACK), so the capture cannot show what went out. Seen: the Switch's group frames have
no DS bits (addr3 our BSSID), key index 1, and its CCMP packet numbers start at a random 48-bit value on each join
(0x2e06668ad953, 0x46f22cc59461, 0xc5d5202fc289, 0xeb78780e228a) where ours started below 0x10000.
Next run (ldnbeacon): our PN starts at 0xF000xxxxxxxx (above the Switch's, in case one replay counter per key);
`--bcast-mode` (default 2: odd join attempts send the room's broadcasts as group frames, even attempts as unicast
frames to the Switch's MAC with the IP broadcast inside; 0 group only, 1 unicast only); after each join an ARP request
from the host (.1, BSSID) for the Switch's address as a group frame (+500 ms) and as unicast (+1500 ms), and the
Switch's ARP replies are logged: which path reaches it. Unicast frames from the host are logged (first 20).
Run 13 (`captures/20261106-beacon-run13/`): three joins, left after 4.3-4.5 s each. **The Switch answers unicast
frames and not group frames**: our group ARP probe (+500 ms) was never answered, the unicast one (+1500 ms) at once,
all three times (group frames had the high PN too). In join 2 (broadcasts as unicast frames) the host's Pia packets
reached it (ACKed, in the capture: IPv4/UDP 169.254.69.1:12345 -> .255:12345, Pia's magic 32ab9864) and it still sent
no UDP. Likely cause: the security parameter. nxrecomp's CreateNetwork (Violet's raids) leaves security_parameter
zero and GetSecurityParameter returns it with the session id; the beacon advertised a made-up server random, so the
Switch's GetSecurityParameter differed from the host's, and Pia (keyed from it, presumably) could not read the host.
Next run (ldnbeacon): the advertised server random is the host's security parameter (zero from a recomp; logged at
start), auth token the host's random_authentication_id when nonzero, broadcasts as unicast frames by default
(`--bcast-mode 1`). Later in nxrecomp: CreateNetwork should make a random security parameter as a console does
(not needed for the beacon: it copies whatever the host has).
Run 14 (`captures/20261106-beacon-run14/`): server random zero (the host's), broadcasts as unicast frames, unicast
ARP probe answered: three joins, the Switch got the host's Pia packets and still sent no UDP, left after 4.5-4.6 s.
**Cause (kinnay's wiki, PIA-Protocol, read 2026-11-07, behaviour only): Pia 6.x cannot pass through address
translation.** Violet's packets have version byte 0x8B (encrypted, version 11 = Pia 6.16-6.23; header: magic,
version, u16 destination / source variable id, u16 packet id, u8 footer size, 8-byte nonce, first 8 bytes of the GCM
tag). LDN mode, 6.16-6.42: the 12-byte GCM nonce is XOR(network id, the source's IP address) + the header's nonce,
and the session key is AES(game key, the network's SSID). The recomp encrypts with its room address (192.168.1.2)
and its SSID is Eden's "YuzuFakeSsidForLdn"; the Switch decrypts with 169.254.X.1 and the session id's hex SSID, so
no packet can authenticate in either direction, whatever the bridge does with frames. (Broadcasts: the footer lists
the receivers' variable ids.) The fix has to be on the recomp's side (it presents LDN as a console does: 169.254.X
addresses and the hex SSID) or the beacon re-encrypts every Pia packet (needs the game key and the network id; any
addresses inside Pia messages would need rewriting too).
Pia re-addressing (2026-11-07; the user chose it over changing the recomp): `src/pia.c` (CRC-32, AES-GCM with an
8-byte tag, NIST vector ok), `piatest` tries the wiki's open details on a capture's Pia packets. **Settled on run 14:
all 28 host packets authenticate** with session key = AES-encrypt(game key, the session id's 16 raw bytes) (the
recomp's Pia reads the session id, not Eden's SSID string: so the key is the same on the air), nonce prefix =
CRC-32(session id[1..15]) XOR the source IPv4, both big-endian, no AAD; re-encrypting gives the packet back. The game
key is `pia_game_key_scarlet_violet` in `../keys/ldn.txt` (kinnay's Pia-Game-Keys). ldnbeacon decrypts each Pia
packet with the sender's address on its side and encrypts it with the address the receiver sees (room -> air: the
node's 169.254.X.(i+1); air -> room: our room address) and logs the first few and the counts. The host's first packet
is a Net (0x2C) message. Still possible after this: Pia's LDN constant id comes from the MAC (Pia-Types), and the MACs
differ between the sides (the host: 02:00:c0:a8:01:02 in the room, our BSSID on the air; the Switch: its own on the
air, 02:00:c0:a8:01:03 in the room); if Pia checks them, the BSSID could take the host's room MAC.
Run 15 (`captures/20261107-beacon-run15/`, Pia re-addressed): two joins, left at 4.5 s again; the host's packets
on the air authenticate as from 169.254.50.1 (piatest: 18 of 18), but **the messages carry room addresses**: the
host's Net (0x2C) message, message flags 0x31 (0x20: zlib, a 4 KB window), inflates to a station list with the host's
constant id c00102a800020000 (from 02:00:c0:a8:01:02), the network id, and StationAddresses 192.168.1.2:12345 (the
host) and 192.168.1.3:12345 (the slot for the joining station: our room address), so the Switch (169.254.50.2) does
not find itself. Message format (5.27-6.30) as the wiki has it: u8 field flags (1 message flags, 2 u16 size, 4 u8
protocol + u24 port, 8 u64 destination; absent fields from the previous message; upper bits seen set, no fields),
payload, padded to 4; 0xFF pads the messages to 16. Now `pia_rewrite` (pia.c, zlib) inflates compressed payloads,
replaces every node's IPv4 and MAC-made constant id with the other side's (room -> air: node i's room address and
room MAC -> 169.254.X.(i+1) and the air's MAC: the host's is our BSSID, ours the Switch's real one; air -> room the
reverse), deflates, writes every message's fields out and re-encrypts; piatest's round trip on run 15's packet: 3
replaced, 108 -> 108 bytes, decrypts as from 169.254.50.1. zlib: vcpkg (Windows), pacman `zlib` (in RUN.txt).
kinnay's LDN library (`../ref/LDN`, GPLv3, cloned 2026-11-07: behaviour only, never copied), checked against our
open points: its host's data frames are non-QoS data, FromDS, addr1 the destination, **addr2 the Ethernet source**
(not the BSSID), addr3 the BSSID, CCMP with nonce priority 0 + addr2 + PN, one PN counter from 1, key index 1 for
broadcast and 0 otherwise; the key goes into the driver at both indices. So our group frames are built as its are
(for the host's frames addr2 = BSSID either way); relaying a third member's packets to the Switch should put that
member's MAC in addr2 as kinnay does. Run 13 timing: the Switch announced its address (gratuitous ARP) 200 ms after
our authentication response, before the group ARP probe (+500 ms), so that probe was valid and unanswered: our
injected group data frames probably never leave the card (mt7925e; the capture cannot show it: no-ACK injections are
not reported back). The Switch sends everything as group frames (addr1 ff:ff:ff:ff:ff:ff, no DS bits, addr3 our
BSSID), its ARP reply to .1 too: the beacon takes those already (on_frame, by IP destination).
If the Switch lists nothing: it may scan actively (probe requests in the log; answer them), or the card may refuse
injection on mon0 (status line: frames sent / failed).

**Superseded by "Switch hosts, the S3 joins" at the end (2026-11-07): read that first.** Earlier state (after S3 run 3): the ESP32-S3 on the desktop is the antenna now (section "ESP32-S3
as the antenna"); the laptop is only a fallback. Room hosts, Switch joins: it finds the network, associates,
authenticates, takes its address, answers group and unicast ARP, and gets the host's Pia packets re-addressed with
the addresses inside rewritten, but **sends no Pia (no IPv4 UDP) and leaves after ~4.6 s** (console "2318-0533").
Next, in order:
1. Run 16 (laptop, before the S3): dropped (the user, 2026-11-07: the stick is done, the S3 is the antenna).
2. The beacon should write what it sends into its pcap (the S3 cannot capture its own transmissions; with the S3 the
   frames go out as Ethernet frames the hardware encrypts, so write them as plain data frames, marked).
3. piatest on what goes to the Switch (room -> air) and on the host's room side: why does the Switch not take the
   host's messages? Then, as they come: the raid's messages (join, lobby, battle), anything Pia checks against MACs.
Open: relayed frames from a third member (addr2 their MAC, as kinnay); several Switches (one room member each; the
S3's AP takes up to 8 here); nxrecomp's CreateNetwork should make a random security parameter as a console does
(the beacon copies whatever the host has); the Switch hosting with the room joining (design item 2) is not started.
Running it (S3, all on the desktop): the room server (`../pokemon-violet/build/room/room_server.exe --port 24872
--name "LDN test" --game-id 01008F6008C5E000 --game "Pokemon Violet"`), then from ldn-beacon/
`build/ldnbeacon.exe --room 127.0.0.1:24872 --channel 6 --pcap captures/<run>/beacon.pcap > captures/<run>/beacon.log
2>&1` (finds the S3 by itself; `build.bat` builds it), then the user starts the game from pokemon-violet/
(`$env:NX_ROOM='127.0.0.1:24872'; $env:NX_NICK='Host'; .\violetrecomp\run.ps1 -NoBuild`), hosts a raid with a link
code and searches for it on the Switch. Firmware: in `s3/`, after the EIM profile
(`. <IDF tools dir>\Microsoft.v5.5.6.PowerShell_profile.ps1`), `idf.py build` and `idf.py -p <port> flash` (stop
ldnbeacon first: it holds the port). Bench without a Switch: `build/s3test [--ap] [--tx]`.
Laptop runs (fallback): `RUN.txt` at the stick's root: unzip with -DD, clean build, then ldnbeacon; results to the
stick; saved here as `captures/<date>-beacon-runN/`. The zip carries `../keys/prod.keys` and `ldn.txt`.

## Language (open question, for later)

Asked 2026-11-06 whether Rust would suit the beacon better than C; the user chose to continue in C for now and decide
later. For Rust: parsing frames anyone in radio range can send, as root; RustCrypto crates. For C: room.c is shared
with nxrecomp (Rust would keep it through FFI), one toolchain, the hard parts are radio and protocol, not language.
C meanwhile parses only through `src/rd.h`.

## ESP32-S3 as the antenna (2026-11-07, the user's choice: no more walking to the laptop)

The user's ESP32-S3-DevKitC-1 on the desktop's native USB port (USB-Serial-JTAG, 303A:1001; it came with a
TinyUSB firmware, 303A:4001) is a dumb radio; ldnbeacon runs on Windows next to the room server and does everything
else, unchanged: the S3 stands in for mon0 (promiscuous receive, raw transmit) and hostapd (SoftAP: hardware ACKs,
Open System authentication, association). ESP-IDF 5.5.6 installed by the user with Espressif's EIM (winget
`Espressif.EIM-CLI`), outside the workspace. The beacon runs on Windows or Linux (the user, 2026-11-07: no Linux-only version any more); Windows has only the S3,
Linux the S3 or the built-in card (`--radio wifi`, the laptop setup).
Differences from the laptop: data frames go out as non-QoS data (`esp_wifi_80211_tx` takes no QoS data; kinnay's host
sends non-QoS anyway); the S3 reports its AP's station events (a station it drops ends the stay in our log, with the
reason); the SoftAP hides its SSID with a zero-length SSID element where a Switch sends 32 zero bytes.
Bench, 2026-11-07 (`build/s3test`, no Switch): the S3 answers over USB, its hidden AP is on the air (the PC's Wi-Fi
lists BSSID <the S3's MAC> on channel 6), promiscuous receive runs alongside the AP (~200 frames/s from the
neighbours' networks, none dropped). `esp_wifi_80211_tx` sends action frames and plain data frames but **refuses any
frame with the Protected bit** (ESP_ERR_INVALID_ARG), so the desktop cannot send frames it encrypted itself. Hence
LDN mode in the firmware (`S3Ap.ldn`): linker `--wrap` of `wpa_auth_sta_associated` (ESP-IDF's AP authenticator
would send 4-way message 1 four times and then deauthenticate) so no handshake starts; on association the data key
goes into the hardware as the station's pairwise key (index 0) and the group key (index 1) and the station is
authorized (`esp_wifi_wpa_ptk_init_done_internal`); the desktop sends Ethernet frames (`S3_TX_ETH`,
`radio_send_eth`) and the S3 sends them as data from the AP, encrypted by the hardware with its own PN counter. Bench:
Ethernet broadcast sent; unicast to a station not associated refused (0x3015), as it should be. Receiving stays raw
(promiscuous, decrypted on the desktop; if the S3 hands over the Switch's frames already decrypted, ldnbeacon takes
those too and logs it once).
S3 runs with the Switch (2026-11-07, `captures/20261107-s3-run1..3/`, the recomp hosting a raid in a local room,
channel 6):
- Run 1: the Switch read the advertisement, probed by name, authenticated and associated with the S3, then sent
  nothing we saw and left after 1.07 s (reason 3; on the console "2-ALZYA-0007"). With WPA2, ESP-IDF sends
  WIFI_EVENT_AP_STACONNECTED only after the 4-way handshake, so the key was never installed, and the hardware's
  failed decryptions were dropped by the firmware. Now the key is installed from a wrap of `hostap_new_assoc_sta`
  (10 ms later, in a task), and frames flagged with a receive error are passed on (S3_RX_ERROR, counted).
- Run 2: key installed 12 ms after association, authorized; the Switch's LDN requests (5, 200 ms apart) reached the
  desktop but "did not decrypt": **with the key in the hardware, promiscuous frames come decrypted, still with the
  Protected bit, the CCMP header and the MIC**. ldnbeacon takes those (LLC/SNAP right after the CCMP header).
- Run 3: **the S3 path works end to end**: request answered, room Connect, the Switch listed with its MAC, the
  host's Pia packets go to it (re-addressed and rewritten, as unicast frames), and **our group ARP probe was answered
  (+500 ms): group frames reach the Switch now** (never on the MT7925). Then as in runs 13-15: the Switch sends only
  its gratuitous ARP, ARP replies to .1 and IPv6 noise, **no IPv4 UDP**, and leaves after 4.66 s (reason 3; on the
  console "2318-0533"). So the remaining problem is Pia, not the radio. Note: the S3 does not capture its own
  transmissions, so our frames are not in the pcap.
- Found afterwards (2026-11-07, piatest on run 15's host packet, `pia_dump` now prints the zlib header): the host's
  compressed Net message starts `48 4b` (a 4 KB window), and `pia_rewrite` recompressed with zlib's default
  (`78 9c`, 32 KB). An inflater set up for a 4 KB window rejects that header, so the Switch probably dropped every
  rewritten host message since run 15, which fits "it never answers". Now deflated with the original's window
  (level 2, so the header is `48 4b` again); piatest round trip ok. Next S3 run tests it. The Net message is
  UpdateNetworkConnectionStatus (0x11, re-sent every 500 ms until acked; kinnay's Net-Protocol): the Switch should
  answer with 0x12.
- Runs 4-6 (`captures/20261107-s3-run4..6/`, with that fix): unchanged, 2318-0533 each time (Nintendo: "Unable to
  communicate with the other console(s)": Pia's timeout), the Switch leaves 4.6-4.8 s after our response and sends
  no IPv4 UDP. ldnbeacon now logs the first two rewritten packets each way, decrypted, before and after. Run 5's
  dump: the 124 -> 108 bytes is only padding (the host's deflate stream is 65 bytes with a sync flush, ours 62: one
  16-byte pad block less); the rewritten message is right as far as we know it: host constant id from our BSSID,
  169.254.64.1 / .2 port 12345, network id 03e36a9a = CRC-32(session id[1..15]). The bridge sends the rewritten
  length (its log line prints the room size). Run 6, broadcasts as group frames (`--bcast-mode 0`): same; that run
  only the unicast ARP probe was answered. The S3 dropped nothing while the Switch was there.
  So the Switch's Pia probably does not accept the host's packets, and the one thing never checked against a real
  console is the crypto: key and nonce are what the recomp's Pia does, on a console they could come from other
  inputs (the SSID text, the server random). The decisive test is a console's own Pia packets: the Switch hosting
  with the beacon joining as a station (design item 2: the S3 as a station, no 4-way handshake, our LDN
  authentication request), then piatest on what the Switch sends.

## Switch hosts, the S3 joins as a station (2026-11-07, `ldnjoin`; the user's call: reverse the roles to see a console's own Pia)

Why: runs 4-6 left one untested suspect for "the Switch never answers the room host", the Pia crypto on a real console.
A joining Switch sends no Pia, so the only way to see a console's Pia packets with one copy of the game is to join a
Switch's raid ourselves. kinnay's LDN library (`../ref/LDN`, behaviour only) was the reference for the station side.

Firmware (station mode, `S3_JOIN` / `S3_LEAVE` / `S3_LINK`, `S3_TX_STA`; protocol version 4, hello carries the station
MAC): STA with the console's BSSID, the session id's 32 hex digits as SSID, the channel, WPA2-PSK with any passphrase,
Nintendo's element (00 22 aa 10 01 02, as the Switch's association request has it, run 7's capture) in probe and
association requests. The console does no 4-way handshake, so the firmware installs the data key itself
(`esp_wifi_set_sta_key_internal`: pairwise index 0, group index 1, both CCMP, RSC 0) and calls
`wpa_supplicant_key_neg_complete` (cancels the supplicant's timeout, auth done, data path open). Lessons, in order:
- Join run 1: done from our key_task the S3 hung (no USB traffic; the desktop's blocking write stalled ldnjoin). Now
  it runs from the supplicant's event loop (`eloop_register_timeout`, which runs in the Wi-Fi task), 10 ms later.
- Join run 2: `supplicant_sta_conn_handler` (wrapped first) is only called after a 4-way handshake, so never. ESP-IDF
  tells the supplicant nothing at association; the trigger is now the Wi-Fi library's own log line "state: assoc ->
  run" seen in `log_vprintf` (hacky, works). STA_CONNECTED comes only after the faked negotiation.
- Join runs 3-6: a panic (reset reason 4) right after STA_CONNECTED. Breadcrumbs (RTC_NOINIT, reported at boot) put it
  after our event handler; the core dump said: **stack overflow in `sys_evt`** (the default event loop task, 2304
  bytes), from ESP-IDF log lines passing through `log_vprintf` (~650 bytes of buffers). Fixed: event task stack 4096
  (sdkconfig.defaults), no logging in the STA_CONNECTED handler. Also a station receive callback that counts and frees
  (we run no network stack).
- Desktop: `ldn_auth_request` (ldnauth.c; challenge flags 0, no parameter lists, random device id, user name
  "beacon", platform 0, version and app version from the advertisement), the token **reversed** (kinnay reads the
  advertisement's token big-endian and writes it little-endian): accepted first time. `--token raw` and a flip after
  status 6 are there but were not needed.

**Join run 7 (`captures/20261107-join-run7/`, the Switch hosting a raid, link code 0531, channel 11, <the Switch's MAC>):
it works.** Associated, keys in, request answered 31 ms later with status 0, listed in the very next advertisement as
participant 1 (169.254.12.2, "beacon", platform 0; the host (its user name) platform 1 at .1). The link code is ASCII "0531" at
app data 0x5C, as expected. The Switch host then broadcast one 108-byte Pia packet to 169.254.12.255:12345 every
500 ms for as long as we stayed (106 s, 204 packets): it never kicked the silent station. The game showed no player
(expected: the S3 is an LDN station only and sent no Pia).
- **Every packet authenticates with exactly the derivation the beacon already uses** (settled on the recomp in run 14):
  session key = AES-encrypt(game key, the session id's 16 raw bytes), nonce prefix = CRC-32(session id[1..15]) XOR the
  source IPv4, both big-endian, no AAD. So the crypto was never the problem.
- The message is the same UpdateNetworkConnectionStatus (0x2C, message flags 0x31, zlib `48 4b`, 63 bytes -> 114) as
  the recomp's: sequence 4, host variable id, host constant id from the host's MAC (2244553311020000 from
  02:11:22:33:44:55, a placeholder for the Switch's MAC, the wiki's formula), network id a9464065, open 1, then the stations (host .1 and the new station
  .2, port 12345). The one differing byte per entry (at entry + 1: host 0 / station 1 here, host 1 / station 0 in the
  recomp's rewritten message) follows the constant ids' order in both (here 2244.. < d990..; in the rewritten one the
  Switch's ce05.. < our BSSID's d990..), so it is consistent, not a bug: probably the host migration ranking.
- IP / UDP as the bridge builds them: IPv4 TTL 64, no DF, IP id counting, UDP checksum filled. 802.11: non-QoS data,
  FromDS + Protected (fc 08 42), addr1 ff:ff:ff:ff:ff:ff, addr2 the host, addr3 the source: a group frame.

So for "the room hosts, a Switch joins" (the priority) the beacon provably builds the right bytes, encrypted the right
way, and the Switch still sends no Pia and leaves after ~4.6 s (2318-0533). Remaining suspects, none checked yet:
- **Delivery of the host's packets to the joining Switch.** A real host sends them as group frames; ours went as
  unicast frames carrying the IP broadcast (S3 runs 3-5, `--bcast-mode 1`, the default) or as the S3 AP's group frames
  (run 6, `--bcast-mode 0`), and the S3's group frames are not proven: the group ARP probe was answered in S3 run 3 but
  not in run 6. Nothing of ours is in any capture (the S3 does not capture its own transmissions). A second radio
  sniffing the beacon's channel (the laptop's mon0, `scripts/capture.sh`) would show what really goes out: frame type,
  key index, PN, and whether the Switch sends anything (an ack to .1) that the S3 misses.
- The S3 AP's group key index: installed at index 1 (`ldn_station_keys`), but which index the hardware puts on group
  frames it sends is unchecked.
- Smaller: kinnay picks the network's third octet in 1..127; ours has been up to 199 (runs 3, 11). The recomp host
  advertises platform 0 / "Player" and a zero server random.
Next (after a context reset, the user's call): pick one of these; the cheapest decisive one is probably a sniff of our
own transmissions with the laptop while a Switch joins the room through the S3.
