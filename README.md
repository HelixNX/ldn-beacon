# ldn-beacon

Brings a real Nintendo Switch's local wireless play (LDN) into an online multiplayer room: the kind of room Citra,
yuzu and Eden use, and the one the [ns-port](https://github.com/HelixNX/ns-port) recompilations join. A small radio
next to the Switch hosts the room's network on the air as a console would; the beacon joins the room as one member
and passes everything between the two. To the Switch, the room's host looks like another console nearby. To the room,
the Switch is one more member.

Built for Pokémon Scarlet / Violet's Tera raids and Union Circle: a real Switch joins a raid hosted by the Violet
recompilation in a room, with three complete raids in a row and no drops so far.

## What works

| | |
|---|---|
| The room hosts, a real Switch joins | **works** (Tera raids, Union Circle) |
| The Switch hosts, the room joins | not yet (`ldnjoin` is the first half) |
| Several Switches at once | not yet |
| Games | Pokémon Scarlet / Violet (each game has its own LDN passphrase and Pia key) |

## What you need

- **An ESP32-S3** board on USB, flashed with the firmware in `s3/`. It is the radio, on Windows or Linux. (An older
  route through a Linux machine's own Wi-Fi card, with monitor mode and `hostapd`, is still in the code as
  `--radio wifi` but was left unfinished: the Switch associates but never completes the join.)
- **Your own Switch files.** The beacon contains no keys or data from Nintendo. At start-up it reads them from your
  own dumps and stops if they are missing:
  - `prod.keys` (and `title.keys` if your NSPs have no tickets), dumped from your console;
  - your console's **firmware** (its NCAs, e.g. `firmware/22.5.0/*.nca`). The LDN keys are found in its `ldn` and
    `es` system modules;
  - the **game's NSPs** (base, and update if you have it). Its LDN passphrase and Pia key are found in its code.
- **A room** for the beacon to join, e.g. ns-port's `room_server`, and someone hosting in it (the Violet recompilation;
  other hosts are untested).

## Build

**Windows:** Visual Studio with the "C++ Clang tools" component, CMake and Ninja; `vcpkg install enet zstd zlib`
(set `VCPKG_ROOT`), then

```
build.bat
```

**Linux:**

```sh
# Arch: sudo pacman -S --needed base-devel cmake enet zstd zlib
cmake -B build && cmake --build build
```

**The S3's firmware** (ESP-IDF 5.3 or newer, e.g. 5.5 from Espressif's installer), from `s3/`:

```sh
idf.py build
idf.py -p <port> flash
```

## Use

1. Start a room (or use one you can reach), e.g. `room_server --port 24872`.
2. Start the beacon with the S3 plugged in (it finds the board by itself):

   ```
   build/ldnbeacon --room 127.0.0.1:24872
   ```

3. Join the same room with the game, e.g. the Violet recompilation, and host a raid with a link code.
4. On the Switch, search for the raid by its link code. It finds the network, joins, and plays.

Ctrl+C stops the beacon.

In the ns-port workspace, `.\start.ps1 room -Beacon` runs the room and the beacon together in one console, keeping
their logs and a capture in `captures/<time>/`.

### Where the beacon looks for your files

`--files <dir>` (repeat it for several folders) names where your keys, NSPs and firmware are. Each folder is searched
along with its subfolders and its `firmware/` folder, so a game's package folder works as is. `~/.switch/` (or
`%USERPROFILE%\.switch\`) is also checked for the keys. Without `--files`, the beacon looks in `.`, `../keys`,
`../firmware` and `../pkmn-violet/rom`, the ns-port workspace layout. Loading takes a few seconds, since it scans the
game's code.

### Options

| Option | |
|---|---|
| `--room host[:port]` | the room to join (port 24872 by default); required |
| `--radio s3[:port]` | the S3's serial port, if it isn't found by itself (`--radio wifi[:iface]`: the unfinished Linux card route) |
| `--channel 1\|6\|11` | the Wi-Fi channel (6 by default) |
| `--nick name`, `--password pw` | the beacon's name in the room, and the room's password |
| `--files dir` | where your keys, firmware and NSPs are (above) |
| `--game scarlet_violet` | which game's keys to load (the only one so far) |
| `--pcap file` | save every frame heard, for Wireshark |
| `--log 0-2` | how much to log (2: every packet) |

### Other tools

| Tool | |
|---|---|
| `advdump <pcap>` | decrypts and prints the LDN advertisements in a capture |
| `ldnjoin` | the S3 joins a real console's network as a station and logs what the host sends |
| `roomtest --scan` | asks a room for its networks and prints them |
| `s3test [--ap] [--tx]` | checks the S3 without a Switch |
| `frametest`, `ccmptest`, `authtest`, `piatest`, `bridgetest`, `s3prototest` | self-tests and capture checks for each layer |

## How it works

A Switch's local play is plain 802.11 with a few twists. The host sends a beacon with a hidden SSID and an encrypted
**advertisement** (a vendor action frame) every 100 ms. Joining consoles associate with WPA2-style CCMP encryption,
whose key is derived from the network's data, then authenticate with an LDN challenge. After that the game's own
traffic (Pia, over UDP) flows between 169.254.x.y addresses.

The beacon turns the room host's network into all of that on the air: beacons, advertisements, the authentication
answer, CCMP in software. It bridges the Switch's UDP to the room, rewriting addresses and the Pia session details
that name them. The ESP32-S3 does the radio work that has to be fast (ACKs, association, sending and receiving frames),
and the desktop does the rest over USB.

The protocol, every test run, and what was learned on the way are in [`NOTES.md`](NOTES.md).

## Credits

- **[kinnay](https://github.com/kinnay)**, whose [NintendoClients wiki](https://github.com/kinnay/NintendoClients/wiki)
  documents the LDN protocol, Pia and Nintendo's key derivations, and whose
  [LDN](https://github.com/kinnay/LDN) library showed how hosting and joining work on a PC. Both were read for
  behaviour; the code here is our own.
- The **Citra, yuzu and Eden** projects, whose multiplayer room protocol (`network_version` 1) the beacon speaks, so it
  can meet their players and ours in one room. **Ryujinx**'s LDN work was also consulted for behaviour.
- [Espressif's ESP-IDF](https://github.com/espressif/esp-idf) for the S3's firmware; [ENet](http://enet.bespin.org/),
  [zstd](https://github.com/facebook/zstd) and [zlib](https://zlib.net/) for the room link and Pia's compressed messages.

## Legal

Not affiliated with or endorsed by Nintendo. This repository contains no Nintendo code, keys, firmware or game data:
the beacon only runs with files you dump from your own console and games. Use it with games you own.
