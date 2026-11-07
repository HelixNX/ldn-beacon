#!/bin/sh
# Captures 802.11 traffic on channels 1, 6 and 11 (Switch local play) into ~/captures, for analysis elsewhere.
#   sudo sh capture.sh [interface] [seconds per channel] [vif]   (defaults: the first Wi-Fi interface, 45)
# "vif" captures on a separate monitor interface (mon0) added next to the Wi-Fi one, which is taken down with its
# addresses removed: some drivers (mt76, e.g. the MT7925) deliver nothing when the interface itself is switched to
# monitor mode (2026-11-06: only the laptop's own outgoing packets).
# Host local play on the Switch (e.g. a local Union Circle or raid lobby) for the whole run, close to the laptop.
# Needs iw and tcpdump: sudo pacman -Sy --needed iw tcpdump libpcap (libpcap too: a newer tcpdump needs it).
# Writes ~/captures/ch1.pcap, ch6.pcap, ch11.pcap, card.txt. NetworkManager / wpa_supplicant are stopped for the
# capture (as airmon-ng check kill does) and started again at the end, also on Ctrl+C.
set -u
[ "$(id -u)" = 0 ] || { echo "run it with sudo: sudo sh $0"; exit 1; }
IF=${1:-}
[ -n "$IF" ] || IF=$(iw dev | awk '$1 == "Interface" { print $2; exit }')
[ -n "$IF" ] || { echo "no Wi-Fi interface found (iw dev)"; exit 1; }
SECS=${2:-45}
VIF=${3:-}
USER_NAME=${SUDO_USER:-root}
HOME_DIR=$(getent passwd "$USER_NAME" | cut -d: -f6)
OUT="$HOME_DIR/captures"
mkdir -p "$OUT"
tcpdump --version > /dev/null 2>&1 || {
    echo "tcpdump does not start:"; tcpdump --version
    echo "try: sudo pacman -S libpcap"; exit 1; }
NINTENDO='wlan type mgt subtype action and wlan[24] = 127 and wlan[25:2] = 0x0022 and wlan[27] = 0xaa'

echo "interface $IF, $SECS s per channel, into $OUT"
{ iw dev "$IF" info; iw phy "$(iw dev "$IF" info | awk '$1 == "wiphy" { print "phy" $2 }')" info
  lspci -k 2>/dev/null | grep -iA3 'network\|wireless'; } > "$OUT/card.txt" 2>&1

PHY=$(iw dev "$IF" info | awk '$1 == "wiphy" { print "phy" $2 }')
CAP=$IF
STOPPED=
[ -n "$VIF" ] && CAP=mon0
restore() {
    [ -n "$VIF" ] && iw dev mon0 del 2> /dev/null
    ip link set "$IF" down
    iw dev "$IF" set type managed
    ip link set "$IF" up
    for S in $STOPPED; do systemctl start "$S"; done
}
trap 'echo; echo "stopped: giving Wi-Fi back"; restore; exit 1' INT TERM

# what airmon-ng's "check kill" does: NetworkManager and wpa_supplicant keep scanning and reconfiguring the card,
# which can stop a monitor interface from receiving anything; they are started again at the end
STOPPED=
for S in NetworkManager wpa_supplicant iwd; do
    systemctl is-active --quiet "$S" 2> /dev/null && systemctl stop "$S" && STOPPED="$STOPPED $S"
done
pkill -x wpa_supplicant 2> /dev/null
[ -n "$STOPPED" ] && echo "stopped for the capture:$STOPPED"
command -v rfkill > /dev/null && rfkill unblock wifi
ip addr flush dev "$IF"                 # no addresses: the laptop's own traffic stays out of the capture
if [ -n "$VIF" ]; then
    ip link set "$IF" down
    iw dev mon0 del 2> /dev/null
    iw phy "$PHY" interface add mon0 type monitor flags otherbss control ||
        iw phy "$PHY" interface add mon0 type monitor || { echo "could not add a monitor interface"; restore; exit 1; }
fi
for CH in 1 6 11; do
    # the channel is set with the interface down and up again each time: some drivers stop receiving otherwise
    ip link set "$CAP" down
    [ -n "$VIF" ] || iw dev "$IF" set type monitor || { echo "monitor mode refused"; restore; exit 1; }
    ip link set "$CAP" up
    iw dev "$CAP" set channel "$CH" || { echo "channel $CH refused"; continue; }
    echo "--- channel $CH ($CAP: $(iw dev "$CAP" info | awk '$1 == "type" { print $2 }'), $SECS s)"
    timeout "$SECS" tcpdump -i "$CAP" -w "$OUT/ch$CH.pcap" 2> "$OUT/ch$CH.err"
    ALL=$(tcpdump -r "$OUT/ch$CH.pcap" 2> /dev/null | wc -l)
    NN=$(tcpdump -r "$OUT/ch$CH.pcap" "$NINTENDO" 2> /dev/null | wc -l)
    echo "    $ALL frames, $NN Nintendo local-play frames"
    [ "$ALL" -gt 0 ] || sed 's/^/    tcpdump: /' "$OUT/ch$CH.err"
done
restore
chown -R "$USER_NAME" "$OUT"
ls -l "$OUT"
echo "done: copy $OUT to the USB stick"
