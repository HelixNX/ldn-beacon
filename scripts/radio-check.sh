#!/bin/sh
# First radio test for the beacon, on the laptop's live USB (CachyOS). Needs root (sudo), iw and tcpdump
# (sudo pacman -S --needed iw tcpdump). Prints what the Wi-Fi card can do, then captures on channels 1, 6 and 11
# (20 s each by default) while a Switch hosts local play nearby; Nintendo's action frames (OUI 00:22:AA) are counted.
#   sudo sh radio-check.sh [interface] [seconds per channel]
# Output: radio-check/ next to where it runs: iw-list.txt, lspci.txt, ch1.pcap, ch6.pcap, ch11.pcap. NetworkManager is
# told to leave the interface alone during the capture and given it back at the end.
set -u
IF=${1:-$(iw dev | awk '$1 == "Interface" { print $2; exit }')}
SECS=${2:-20}
OUT=radio-check
[ -n "$IF" ] || { echo "no Wi-Fi interface found (iw dev)"; exit 1; }
mkdir -p "$OUT"
echo "interface: $IF"
lspci -k 2>/dev/null | grep -iA3 'network\|wireless' > "$OUT/lspci.txt"
cat "$OUT/lspci.txt"
PHY=$(iw dev "$IF" info | awk '$1 == "wiphy" { print "phy" $2 }')
iw phy "$PHY" info > "$OUT/iw-list.txt"
echo "--- supported interface modes"
sed -n '/Supported interface modes/,/Band 1/p' "$OUT/iw-list.txt" | grep '\*'
echo "--- valid interface combinations"
sed -n '/valid interface combinations/,/^[[:space:]]*$/p' "$OUT/iw-list.txt"
echo "--- frames it can send from an AP interface (look for 0x00d0: action)"
sed -n '/Supported TX frame types/,/Supported RX frame types/p' "$OUT/iw-list.txt" | grep -A1 -i ' AP:'

command -v tcpdump >/dev/null || { echo "tcpdump is not installed (sudo pacman -Sy --needed tcpdump)"; exit 1; }
command -v rfkill >/dev/null && rfkill unblock wifi
command -v nmcli >/dev/null && nmcli device set "$IF" managed no
ip link set "$IF" down
iw dev "$IF" set type monitor || { echo "monitor mode refused"; exit 1; }
ip link set "$IF" up || { echo "the interface would not come up in monitor mode"; exit 1; }
echo "--- monitor mode:"
iw dev "$IF" info | grep -E 'type|channel'
for CH in 1 6 11; do
    iw dev "$IF" set channel "$CH" || { echo "channel $CH refused"; continue; }
    echo "--- channel $CH, $SECS s: host local play on the Switch now"
    START=$(date +%s)
    timeout "$SECS" tcpdump -i "$IF" -w "$OUT/ch$CH.pcap" 2> "$OUT/ch$CH.err"
    RC=$?
    TOOK=$(( $(date +%s) - START ))
    if [ "$TOOK" -lt $((SECS - 2)) ]; then
        echo "    tcpdump stopped after $TOOK s (exit $RC):"
        sed 's/^/      /' "$OUT/ch$CH.err"
    fi
    ALL=$(tcpdump -r "$OUT/ch$CH.pcap" 2>/dev/null | wc -l)
    N=$(tcpdump -r "$OUT/ch$CH.pcap" -e 2>/dev/null | grep -ci 'action')
    NN=$(tcpdump -r "$OUT/ch$CH.pcap" -x 2>/dev/null | grep -ci '0022 aa\|0022aa\|00 22 aa')
    echo "    frames: $ALL, action frames: $N, with Nintendo's OUI (rough count): $NN"
done
ip link set "$IF" down
iw dev "$IF" set type managed
ip link set "$IF" up
command -v nmcli >/dev/null && nmcli device set "$IF" managed yes
echo "done: bring back the $OUT folder"
