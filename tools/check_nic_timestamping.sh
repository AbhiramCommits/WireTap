#!/usr/bin/env bash
# Reports a NIC's hardware timestamping capabilities via ethtool -T.
#
# wiretap_recv enables SO_TIMESTAMPING (hardware + software); this script
# tells you what the NIC actually advertises, so you know whether the
# "hw=" counter in the shutdown report can be non-zero.
#
# usage: tools/check_nic_timestamping.sh <interface>

set -eu

if [ "$#" -ne 1 ]; then
    echo "usage: $0 <interface>" >&2
    exit 2
fi
iface="$1"

if ! command -v ethtool >/dev/null 2>&1; then
    echo "error: ethtool not found (install with: sudo apt-get install ethtool)" >&2
    exit 2
fi

echo "== ethtool -T $iface =="
output="$(ethtool -T "$iface" 2>&1)" || { echo "$output" >&2; exit 1; }
echo "$output"
echo

if printf '%s\n' "$output" | grep -q "SOF_TIMESTAMPING_RX_HARDWARE"; then
    echo "verdict: $iface supports hardware receive timestamping"
elif printf '%s\n' "$output" | grep -q "PTP Hardware Clock"; then
    echo "verdict: $iface has a PTP hardware clock (check RX capabilities above)"
else
    echo "verdict: $iface does NOT advertise hardware receive timestamping;"
    echo "         wiretap_recv will fall back to kernel software timestamps"
fi
