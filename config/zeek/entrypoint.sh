#!/bin/bash
set -e

echo "================================================================"
echo "  SIH26145 Zeek 7.x Passive Sensor Startup                     "
echo "  Mode: Passive Deep Packet Inspection with JA4 Fingerprinting  "
echo "================================================================"

LOG_DIR="${ZEEK_LOG_DIR:-/logs}"
mkdir -p "$LOG_DIR"
cd "$LOG_DIR"

if [ -n "$ZEEK_PCAP_FILE" ] && [ -f "$ZEEK_PCAP_FILE" ]; then
    echo "[+] Running Zeek in PCAP Analysis Mode on: $ZEEK_PCAP_FILE"
    exec zeek -C -j -r "$ZEEK_PCAP_FILE" local.zeek
elif [ -n "$ZEEK_INTERFACE" ]; then
    echo "[+] Running Zeek in Live Capture Mode on Interface: $ZEEK_INTERFACE"
    exec zeek -C -j -i "$ZEEK_INTERFACE" local.zeek
else
    echo "[+] Defaulting to Live Capture Mode on eth0"
    exec zeek -C -j -i eth0 local.zeek
fi
