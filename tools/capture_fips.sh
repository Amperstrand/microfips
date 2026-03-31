#!/bin/bash
# Capture FIPS UDP traffic on port 2121
# Usage: ./capture_fips.sh [output.pcap] [max-packets]
# Requires: sudo (for raw packet capture)

OUTPUT="${1:-fips_capture.pcap}"
COUNT="${2:-100}"
sudo tcpdump -i any 'udp port 2121' -w "$OUTPUT" -c "$COUNT" -v
