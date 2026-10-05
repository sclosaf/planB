#!/bin/bash

set -e

BASE_DIR="$HOME/Downloads/temp"
ATTACK_DIR="$BASE_DIR/Edge-IIoTset-dataset/Attack-traffic"

declare -A ATTACKS=(
    [1]="Backdoor-attack"
    [2]="DDoS-HTTP-Flood-attacks"
    [3]="DDoS-ICMP-Flood-attacks"
    [4]="DDoS-TCP-SYN-Flood-attacks"
    [5]="DDoS-UDP-Flood-attacks"
    [6]="MITM-attack"
    [7]="OS-Fingerprinting-attack"
    [8]="Password-attacks"
    [9]="Port-Scanning-attack"
    [10]="Ransomware-attack"
    [11]="SQL-injection-attack"
    [12]="Uploading-attack"
    [13]="Vulnerability-scanner-attack"
    [14]="XSS-attacks"
)

usage() {
    echo "Usage: $0 -n <number>"
    echo
    echo "Available numbers:"
    for key in $(echo "${!ATTACKS[@]}" | tr ' ' '\n' | sort -n); do
        echo "  $key) ${ATTACKS[$key]}"
    done
    exit 1
}

while getopts "n:h" opt; do
    case $opt in
        n) NUM="$OPTARG" ;;
        h) usage ;;
        *) usage ;;
    esac
done

if [ -z "$NUM" ]; then
    echo "Error: -n parameter is required"
    echo
    usage
fi

if [ -z "${ATTACKS[$NUM]}" ]; then
    echo "Error: invalid number '$NUM'"
    echo
    usage
fi

NAME="${ATTACKS[$NUM]}"
PCAP="$ATTACK_DIR/$NAME.pcap"
CSV="$ATTACK_DIR/$NAME.csv"

if [ ! -f "$PCAP" ]; then
    echo "Error: PCAP not found: $PCAP"
    exit 1
fi

if [ ! -f "$CSV" ]; then
    echo "Error: CSV not found: $CSV"
    exit 1
fi

echo "=== Selected attack ==="
echo "Number : $NUM"
echo "Name   : $NAME"
echo "PCAP   : $PCAP"
echo "CSV    : $CSV"
echo

source "$BASE_DIR/.venv/bin/activate"

sudo rm -rf "$BASE_DIR/test"
mkdir -p "$BASE_DIR/test"
sudo chown -R "suricata:suricata" "$BASE_DIR/test"

sudo suricata \
    -r "$PCAP" \
    -S "$BASE_DIR/custom.rules" \
    -l "$BASE_DIR/test" \
    -k none

python3 "$BASE_DIR/evaluate.py" \
    -e "$BASE_DIR/test/eve.json" \
    -c "$CSV" \
    -p "$PCAP" \
    -r
