#!/bin/bash

rules=(
    "botcc.portgrouped.rules"
    "botcc.rules"
    "ciarmy.rules"
    "compromised.rules"
    "drop.rules"
    "dshield.rules"
    "emerging-activex.rules"
    "emerging-adware_pup.rules"
    "emerging-attack_response.rules"
    "emerging-chat.rules"
    "emerging-coinminer.rules"
    "emerging-current_events.rules"
    "emerging-deleted.rules"
    "emerging-dns.rules"
    "emerging-dos.rules"
    "emerging-dyn_dns.rules"
    "emerging-exploit.rules"
    "emerging-exploit_kit.rules"
    "emerging-file_sharing.rules"
    "emerging-ftp.rules"
    "emerging-games.rules"
    "emerging-hunting.rules"
    "emerging-icmp.rules"
    "emerging-imap.rules"
    "emerging-inappropriate.rules"
    "emerging-info.rules"
    "emerging-ja3.rules"
    "emerging-malware.rules"
    "emerging-misc.rules"
    "emerging-mobile_malware.rules"
    "emerging-netbios.rules"
    "emerging-p2p.rules"
    "emerging-phishing.rules"
    "emerging-pop3.rules"
    "emerging-remote_access.rules"
    "emerging-retired.rules"
    "emerging-rpc.rules"
    "emerging-scada.rules"
    "emerging-scan.rules"
    "emerging-shellcode.rules"
    "emerging-smtp.rules"
    "emerging-snmp.rules"
    "emerging-sql.rules"
    "emerging-ta_abused_services.rules"
    "emerging-telnet.rules"
    "emerging-tftp.rules"
    "emerging-user_agents.rules"
    "emerging-voip.rules"
    "emerging-web_client.rules"
    "emerging-web_server.rules"
    "emerging-web_specific_apps.rules"
    "emerging-worm.rules"
    "threatview_CS_c2.rules"
    "tor.rules"
)

urls=(
    "https://www.kaggle.com/api/v1/datasets/download/mohamedamineferrag/edgeiiotset-cyber-security-dataset-of-iot-iiot"

    "https://archive.ics.uci.edu/static/public/516/kitsune+network+attack+dataset.zip"

    "https://archive.ics.uci.edu/static/public/516/kitsune+network+attack+dataset.zip"

    "https://feodotracker.abuse.ch/downloads/feodotracker.tar.gz"
    "https://feodotracker.abuse.ch/downloads/feodotracker_aggressive.tar.gz"

    "https://rules.emergingthreats.net/open/suricata-7.0.3/emerging-all.rules.tar.gz"
    "https://rules.emergingthreats.net/open/suricata-7.0.3/emerging.rules.tar.gz"

    "https://rules.emergingthreats.net/open/suricata-7.0.3/emerging-all.rules.zip"
    "https://rules.emergingthreats.net/open/suricata-7.0.3/emerging.rules.zip"

    "https://rules.emergingthreats.net/open/suricata-7.0.3/SID-Descriptions-ETOpen.json.gz"
)

echo "WARNING:"
echo "This script will perform a large number of downloads."
echo "The files will be saved to:"
echo "  $(pwd)/download"
echo
echo "Several GB of data may be downloaded."
echo

read -r -p "Do you want to continue? [y/N] " answer

case "$answer" in
    [yY]|[yY][eE][sS])
        echo
        echo "Starting downloads..."
        echo
        ;;
    *)
        echo
        echo "Operation cancelled."
        exit 0
        ;;
esac

rm -rf download
mkdir -p download
mkdir -p download/rules

total=$(( ${#urls[@]} + ${#rules[@]} ))
count=0

for url in "${urls[@]}"; do
    count=$((count + 1))

    echo
    echo "[$count/$total] Downloading: $url"

    wget \
        -q \
        --show-progress \
        -c \
        -P download \
        "$url" || echo "FAILED: $url"
done

for rule in "${rules[@]}"; do
    count=$((count + 1))

    echo
    echo "[$count/$total] Downloading rule: $rule"

    wget \
        -q \
        --show-progress \
        -c \
        -P download/rules \
        "https://rules.emergingthreats.net/open/suricata-7.0.3/rules/$rule" \
        || echo "FAILED: $rule"
done

echo
echo "If you need other PCAPs, look into:"
echo "https://gitlab.com/wireshark/wireshark/-/wikis/SampleCaptures"
echo "https://docs.suricata.io/en/suricata-8.0.4/public-data-sets.html"
echo
