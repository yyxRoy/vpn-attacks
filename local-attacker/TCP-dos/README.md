# TCP Port Exhausting DoS

This directory contains the local-attacker-side code for the TCP port exhausting DoS attack described in the paper. The attacker continuously sends low-TTL TCP SYN packets across the full source-port space so that the VPN server consumes and refreshes TCP connection-tracking entries for a chosen target server.

## Requirements

- The attacker and victim must connect to the same VPN server and share the same public IP address after NAT.
- The attacker machine needs `libtins` installed.

## Usage

```bash
make
```

Update the variables in `attack-dos.sh`, then run:

```bash
sudo bash attack-dos.sh
```

While the attack is running, the victim should have difficulty establishing new TCP connections to the target `<remote_server_ip>:<remote_server_port>` through the same VPN server.
