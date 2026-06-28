# Security Advisories

This directory contains public references for CVEs assigned to vulnerabilities
described in the paper "Invisible Adversaries: A Systematic Study of Session
Manipulation Attacks on VPNs."

The advisories are intended to provide the minimum public information needed to
identify each vulnerability. They intentionally omit exploit instructions,
private vendor correspondence, and operational details that are not needed for
defensive understanding.

## TCP Session Hijacking

| CVE ID | Vendor | Affected component |
| --- | --- | --- |
| [CVE-2024-50751](CVE-2024-50751.md) | IPVanish | IPVanish VPN servers |
| [CVE-2024-50752](CVE-2024-50752.md) | Windscribe | Windscribe VPN servers |
| [CVE-2024-50753](CVE-2024-50753.md) | CyberGhost | CyberGhost VPN servers |
| [CVE-2024-50754](CVE-2024-50754.md) | PrivateVPN | PrivateVPN VPN servers |
| [CVE-2024-50755](CVE-2024-50755.md) | Private Internet Access | Private Internet Access VPN servers |
| [CVE-2024-50756](CVE-2024-50756.md) | NordVPN | NordVPN VPN servers |
| [CVE-2024-50757](CVE-2024-50757.md) | ExpressVPN | ExpressVPN VPN servers |
| [CVE-2024-50758](CVE-2024-50758.md) | Surfshark | Surfshark VPN servers |

These vulnerabilities allow an off-path malicious VPN user sharing a VPN server
with a victim to manipulate another VPN user's TCP session under affected VPN
server deployment conditions. The root causes include port preservation and
insufficient validation of TCP RST sequence numbers in the VPN server's
connection-tracking behavior.

## Port Exhaustion Denial of Service

| CVE ID | Vendor | Affected component |
| --- | --- | --- |
| [CVE-2024-50759](CVE-2024-50759.md) | PrivateVPN | PrivateVPN VPN servers |
| [CVE-2024-50760](CVE-2024-50760.md) | CyberGhost | CyberGhost VPN servers |
| [CVE-2024-50761](CVE-2024-50761.md) | IPVanish | IPVanish VPN servers |
| [CVE-2024-50762](CVE-2024-50762.md) | Windscribe | Windscribe VPN servers |
| [CVE-2024-50763](CVE-2024-50763.md) | ExpressVPN | ExpressVPN VPN servers |
| [CVE-2024-50764](CVE-2024-50764.md) | Private Internet Access | Private Internet Access VPN servers |

These vulnerabilities allow a malicious VPN user sharing a VPN server with other
users to consume the VPN server's public-facing source-port resources for a
chosen remote service, preventing other VPN users from establishing sessions to
that service.

## Discoverers

Yuxiang Yang, Ke Xu, Ao Wang, Xuewei Feng, and Qi Li.

## References

- [Repository README](../README.md)
- [Paper PDF](../INFOCOM26-vpn-attack.pdf)
