# IPsecTrace — AWS DUAL-INSTANCE DEMONSTRATION ARCHITECTURE & SETUP GUIDE

This document details the exact, verified cloud infrastructure design for running the IPsecTrace live prototype in an Amazon Web Services (AWS) environment.

---

## 1. AWS Architecture Overview

```text
┌────────────────────────────────────────────────────────────────────────────────────────┐
│                                   AWS VPC (10.0.0.0/16)                                 │
│                                                                                        │
│   ┌─────────────────────────────────────┐    ┌─────────────────────────────────────┐   │
│   │       EC2-A: TRAFFIC GENERATOR       │    │        EC2-B: IPsec GATEWAY         │   │
│   │         Subnet: 10.0.1.0/24         │    │         Subnet: 10.0.2.0/24         │   │
│   │         Private IP: 10.0.1.10       │    │         Private IP: 10.0.2.10       │   │
│   │                                     │    │                                     │   │
│   │  • Traffic Simulator (Python/curl)  │    │  • strongSwan 5.9+ (Linux XFRM)     │   │
│   │  • Workloads: Web, ICMP, SSH, Bulk  │    │  • ESP (Proto 50) + IKE (UDP 500)   │   │
│   └──────────────────┬──────────────────┘    └──────────────────▲──────────────────┘   │
│                      │                                          │                      │
│                      │        IPsec Encrypted Tunnel (ESP)       │                      │
│                      └──────────────────────────────────────────┘                      │
│                                                                                        │
│                                           │ (Passive TAP / tcpdump)                    │
│                                           ▼                                            │
│                              ┌──────────────────────────┐                              │
│                              │   IPsecTrace ANALYZER  │                              │
│                              │  • Scapy Ingestion       │                              │
│                              │  • Model C Hybrid AI     │                              │
│                              │  • Deterministic Rules   │                              │
│                              └──────────────────────────┘                              │
└────────────────────────────────────────────────────────────────────────────────────────┘
```

---

## 2. Infrastructure Requirements & Specifications

- **VPC Configuration**: Custom VPC `10.0.0.0/16` with DNS hostnames enabled.
- **Subnets**:
  - `Subnet-A`: `10.0.1.0/24` (Availability Zone A)
  - `Subnet-B`: `10.0.2.0/24` (Availability Zone B)
- **EC2 Instance Types**:
  - `EC2-A` (Generator): `t3.medium` (2 vCPU, 4 GiB RAM, Ubuntu 24.04 LTS)
  - `EC2-B` (Gateway / Analyzer): `c6i.large` (2 vCPU, 4 GiB RAM, Ubuntu 24.04 LTS)
- **Security Group (Strict Minimal Ingress)**:
  - UDP `500` (IKE key exchange) — Source: `10.0.0.0/16`
  - UDP `4500` (NAT-Traversal) — Source: `10.0.0.0/16`
  - IP Protocol `50` (ESP) — Source: `10.0.0.0/16`
  - TCP `22` (SSH management) — Source: `Your_Admin_IP/32` (Never `0.0.0.0/0`)

---

## 3. Step-by-Step Gateway Provisioning (EC2-B)

### Step 3.1: Install strongSwan and Kernel IPsec Modules
```bash
sudo apt-get update && sudo apt-get install -y strongswan strongswan-pki libcharon-extra-plugins tcpdump python3-pip
```

### Step 3.2: Configure IPsec Secret & Connection (`/etc/ipsec.conf`)
```ini
config setup
    charondebug="ike 2, knl 2, cfg 2"

conn aws-demo-tunnel
    authby=secret
    auto=start
    type=tunnel
    left=10.0.2.10
    leftsubnet=10.0.2.0/24
    right=10.0.1.10
    rightsubnet=10.0.1.0/24
    ike=aes256-sha256-modp2048!
    esp=aes256-sha256!
    keyexchange=ikev2
```

Add PSK to `/etc/ipsec.secrets`:
```ini
10.0.2.10 10.0.1.10 : PSK "SentryIpsecDemoSecret2026SecureKey"
```

Restart IPsec daemon:
```bash
sudo ipsec restart
sudo ipsec statusall
```

---

## 4. Traffic Generation on EC2-A

On `EC2-A`, initiate traffic streams across the tunnel:

```bash
# 1. ICMP Diagnostic Traffic
ping -c 100 10.0.2.10

# 2. Bulk File Transfer (Encrypted)
dd if=/dev/urandom of=bulk_10mb.bin bs=1M count=10
scp bulk_10mb.bin ubuntu@10.0.2.10:/tmp/

# 3. Web HTTPS Simulation
curl -k https://10.0.2.10:8443/
```

---

## 5. Capturing and Running IPsecTrace

On `EC2-B`, capture the live encrypted interface and execute IPsecTrace:

```bash
# 1. Capture 30 seconds of live encrypted ESP traffic
sudo tcpdump -i eth0 esp or udp port 500 or udp port 4500 -w /tmp/aws_live_demo.pcap -c 500

# 2. Execute IPsecTrace Analyzer
python3 demo/run_demo.py --pcap /tmp/aws_live_demo.pcap
```

---

## 6. Cost Control & Resource Teardown

To avoid incurring AWS compute charges:
1. Always shut down instances after recording: `./demo/aws/stop.sh`
2. Terminate instances, security groups, and VPC when testing is concluded: `./demo/aws/cleanup.sh`
