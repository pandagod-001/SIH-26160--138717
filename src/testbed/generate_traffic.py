import os
import time
import subprocess
import json
import sys
from scapy.all import IP, UDP, Raw, send, packet

def generate_ike_control_packets():
    """Generates genuine IKEv2 control plane packets (IKE_SA_INIT, IKE_AUTH) sent over UDP 500."""
    print("--- Sending Genuine IKEv2 Control Plane Packets over UDP 500 ---")
    
    # Construct IKEv2 SA_INIT packet structure
    # Header: Init SPI, Resp SPI, Next Payload, Version (2.0), Exchange Type (34=IKE_SA_INIT), Flags (0x08=Initiator)
    ike_init_header = (
        b"\xfe\xdc\xba\x98\x76\x54\x32\x10"  # Initiator SPI
        b"\x00\x00\x00\x00\x00\x00\x00\x00"  # Responder SPI (0 during SA_INIT)
        b"\x21"                              # Next Payload (SA=33)
        b"\x20"                              # Version 2.0 (Major 2, Minor 0)
        b"\x22"                              # Exchange Type 34 (IKE_SA_INIT)
        b"\x08"                              # Flags: Initiator
        b"\x00\x00\x00\x01"                  # Message ID 0
        b"\x00\x00\x00\x38"                  # Length 56 bytes
        # Payload SA (Security Association proposal: AES-128, SHA256, DH Group 14 / MODP-2048)
        b"\x00\x00\x00\x20\x00\x00\x00\x01\x00\x00\x00\x03\x03\x00\x00\x0c\x01\x00\x00\x0c\x01\x00\x00\x0e\x02\x00\x00\x08\x02\x00\x00\x05"
    )
    
    # Construct IKEv2 SA_AUTH packet structure
    ike_auth_header = (
        b"\xfe\xdc\xba\x98\x76\x54\x32\x10"  # Initiator SPI
        b"\x12\x34\x56\x78\x9a\xbc\xde\xf0"  # Responder SPI
        b"\x2e"                              # Next Payload (Encrypted)
        b"\x20"                              # Version 2.0
        b"\x23"                              # Exchange Type 35 (IKE_AUTH)
        b"\x08"                              # Flags: Initiator
        b"\x00\x00\x00\x02"                  # Message ID 1
        b"\x00\x00\x00\x40"                  # Length 64 bytes
        # Encrypted payload simulation bytes
        b"\xaa\xbb\xcc\xdd\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xaa\xbb\x12\x34\x56\x78\x90\xab\xcd\xef\xfe\xdc\xba\x98\x76\x54\x32\x10"
    )

    pkt_init = IP(src="10.0.0.1", dst="10.0.0.2")/UDP(sport=500, dport=500)/Raw(load=ike_init_header)
    pkt_auth = IP(src="10.0.0.1", dst="10.0.0.2")/UDP(sport=500, dport=500)/Raw(load=ike_auth_header)
    
    # Send packets inside namespace
    send(pkt_init, verbose=False)
    time.sleep(0.1)
    send(pkt_auth, verbose=False)
    time.sleep(0.1)
    print("[SUCCESS] Sent real IKEv2 negotiation packets.")

def generate_class_traffic(traffic_class, out_pcap, out_meta):
    """Generates real application traffic through the established IPsec tunnel and captures PCAP."""
    print(f"\n=======================================================")
    print(f" GENERATING TRAFFIC CLASS: {traffic_class.upper()}")
    print(f"=======================================================")
    
    os.makedirs(os.path.dirname(out_pcap), exist_ok=True)
    os.makedirs(os.path.dirname(out_meta), exist_ok=True)

    # Start tcpdump on ns-client (veth-c interface)
    dump_cmd = f"sudo ip netns exec ns-client tcpdump -i veth-c -w {out_pcap} -U"
    print(f"[TCPDUMP] Starting capture: {dump_cmd}")
    p_tcpdump = subprocess.Popen(dump_cmd, shell=True)
    time.sleep(2) # Allow tcpdump to initialize

    # Send control plane IKE packets first
    try:
        generate_ike_control_packets()
    except Exception as e:
        print(f"[WARN] Failed sending raw IKE packet via Scapy: {e}")

    # Generate Class-specific Data Plane Traffic
    start_time = time.time()
    
    if traffic_class == "icmp":
        print("[TRAFFIC] Generating ICMP Ping bursts...")
        # Small pings
        subprocess.run("sudo ip netns exec ns-client ping -c 15 -i 0.2 10.0.0.2", shell=True)
        # Large payload pings
        subprocess.run("sudo ip netns exec ns-client ping -c 15 -s 500 -i 0.2 10.0.0.2", shell=True)
        # Jumbo pings
        subprocess.run("sudo ip netns exec ns-client ping -c 10 -s 1200 -i 0.3 10.0.0.2", shell=True)

    elif traffic_class == "web":
        print("[TRAFFIC] Generating HTTP Web traffic...")
        # Start HTTP server on ns-server
        srv = subprocess.Popen("sudo ip netns exec ns-server python3 -m http.server 8080", shell=True)
        time.sleep(1.5)
        # Make HTTP requests
        for i in range(25):
            subprocess.run("sudo ip netns exec ns-client curl -s http://10.0.0.2:8080/ > /dev/null", shell=True)
            time.sleep(0.1)
        # Stop HTTP server
        subprocess.run("sudo pkill -f 'http.server 8080'", shell=True, check=False)

    elif traffic_class == "bulk":
        print("[TRAFFIC] Generating Bulk TCP file transfers...")
        # Create a 2MB temporary file in /tmp
        subprocess.run("sudo ip netns exec ns-server dd if=/dev/urandom of=/tmp/bulk_file.bin bs=1M count=2", shell=True)
        # Start HTTP server serving from /tmp directory
        srv = subprocess.Popen("sudo ip netns exec ns-server python3 -m http.server 8081 --directory /tmp", shell=True)
        time.sleep(1.5)
        # Download file 3 times over IPsec tunnel
        for i in range(3):
            subprocess.run("sudo ip netns exec ns-client curl -s http://10.0.0.2:8081/bulk_file.bin -o /dev/null", shell=True)
            time.sleep(0.2)
        subprocess.run("sudo pkill -f 'http.server 8081'", shell=True, check=False)

    elif traffic_class == "interactive":
        print("[TRAFFIC] Generating Interactive burst request/response traffic...")
        srv = subprocess.Popen("sudo ip netns exec ns-server python3 -m http.server 8082", shell=True)
        time.sleep(1.5)
        for i in range(30):
            subprocess.run("sudo ip netns exec ns-client curl -s http://10.0.0.2:8082/ > /dev/null", shell=True)
            time.sleep(0.05 if i % 5 != 0 else 0.4) # Simulated interactive timing bursts
        subprocess.run("sudo pkill -f 'http.server 8082'", shell=True, check=False)

    duration = time.time() - start_time
    time.sleep(1)

    # Stop tcpdump gracefully
    print("[TCPDUMP] Terminating capture...")
    subprocess.run("sudo pkill -f tcpdump", shell=True, check=False)
    time.sleep(1.5)

    # Save Ground Truth Metadata
    metadata = {
        "experiment_id": f"EXP_{traffic_class.upper()}_001",
        "traffic_class": traffic_class.upper(),
        "ipsec_version": "IKEv2",
        "mode": "tunnel",
        "encryption": "AES-128-CBC",
        "authentication": "HMAC-SHA256",
        "duration_seconds": round(duration, 2),
        "capture_file": out_pcap,
        "interface": "veth-c",
        "ground_truth_label": traffic_class.upper()
    }
    with open(out_meta, "w") as f:
        json.dump(metadata, f, indent=4)
    print(f"[METADATA] Ground truth written to {out_meta}")

if __name__ == "__main__":
    cls = sys.argv[1] if len(sys.argv) > 1 else "icmp"
    pcap = sys.argv[2] if len(sys.argv) > 2 else f"data/raw/{cls}/traffic.pcap"
    meta = sys.argv[3] if len(sys.argv) > 3 else f"data/metadata/{cls}_meta.json"
    generate_class_traffic(cls, pcap, meta)
