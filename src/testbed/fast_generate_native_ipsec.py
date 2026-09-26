import os
import sys
import time
import json
import glob
import subprocess
import numpy as np
import pandas as pd
from scapy.all import rdpcap, IP, UDP, Raw, ESP

def run_cmd(cmd, check=False):
    res = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    return res

def setup_testbed(spi_cs="0x11223344", spi_sc="0x55667788", enc_alg="cbc(aes)", enc_key="0x0102030405060708090a0b0c0d0e0f10"):
    run_cmd("ip netns del ns-client", check=False)
    run_cmd("ip netns del ns-server", check=False)

    run_cmd("ip netns add ns-client", check=True)
    run_cmd("ip netns add ns-server", check=True)

    run_cmd("ip link add veth-c type veth peer name veth-s", check=True)
    run_cmd("ip link set veth-c netns ns-client", check=True)
    run_cmd("ip link set veth-s netns ns-server", check=True)

    run_cmd("ip netns exec ns-client ip addr add 10.0.0.1/24 dev veth-c", check=True)
    run_cmd("ip netns exec ns-server ip addr add 10.0.0.2/24 dev veth-s", check=True)

    run_cmd("ip netns exec ns-client ip link set dev veth-c up", check=True)
    run_cmd("ip netns exec ns-client ip link set dev lo up", check=True)
    run_cmd("ip netns exec ns-server ip link set dev veth-s up", check=True)
    run_cmd("ip netns exec ns-server ip link set dev lo up", check=True)

    auth_key = "0x0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20"

    run_cmd("ip netns exec ns-client ip xfrm state flush", check=False)
    run_cmd("ip netns exec ns-client ip xfrm policy flush", check=False)
    run_cmd("ip netns exec ns-server ip xfrm state flush", check=False)
    run_cmd("ip netns exec ns-server ip xfrm policy flush", check=False)

    run_cmd(f"ip netns exec ns-client ip xfrm state add src 10.0.0.1 dst 10.0.0.2 proto esp spi {spi_cs} reqid 1 mode tunnel enc '{enc_alg}' {enc_key} auth 'hmac(sha256)' {auth_key}")
    run_cmd(f"ip netns exec ns-client ip xfrm state add src 10.0.0.2 dst 10.0.0.1 proto esp spi {spi_sc} reqid 2 mode tunnel enc '{enc_alg}' {enc_key} auth 'hmac(sha256)' {auth_key}")

    run_cmd(f"ip netns exec ns-client ip xfrm policy add src 10.0.0.1 dst 10.0.0.2 dir out tmpl src 10.0.0.1 dst 10.0.0.2 proto esp mode tunnel reqid 1")
    run_cmd(f"ip netns exec ns-client ip xfrm policy add src 10.0.0.2 dst 10.0.0.1 dir in tmpl src 10.0.0.2 dst 10.0.0.1 proto esp mode tunnel reqid 2")

    run_cmd(f"ip netns exec ns-server ip xfrm state add src 10.0.0.1 dst 10.0.0.2 proto esp spi {spi_cs} reqid 1 mode tunnel enc '{enc_alg}' {enc_key} auth 'hmac(sha256)' {auth_key}")
    run_cmd(f"ip netns exec ns-server ip xfrm state add src 10.0.0.2 dst 10.0.0.1 proto esp spi {spi_sc} reqid 2 mode tunnel enc '{enc_alg}' {enc_key} auth 'hmac(sha256)' {auth_key}")

    run_cmd(f"ip netns exec ns-server ip xfrm policy add src 10.0.0.2 dst 10.0.0.1 dir out tmpl src 10.0.0.2 dst 10.0.0.1 proto esp mode tunnel reqid 2")
    run_cmd(f"ip netns exec ns-server ip xfrm policy add src 10.0.0.1 dst 10.0.0.2 dir in tmpl src 10.0.0.1 dst 10.0.0.2 proto esp mode tunnel reqid 1")

def apply_network_conditions(latency_ms=0, jitter_ms=0, loss_percent=0.0):
    run_cmd("ip netns exec ns-client tc qdisc del dev veth-c root", check=False)
    if latency_ms > 0 or loss_percent > 0:
        cmd = f"ip netns exec ns-client tc qdisc add dev veth-c root netem"
        if latency_ms > 0:
            cmd += f" delay {latency_ms}ms"
            if jitter_ms > 0:
                cmd += f" {jitter_ms}ms"
        if loss_percent > 0:
            cmd += f" loss {loss_percent}%"
        run_cmd(cmd, check=False)

def send_ike_packets():
    ike_init = b"\xfe\xdc\xba\x98\x76\x54\x32\x10\x00\x00\x00\x00\x00\x00\x00\x00\x21\x20\x22\x08\x00\x00\x00\x01\x00\x00\x00\x38\x00\x00\x00\x20\x00\x00\x00\x01\x00\x00\x00\x03\x03\x00\x00\x0c\x01\x00\x00\x0c\x01\x00\x00\x0e\x02\x00\x00\x08\x02\x00\x00\x05"
    run_cmd(f"python3 -c \"from scapy.all import IP, UDP, Raw, send; send(IP(src='10.0.0.1', dst='10.0.0.2')/UDP(sport=500, dport=500)/Raw(load=b'{ike_init.hex()}'), verbose=False)\"", check=False)

def run_session_traffic(traffic_class, duration_sec, request_count, payload_size_bytes):
    t0 = time.time()
    
    if traffic_class == "ICMP":
        pkt_size = min(payload_size_bytes, 1400)
        interval = max(0.01, duration_sec / max(request_count, 1))
        run_cmd(f"ip netns exec ns-client ping -c {request_count} -s {pkt_size} -i {interval:.3f} 10.0.0.2", check=False)

    elif traffic_class == "WEB":
        port = 8100 + (int(time.time() * 1000) % 800)
        srv = subprocess.Popen(f"ip netns exec ns-server python3 -m http.server {port}", shell=True)
        time.sleep(0.3)
        for i in range(request_count):
            if time.time() - t0 > duration_sec:
                break
            run_cmd(f"ip netns exec ns-client curl -s http://10.0.0.2:{port}/ > /dev/null", check=False)
            time.sleep(max(0.005, duration_sec / (request_count * 2)))
        subprocess.run(f"pkill -f 'http.server {port}'", shell=True, check=False)

    elif traffic_class == "BULK":
        port = 9100 + (int(time.time() * 1000) % 800)
        file_mb = max(1, payload_size_bytes // (1024 * 1024))
        tmp_file = f"/tmp/bulk_{port}.bin"
        run_cmd(f"dd if=/dev/urandom of={tmp_file} bs=1M count={file_mb}", check=False)
        srv = subprocess.Popen(f"ip netns exec ns-server python3 -m http.server {port} --directory /tmp", shell=True)
        time.sleep(0.3)
        for i in range(max(1, request_count // 5)):
            if time.time() - t0 > duration_sec:
                break
            run_cmd(f"ip netns exec ns-client curl -s http://10.0.0.2:{port}/bulk_{port}.bin -o /dev/null", check=False)
            time.sleep(0.05)
        subprocess.run(f"pkill -f 'http.server {port}'", shell=True, check=False)
        run_cmd(f"rm -f {tmp_file}", check=False)

    elif traffic_class == "INTERACTIVE":
        port = 7100 + (int(time.time() * 1000) % 800)
        srv = subprocess.Popen(f"ip netns exec ns-server python3 -m http.server {port}", shell=True)
        time.sleep(0.3)
        for i in range(request_count):
            if time.time() - t0 > duration_sec:
                break
            run_cmd(f"ip netns exec ns-client curl -s http://10.0.0.2:{port}/ > /dev/null", check=False)
            gap = 0.01 if i % 4 != 0 else 0.15
            time.sleep(gap)
        subprocess.run(f"pkill -f 'http.server {port}'", shell=True, check=False)

def main():
    raw_dir = "data/raw_native_ipsec"
    pcap_dir = os.path.join(raw_dir, "pcaps")
    meta_dir = os.path.join(raw_dir, "metadata")
    os.makedirs(pcap_dir, exist_ok=True)
    os.makedirs(meta_dir, exist_ok=True)

    traffic_classes = ["BULK", "WEB", "INTERACTIVE", "ICMP"]
    
    net_configs = [
        {"env_id": "ENV_CLEAN", "latency": 0, "jitter": 0, "loss": 0.0},
        {"env_id": "ENV_LOW_LATENCY", "latency": 10, "jitter": 2, "loss": 0.0},
        {"env_id": "ENV_HIGH_LATENCY", "latency": 45, "jitter": 5, "loss": 0.5},
        {"env_id": "ENV_LOSSY", "latency": 20, "jitter": 3, "loss": 1.5},
    ]

    sess_counter = 0
    t_start = time.time()

    for t_cls in traffic_classes:
        for env in net_configs:
            env_id = env["env_id"]
            for s_idx in range(15): # 15 sessions per class-env pair = 240 total sessions
                sess_counter += 1
                exp_id = f"EXP_{t_cls}_{env_id}"
                sess_id = f"SESS_{sess_counter:04d}"
                
                pcap_path = os.path.join(pcap_dir, f"{exp_id}_{sess_id}.pcap")
                meta_path = os.path.join(meta_dir, f"{exp_id}_{sess_id}.json")

                if os.path.exists(pcap_path) and os.path.getsize(pcap_path) > 1000:
                    print(f"[{sess_counter:03d}/240] {exp_id} {sess_id} -> EXISTS, skipping generation")
                    continue

                dur_sec = int(np.random.choice([4, 6, 8]))
                req_cnt = int(np.random.choice([30, 50, 70])) if t_cls != "BULK" else 10
                payload_sz = int(np.random.choice([512, 1024, 2048])) * 1024 if t_cls == "BULK" else 1024

                spi_cs = f"0x{sess_counter:08x}"
                spi_sc = f"0x{sess_counter + 1000:08x}"

                setup_testbed(spi_cs=spi_cs, spi_sc=spi_sc)
                apply_network_conditions(env["latency"], env["jitter"], env["loss"])

                p_tcpdump = subprocess.Popen(f"ip netns exec ns-client tcpdump -i veth-c -w {pcap_path} -U", shell=True)
                time.sleep(0.4)

                send_ike_packets()
                run_session_traffic(t_cls, dur_sec, req_cnt, payload_sz)
                
                time.sleep(0.2)
                subprocess.run("pkill -f tcpdump", shell=True, check=False)
                time.sleep(0.3)

                env_clean = {k: int(v) if isinstance(v, (np.integer, int)) else (float(v) if isinstance(v, (np.floating, float)) else v) for k, v in env.items()}
                meta_record = {
                    "experiment_id": str(exp_id),
                    "session_id": str(sess_id),
                    "traffic_class": str(t_cls),
                    "environment_id": str(env_id),
                    "ipsec_version": "IKEv2",
                    "esp_transform": "cbc(aes)-128",
                    "integrity_transform": "hmac(sha256)",
                    "network_conditions": env_clean,
                    "duration_intended_sec": int(dur_sec),
                    "pcap_file": str(pcap_path),
                    "timestamp": float(time.time())
                }
                with open(meta_path, "w") as f:
                    json.dump(meta_record, f, indent=2)

                print(f"[{sess_counter:03d}/240] Generated {exp_id} {sess_id} (size: {os.path.getsize(pcap_path)} bytes)")

    run_cmd("ip netns del ns-client", check=False)
    run_cmd("ip netns del ns-server", check=False)

    elapsed = time.time() - t_start
    print(f"\nALL 240 SESSIONS GENERATED IN {elapsed:.2f}s!")

if __name__ == "__main__":
    main()
