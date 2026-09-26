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
    if check and res.returncode != 0:
        print(f"[ERROR] Command failed: {cmd}\nStderr: {res.stderr}")
    return res

def setup_testbed(spi_cs="0x11223344", spi_sc="0x55667788", enc_alg="cbc(aes)", enc_key="0x0102030405060708090a0b0c0d0e0f10"):
    """Sets up Linux network namespaces and kernel XFRM IPsec ESP tunnel."""
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

    # Flush existing XFRM states & policies
    run_cmd("ip netns exec ns-client ip xfrm state flush", check=False)
    run_cmd("ip netns exec ns-client ip xfrm policy flush", check=False)
    run_cmd("ip netns exec ns-server ip xfrm state flush", check=False)
    run_cmd("ip netns exec ns-server ip xfrm policy flush", check=False)

    # Configure XFRM States
    run_cmd(f"ip netns exec ns-client ip xfrm state add src 10.0.0.1 dst 10.0.0.2 proto esp spi {spi_cs} reqid 1 mode tunnel enc '{enc_alg}' {enc_key} auth 'hmac(sha256)' {auth_key}")
    run_cmd(f"ip netns exec ns-client ip xfrm state add src 10.0.0.2 dst 10.0.0.1 proto esp spi {spi_sc} reqid 2 mode tunnel enc '{enc_alg}' {enc_key} auth 'hmac(sha256)' {auth_key}")

    # Configure XFRM Policies
    run_cmd(f"ip netns exec ns-client ip xfrm policy add src 10.0.0.1 dst 10.0.0.2 dir out tmpl src 10.0.0.1 dst 10.0.0.2 proto esp mode tunnel reqid 1")
    run_cmd(f"ip netns exec ns-client ip xfrm policy add src 10.0.0.2 dst 10.0.0.1 dir in tmpl src 10.0.0.2 dst 10.0.0.1 proto esp mode tunnel reqid 2")

    run_cmd(f"ip netns exec ns-server ip xfrm state add src 10.0.0.1 dst 10.0.0.2 proto esp spi {spi_cs} reqid 1 mode tunnel enc '{enc_alg}' {enc_key} auth 'hmac(sha256)' {auth_key}")
    run_cmd(f"ip netns exec ns-server ip xfrm state add src 10.0.0.2 dst 10.0.0.1 proto esp spi {spi_sc} reqid 2 mode tunnel enc '{enc_alg}' {enc_key} auth 'hmac(sha256)' {auth_key}")

    run_cmd(f"ip netns exec ns-server ip xfrm policy add src 10.0.0.2 dst 10.0.0.1 dir out tmpl src 10.0.0.2 dst 10.0.0.1 proto esp mode tunnel reqid 2")
    run_cmd(f"ip netns exec ns-server ip xfrm policy add src 10.0.0.1 dst 10.0.0.2 dir in tmpl src 10.0.0.1 dst 10.0.0.2 proto esp mode tunnel reqid 1")

def apply_network_conditions(latency_ms=0, jitter_ms=0, loss_percent=0.0):
    """Applies netem qdisc latency, jitter, and packet loss to veth-c interface."""
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
    """Generates IKEv2 control plane packets (UDP 500)."""
    ike_init = b"\xfe\xdc\xba\x98\x76\x54\x32\x10\x00\x00\x00\x00\x00\x00\x00\x00\x21\x20\x22\x08\x00\x00\x00\x01\x00\x00\x00\x38\x00\x00\x00\x20\x00\x00\x00\x01\x00\x00\x00\x03\x03\x00\x00\x0c\x01\x00\x00\x0c\x01\x00\x00\x0e\x02\x00\x00\x08\x02\x00\x00\x05"
    ike_auth = b"\xfe\xdc\xba\x98\x76\x54\x32\x10\x12\x34\x56\x78\x9a\xbc\xde\xf0\x2e\x20\x23\x08\x00\x00\x00\x02\x00\x00\x00\x40\xaa\xbb\xcc\xdd\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xaa\xbb\x12\x34\x56\x78\x90\xab\xcd\xef\xfe\xdc\xba\x98\x76\x54\x32\x10"
    
    pkt_init = IP(src="10.0.0.1", dst="10.0.0.2")/UDP(sport=500, dport=500)/Raw(load=ike_init)
    pkt_auth = IP(src="10.0.0.1", dst="10.0.0.2")/UDP(sport=500, dport=500)/Raw(load=ike_auth)
    
    run_cmd(f"python3 -c \"from scapy.all import IP, UDP, Raw, send; send(IP(src='10.0.0.1', dst='10.0.0.2')/UDP(sport=500, dport=500)/Raw(load=b'{ike_init.hex()}'), verbose=False)\"", check=False)

def run_session_traffic(traffic_class, duration_sec, request_count, payload_size_bytes):
    """Executes class-specific ground truth application traffic inside ns-client."""
    t0 = time.time()
    
    if traffic_class == "ICMP":
        pkt_size = min(payload_size_bytes, 1400)
        interval = max(0.05, duration_sec / max(request_count, 1))
        run_cmd(f"ip netns exec ns-client ping -c {request_count} -s {pkt_size} -i {interval:.3f} 10.0.0.2", check=False)

    elif traffic_class == "WEB":
        port = 8080 + (int(time.time() * 1000) % 1000)
        srv = subprocess.Popen(f"ip netns exec ns-server python3 -m http.server {port}", shell=True)
        time.sleep(0.5)
        for i in range(request_count):
            if time.time() - t0 > duration_sec:
                break
            run_cmd(f"ip netns exec ns-client curl -s http://10.0.0.2:{port}/ > /dev/null", check=False)
            time.sleep(max(0.01, duration_sec / (request_count * 2)))
        subprocess.run(f"pkill -f 'http.server {port}'", shell=True, check=False)

    elif traffic_class == "BULK":
        port = 9080 + (int(time.time() * 1000) % 1000)
        file_mb = max(1, payload_size_bytes // (1024 * 1024))
        tmp_file = f"/tmp/bulk_{port}.bin"
        run_cmd(f"dd if=/dev/urandom of={tmp_file} bs=1M count={file_mb}", check=False)
        srv = subprocess.Popen(f"ip netns exec ns-server python3 -m http.server {port} --directory /tmp", shell=True)
        time.sleep(0.5)
        for i in range(max(1, request_count // 5)):
            if time.time() - t0 > duration_sec:
                break
            run_cmd(f"ip netns exec ns-client curl -s http://10.0.0.2:{port}/bulk_{port}.bin -o /dev/null", check=False)
            time.sleep(0.1)
        subprocess.run(f"pkill -f 'http.server {port}'", shell=True, check=False)
        run_cmd(f"rm -f {tmp_file}", check=False)

    elif traffic_class == "INTERACTIVE":
        port = 7080 + (int(time.time() * 1000) % 1000)
        srv = subprocess.Popen(f"ip netns exec ns-server python3 -m http.server {port}", shell=True)
        time.sleep(0.5)
        for i in range(request_count):
            if time.time() - t0 > duration_sec:
                break
            run_cmd(f"ip netns exec ns-client curl -s http://10.0.0.2:{port}/ > /dev/null", check=False)
            gap = 0.02 if i % 4 != 0 else 0.3 # Burst gap pattern
            time.sleep(gap)
        subprocess.run(f"pkill -f 'http.server {port}'", shell=True, check=False)

def validate_pcap(pcap_path):
    """Validates raw PCAP file to ensure readable ESP packets are present."""
    if not os.path.exists(pcap_path) or os.path.getsize(pcap_path) < 100:
        return "INVALID", "File missing or empty"
    try:
        pkts = rdpcap(pcap_path)
        if len(pkts) == 0:
            return "INVALID", "Zero packets captured"
        
        esp_count = sum(1 for p in pkts if p.haslayer(ESP) or (p.haslayer(IP) and p[IP].proto == 50))
        if esp_count == 0:
            return "PARTIAL", "No ESP layer detected (unencrypted or filter bypass)"
        
        return "VALID", f"{len(pkts)} pkts, {esp_count} ESP pkts"
    except Exception as e:
        return "INVALID", f"PCAP parse error: {str(e)}"

def extract_window_features(pcap_path, exp_id, sess_id, traffic_class, env_id, window_sec=5.0):
    """Extracts 5-second non-overlapping time-window feature vectors from valid PCAP."""
    try:
        pkts = rdpcap(pcap_path)
    except Exception:
        return []
    
    if not pkts:
        return []

    timestamps = [float(p.time) for p in pkts]
    min_t = min(timestamps)
    max_t = max(timestamps)
    
    total_duration = max_t - min_t
    if total_duration <= 0:
        return []

    # Segment packets into window_sec slices
    windows = []
    num_windows = int(np.ceil(total_duration / window_sec))
    
    for w_idx in range(num_windows):
        w_start = min_t + w_idx * window_sec
        w_end = w_start + window_sec
        
        w_pkts = [p for p in pkts if w_start <= float(p.time) < w_end]
        if not w_pkts:
            continue
        
        w_times = [float(p.time) for p in w_pkts]
        w_sizes = [len(p) for p in w_pkts]
        
        duration = max(max(w_times) - min(w_times), 1e-6)
        pkt_count = len(w_pkts)
        byte_count = sum(w_sizes)
        
        pps = pkt_count / duration
        bps = byte_count / duration
        
        if pkt_count > 1:
            iats = np.diff(sorted(w_times))
            mean_iat = float(np.mean(iats))
            std_iat = float(np.std(iats))
        else:
            mean_iat = 0.0
            std_iat = 0.0
            
        windows.append({
            "sample_id": f"NAT_{exp_id}_{sess_id}_W{w_idx:03d}",
            "dataset_source": "DS1_NATIVE_IPSEC_LARGE",
            "provenance_tier": 1,
            "experiment_id": exp_id,
            "experiment_group": f"GRP_{exp_id}_{sess_id}",
            "session_id": sess_id,
            "window_id": w_idx,
            "traffic_class": traffic_class,
            "environment_id": env_id,
            "flow_duration_sec": round(duration, 6),
            "packets_per_sec": round(pps, 4),
            "bytes_per_sec": round(bps, 4),
            "mean_iat_sec": round(mean_iat, 6),
            "std_iat_sec": round(std_iat, 6),
            "mean_packet_size_bytes": round(float(np.mean(w_sizes)), 2),
            "std_packet_size_bytes": round(float(np.std(w_sizes)), 2),
            "min_packet_size_bytes": float(np.min(w_sizes)),
            "max_packet_size_bytes": float(np.max(w_sizes)),
            "pcap_source": os.path.basename(pcap_path)
        })
    return windows

def main():
    print("=========================================================")
    print("   LARGE NATIVE-IPSEC DATASET GENERATOR & AUDITOR      ")
    print("=========================================================\n")

    raw_dir = "data/raw_native_ipsec"
    pcap_dir = os.path.join(raw_dir, "pcaps")
    meta_dir = os.path.join(raw_dir, "metadata")
    os.makedirs(pcap_dir, exist_ok=True)
    os.makedirs(meta_dir, exist_ok=True)

    traffic_classes = ["BULK", "WEB", "INTERACTIVE", "ICMP"]
    
    # Grid of controlled environmental variations (Latency, Loss, Jitter, Duration, EncAlg)
    net_configs = [
        {"env_id": "ENV_CLEAN", "latency": 0, "jitter": 0, "loss": 0.0},
        {"env_id": "ENV_LOW_LATENCY", "latency": 10, "jitter": 2, "loss": 0.0},
        {"env_id": "ENV_HIGH_LATENCY", "latency": 45, "jitter": 5, "loss": 0.5},
        {"env_id": "ENV_LOSSY", "latency": 20, "jitter": 3, "loss": 1.5},
    ]

    total_target_sessions = 320 # 80 sessions per class across 4 environments
    all_window_samples = []
    session_logs = []
    
    sess_counter = 0

    t_start = time.time()

    for t_cls in traffic_classes:
        for env in net_configs:
            env_id = env["env_id"]
            for s_idx in range(20): # 20 independent sessions per class-env pair
                sess_counter += 1
                exp_id = f"EXP_{t_cls}_{env_id}"
                sess_id = f"SESS_{sess_counter:04d}"
                
                # Varied parameters per session
                dur_sec = np.random.choice([10, 15, 20, 25, 30])
                req_cnt = int(np.random.choice([20, 40, 60, 80])) if t_cls != "BULK" else 10
                payload_sz = int(np.random.choice([512, 1024, 2048, 5120])) * 1024 if t_cls == "BULK" else 1024

                spi_cs = f"0x{sess_counter:08x}"
                spi_sc = f"0x{sess_counter + 1000:08x}"

                # 1. Setup IPsec Tunnel
                setup_testbed(spi_cs=spi_cs, spi_sc=spi_sc)

                # 2. Apply Network Conditions
                apply_network_conditions(env["latency"], env["jitter"], env["loss"])

                # 3. Start PCAP capture
                pcap_path = os.path.join(pcap_dir, f"{exp_id}_{sess_id}.pcap")
                meta_path = os.path.join(meta_dir, f"{exp_id}_{sess_id}.json")
                
                p_tcpdump = subprocess.Popen(f"ip netns exec ns-client tcpdump -i veth-c -w {pcap_path} -U", shell=True)
                time.sleep(1.0) # Warmup tcpdump

                # 4. Generate Traffic
                send_ike_packets()
                run_session_traffic(t_cls, dur_sec, req_cnt, payload_sz)
                
                time.sleep(0.5)
                subprocess.run("pkill -f tcpdump", shell=True, check=False)
                time.sleep(0.8)

                # 5. Validate PCAP
                status, val_msg = validate_pcap(pcap_path)

                # 6. Save Metadata
                # Convert numpy types to native python types for JSON serialization
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
                    "validation_status": str(status),
                    "validation_message": str(val_msg),
                    "timestamp": float(time.time())
                }
                with open(meta_path, "w") as f:
                    json.dump(meta_record, f, indent=2)


                session_logs.append(meta_record)

                if status == "VALID":
                    # 7. Extract window features
                    windows = extract_window_features(pcap_path, exp_id, sess_id, t_cls, env_id, window_sec=5.0)
                    all_window_samples.extend(windows)
                    print(f"[{sess_counter:03d}/{total_target_sessions}] {exp_id} {sess_id} -> {status} ({len(windows)} windows extracted)")
                else:
                    print(f"[{sess_counter:03d}/{total_target_sessions}] {exp_id} {sess_id} -> REJECTED ({status}: {val_msg})")

    # Clean up testbed
    run_cmd("ip netns del ns-client", check=False)
    run_cmd("ip netns del ns-server", check=False)

    df_dataset = pd.DataFrame(all_window_samples)
    out_csv = "data/processed/native_ipsec_large_dataset.csv"
    os.makedirs("data/processed", exist_ok=True)
    df_dataset.to_csv(out_csv, index=False)
    
    elapsed = time.time() - t_start
    print("\n=========================================================")
    print(f" GENERATION COMPLETE IN {elapsed:.2f}s!")
    print(f" Total Sessions Executed: {sess_counter}")
    print(f" Total Valid Window Samples Extracted: {len(df_dataset)}")
    print(f" Dataset saved to: {out_csv}")
    print("=========================================================")

if __name__ == "__main__":
    main()
