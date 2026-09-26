import subprocess
import time
import sys
import os

def run_cmd(cmd, check=True):
    print(f"[EXEC] {cmd}")
    res = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    if check and res.returncode != 0:
        print(f"[ERROR] Command failed: {cmd}\nStderr: {res.stderr}")
    return res

def setup_namespaces():
    print("--- Setting up Linux Network Namespaces & IPsec Tunnel ---")
    # Clean up existing namespaces if any
    run_cmd("sudo ip netns del ns-client", check=False)
    run_cmd("sudo ip netns del ns-server", check=False)

    # Create namespaces
    run_cmd("sudo ip netns add ns-client")
    run_cmd("sudo ip netns add ns-server")

    # Create veth pair
    run_cmd("sudo ip link add veth-c type veth peer name veth-s")
    run_cmd("sudo ip link set veth-c netns ns-client")
    run_cmd("sudo ip link set veth-s netns ns-server")

    # Configure IP addresses
    run_cmd("sudo ip netns exec ns-client ip addr add 10.0.0.1/24 dev veth-c")
    run_cmd("sudo ip netns exec ns-server ip addr add 10.0.0.2/24 dev veth-s")

    # Bring links up
    run_cmd("sudo ip netns exec ns-client ip link set dev veth-c up")
    run_cmd("sudo ip netns exec ns-client ip link set dev lo up")
    run_cmd("sudo ip netns exec ns-server ip link set dev veth-s up")
    run_cmd("sudo ip netns exec ns-server ip link set dev lo up")

    # Verify basic IP connectivity
    res = run_cmd("sudo ip netns exec ns-client ping -c 2 10.0.0.2")
    if res.returncode != 0:
        print("[FAIL] Basic veth connectivity test failed")
        sys.exit(1)
    print("[SUCCESS] Direct veth network connectivity verified (10.0.0.1 <-> 10.0.0.2)")

def configure_ipsec_xfrm():
    print("--- Configuring Kernel IPsec (XFRM) Security Associations & Policies ---")
    # SPIs for client -> server and server -> client
    spi_cs = "0x11223344"
    spi_sc = "0x55667788"

    # Cryptographic Keys (AES-128-CBC + HMAC-SHA256)
    enc_key = "0x0102030405060708090a0b0c0d0e0f10"
    auth_key = "0x0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20"

    # Flush existing XFRM states & policies
    run_cmd("sudo ip netns exec ns-client ip xfrm state flush", check=False)
    run_cmd("sudo ip netns exec ns-client ip xfrm policy flush", check=False)
    run_cmd("sudo ip netns exec ns-server ip xfrm state flush", check=False)
    run_cmd("sudo ip netns exec ns-server ip xfrm policy flush", check=False)

    # Client-side XFRM States
    run_cmd(f"sudo ip netns exec ns-client ip xfrm state add src 10.0.0.1 dst 10.0.0.2 proto esp spi {spi_cs} reqid 1 mode tunnel enc 'cbc(aes)' {enc_key} auth 'hmac(sha256)' {auth_key}")
    run_cmd(f"sudo ip netns exec ns-client ip xfrm state add src 10.0.0.2 dst 10.0.0.1 proto esp spi {spi_sc} reqid 2 mode tunnel enc 'cbc(aes)' {enc_key} auth 'hmac(sha256)' {auth_key}")

    # Client-side XFRM Policies
    run_cmd(f"sudo ip netns exec ns-client ip xfrm policy add src 10.0.0.1 dst 10.0.0.2 dir out tmpl src 10.0.0.1 dst 10.0.0.2 proto esp mode tunnel reqid 1")
    run_cmd(f"sudo ip netns exec ns-client ip xfrm policy add src 10.0.0.2 dst 10.0.0.1 dir in tmpl src 10.0.0.2 dst 10.0.0.1 proto esp mode tunnel reqid 2")

    # Server-side XFRM States
    run_cmd(f"sudo ip netns exec ns-server ip xfrm state add src 10.0.0.1 dst 10.0.0.2 proto esp spi {spi_cs} reqid 1 mode tunnel enc 'cbc(aes)' {enc_key} auth 'hmac(sha256)' {auth_key}")
    run_cmd(f"sudo ip netns exec ns-server ip xfrm state add src 10.0.0.2 dst 10.0.0.1 proto esp spi {spi_sc} reqid 2 mode tunnel enc 'cbc(aes)' {enc_key} auth 'hmac(sha256)' {auth_key}")

    # Server-side XFRM Policies
    run_cmd(f"sudo ip netns exec ns-server ip xfrm policy add src 10.0.0.2 dst 10.0.0.1 dir out tmpl src 10.0.0.2 dst 10.0.0.1 proto esp mode tunnel reqid 2")
    run_cmd(f"sudo ip netns exec ns-server ip xfrm policy add src 10.0.0.1 dst 10.0.0.2 dir in tmpl src 10.0.0.1 dst 10.0.0.2 proto esp mode tunnel reqid 1")

    print("[SUCCESS] IPsec ESP Security Associations & Policies successfully active.")

def teardown_namespaces():
    print("--- Cleaning up Network Namespaces ---")
    run_cmd("sudo ip netns del ns-client", check=False)
    run_cmd("sudo ip netns del ns-server", check=False)

if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "clean":
        teardown_namespaces()
    else:
        setup_namespaces()
        configure_ipsec_xfrm()
