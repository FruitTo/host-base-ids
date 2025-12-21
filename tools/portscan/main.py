from scapy.all import *
import time

TARGET_IP = "192.168.122.109"
TARGET_PORT = 80

print(f"🚀 Starting Scan Test against {TARGET_IP}...")

print(f"1️⃣  Sending TCP NULL Scan (Flags=0)...")
pkt_null = IP(dst=TARGET_IP)/TCP(dport=TARGET_PORT, flags=0)
send(pkt_null, verbose=0)
time.sleep(1)

print(f"2️⃣  Sending TCP FULL XMAS Scan (Flags=63)...")
pkt_full = IP(dst=TARGET_IP)/TCP(dport=TARGET_PORT, flags=63)
send(pkt_full, verbose=0)
time.sleep(1)

print(f"3️⃣  Sending Custom Scan (Flags=56)...")
pkt_custom = IP(dst=TARGET_IP)/TCP(dport=TARGET_PORT, flags=56)
send(pkt_custom, verbose=0)
time.sleep(1)

print(f"4️⃣  Sending Standard Nmap Xmas Scan (Flags=41)...")
pkt_std_xmas = IP(dst=TARGET_IP)/TCP(dport=TARGET_PORT, flags=41)
send(pkt_std_xmas, verbose=0)

print("\n✅ Test Completed! Check your C++ console output.")
