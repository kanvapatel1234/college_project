import subprocess
import sys
import re
from scapy.all import sniff, IP, TCP

# -------------------------------------------------------------
# 1. TOOL PATHS (Adjust if your Icarus Verilog is on C: or D:)
# -------------------------------------------------------------
IVERILOG_BIN = r"D:\iverilog\bin\iverilog.exe"
VVP_BIN = r"D:\iverilog\bin\vvp.exe"

# -------------------------------------------------------------
# 2. CAPTURE REAL PACKET WHILE BROWSING
# -------------------------------------------------------------
print("==================================================")
print("[Sniffer] Listening for outgoing web traffic (Port 80 or 443)...")
print("[Action] Open your browser and load any website now!")
print("==================================================")

# Intercept outgoing HTTP (80) or HTTPS (443) packets with payload
def is_web_traffic(pkt):
    return (
        pkt.haslayer(IP) and 
        pkt.haslayer(TCP) and 
        (pkt[TCP].dport in [80, 443] or pkt[TCP].sport in [80, 443])
    )

# Sniff 1 live packet matching web traffic
packets = sniff(lfilter=is_web_traffic, count=1)
pkt = packets[0]

raw_bytes = bytes(pkt)

src_ip_str = pkt[IP].src
dst_ip_str = pkt[IP].dst
src_port = pkt[TCP].sport
dst_port = pkt[TCP].dport

print(f"\n[Captured] Real-World Packet Intercepted ({len(raw_bytes)} bytes)")
print(f"  Source IP       : {src_ip_str}")
print(f"  Destination IP  : {dst_ip_str}")
print(f"  Source Port     : {src_port}")
print(f"  Destination Port: {dst_port}")

# Convert IPs to 8-character hex for verification
exp_src_ip = f"{int.from_bytes(bytes(map(int, src_ip_str.split('.'))), 'big'):08x}"
exp_dst_ip = f"{int.from_bytes(bytes(map(int, dst_ip_str.split('.'))), 'big'):08x}"

# -------------------------------------------------------------
# 3. WRITE RAW WIRE BYTES TO packet_data.hex
# -------------------------------------------------------------
with open("packet_data.hex", "w") as f:
    for b in raw_bytes:
        f.write(f"{b:02x}\n")

print("[Pipeline] Written wire bytes to packet_data.hex")

# -------------------------------------------------------------
# 4. EXECUTE VERILOG COMPILATION & SIMULATION
# -------------------------------------------------------------
print("\n[Verilog] Compiling and running simulation...")
compile_cmd = [IVERILOG_BIN, "-s", "tb_parser", "-o", "parser_sim", "packet_parser_top.v", "tb_parser.v"]
sim_cmd = [VVP_BIN, "parser_sim"]

res_compile = subprocess.run(compile_cmd, capture_output=True, text=True)
if res_compile.returncode != 0:
    print("[Error] Icarus Verilog compilation failed:")
    print(res_compile.stderr)
    sys.exit(1)

res_sim = subprocess.run(sim_cmd, capture_output=True, text=True)
print("[Verilog Hardware Output]:")
print(res_sim.stdout)

# -------------------------------------------------------------
# 5. AUTOMATED SCOREBOARD
# -------------------------------------------------------------
output = res_sim.stdout
src_ip_match = re.search(r"Source IP\s*:\s*([0-9a-fA-F]{8})", output)
dst_ip_match = re.search(r"Destination IP\s*:\s*([0-9a-fA-F]{8})", output)
src_port_match = re.search(r"Source Port\s*:\s*(\d+)", output)
dst_port_match = re.search(r"Destination Port\s*:\s*(\d+)", output)

if all([src_ip_match, dst_ip_match, src_port_match, dst_port_match]):
    act_src_ip = src_ip_match.group(1).lower()
    act_dst_ip = dst_ip_match.group(1).lower()
    act_src_port = int(src_port_match.group(1))
    act_dst_port = int(dst_port_match.group(1))

    print("-" * 50)
    print("HARDWARE EXTRACTION VERIFICATION:")
    print(f"  [{'PASS' if act_src_ip == exp_src_ip else 'FAIL'}] Source IP      : {act_src_ip} vs {exp_src_ip}")
    print(f"  [{'PASS' if act_dst_ip == exp_dst_ip else 'FAIL'}] Destination IP : {act_dst_ip} vs {exp_dst_ip}")
    print(f"  [{'PASS' if act_src_port == src_port else 'FAIL'}] Source Port    : {act_src_port} vs {src_port}")
    print(f"  [{'PASS' if act_dst_port == dst_port else 'FAIL'}] Destination Port: {act_dst_port} vs {dst_port}")
    print("-" * 50)