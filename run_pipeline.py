import subprocess
import sys
from scapy.all import Ether, IP, TCP, Raw

# -------------------------------------------------------------
# 1. TOOL PATH CONFIGURATION
# -------------------------------------------------------------
# Specify the full path to Icarus Verilog tools
IVERILOG_BIN = r"C:\iverilog\bin\iverilog.exe"
VVP_BIN = r"C:\iverilog\bin\vvp.exe"

# -------------------------------------------------------------
# 2. DEFINE TEST PACKET WITH SCAPY
# -------------------------------------------------------------
src_ip_str = "10.0.0.45"
dst_ip_str = "172.16.1.99"
src_port_num = 54321
dst_port_num = 443
payload_data = "TEST_SCAPY_PAYLOAD"

pkt = Ether(src="aa:bb:cc:dd:ee:01", dst="aa:bb:cc:dd:ee:02") / \
      IP(src=src_ip_str, dst=dst_ip_str) / \
      TCP(sport=src_port_num, dport=dst_port_num) / \
      Raw(load=payload_data)

raw_bytes = bytes(pkt)

# Write hex file for Verilog $readmemh
with open("packet_data.hex", "w") as f:
    for b in raw_bytes:
        f.write(f"{b:02x}\n")

print(f"[Python] Packet generated ({len(raw_bytes)} bytes)")
print(f"[Python] Expected Src IP  : {src_ip_str} -> {int.from_bytes(bytes(map(int, src_ip_str.split('.'))), 'big'):08x}")
print(f"[Python] Expected Dst IP  : {dst_ip_str} -> {int.from_bytes(bytes(map(int, dst_ip_str.split('.'))), 'big'):08x}")
print(f"[Python] Expected Src Port: {src_port_num} -> {src_port_num:04x}")
print(f"[Python] Expected Dst Port: {dst_port_num} -> {dst_port_num:04x}")
print("-" * 50)

# -------------------------------------------------------------
# 3. RUN ICARUS VERILOG COMPILATION & SIMULATION
# -------------------------------------------------------------
print("[Verilog] Compiling packet_parser_top.v and tb_parser.v...")

# Explicit paths to the Icarus Verilog binaries
iverilog_bin = r"C:\iverilog\bin\iverilog.exe"
vvp_bin = r"C:\iverilog\bin\vvp.exe"

compile_cmd = [iverilog_bin, "-s", "tb_parser", "-o", "parser_sim", "packet_parser_top.v", "tb_parser.v"]
sim_cmd = [vvp_bin, "parser_sim"]

# Compile
res_compile = subprocess.run(compile_cmd, capture_output=True, text=True)
if res_compile.returncode != 0:
    print("[Error] Icarus Verilog compilation failed:")
    print(res_compile.stderr)
    sys.exit(1)

# Simulate
res_sim = subprocess.run(sim_cmd, capture_output=True, text=True)
print("[Verilog Hardware Output]:")
print(res_sim.stdout)