import subprocess
import sys
import re
from scapy.all import sniff, IP, TCP

IVERILOG_BIN = r"D:\iverilog\bin\iverilog.exe"
VVP_BIN = r"D:\iverilog\bin\vvp.exe"

# -------------------------------------------------------------
# 1. COMPILE ONCE BEFORE STREAMING
# -------------------------------------------------------------
print("[Setup] Compiling packet_parser_top.v and tb_parser.v...")
compile_cmd = [IVERILOG_BIN, "-s", "tb_parser", "-o", "parser_sim", "packet_parser_top.v", "tb_parser.v"]
res_compile = subprocess.run(compile_cmd, capture_output=True, text=True)

if res_compile.returncode != 0:
    print("[Error] Compilation failed:\n", res_compile.stderr)
    sys.exit(1)

print("[Setup] Build successful. Starting live stream...\n")
print(f"{'PKT #':<7} | {'SRC IP':<15} | {'DST IP':<15} | {'SPORT':<6} | {'DPORT':<6} | {'VERILOG STATUS'}")
print("-" * 75)

packet_counter = 0

# -------------------------------------------------------------
# 2. PACKET HANDLER CALLBACK
# -------------------------------------------------------------
def process_live_packet(pkt):
    global packet_counter
    packet_counter += 1

    raw_bytes = bytes(pkt)
    src_ip_str = pkt[IP].src
    dst_ip_str = pkt[IP].dst
    src_port = pkt[TCP].sport
    dst_port = pkt[TCP].dport

    exp_src_ip = f"{int.from_bytes(bytes(map(int, src_ip_str.split('.'))), 'big'):08x}"
    exp_dst_ip = f"{int.from_bytes(bytes(map(int, dst_ip_str.split('.'))), 'big'):08x}"

    # 1. Update hex file
    with open("packet_data.hex", "w") as f:
        for b in raw_bytes:
            f.write(f"{b:02x}\n")

    # 2. Run pre-compiled simulation
    res_sim = subprocess.run([VVP_BIN, "parser_sim"], capture_output=True, text=True)
    sim_out = res_sim.stdout

    # 3. Extract parsed results
    src_match = re.search(r"Source IP\s*:\s*([0-9a-fA-F]{8})", sim_out)
    dst_match = re.search(r"Destination IP\s*:\s*([0-9a-fA-F]{8})", sim_out)
    sport_match = re.search(r"Source Port\s*:\s*(\d+)", sim_out)
    dport_match = re.search(r"Destination Port\s*:\s*(\d+)", sim_out)

    if all([src_match, dst_match, sport_match, dport_match]):
        hw_src_ip = src_match.group(1).lower()
        hw_dst_ip = dst_match.group(1).lower()
        hw_sport = int(sport_match.group(1))
        hw_dport = int(dport_match.group(1))

        matched = (hw_src_ip == exp_src_ip and 
                   hw_dst_ip == exp_dst_ip and 
                   hw_sport == src_port and 
                   hw_dport == dst_port)
        status = "[MATCHED]" if matched else "[MISMATCH]"
    else:
        status = "[ERR: NO PARSE]"

    print(f"{packet_counter:<7} | {src_ip_str:<15} | {dst_ip_str:<15} | {src_port:<6} | {dst_port:<6} | {status}")

# -------------------------------------------------------------
# 3. CONTINUOUS SNIFFING LOOP
# -------------------------------------------------------------
# Intercepts all TCP traffic on web ports continuously
filter_rule = "ip and tcp and (port 80 or port 443)"
sniff(filter=filter_rule, prn=process_live_packet, store=False)