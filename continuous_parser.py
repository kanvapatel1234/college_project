import subprocess
import sys
import re
from scapy.all import sniff, IP, TCP, Raw

IVERILOG_BIN = r"D:\iverilog\bin\iverilog.exe"
VVP_BIN = r"D:\iverilog\bin\vvp.exe"

# -------------------------------------------------------------
# 1. BUILD VERILOG HARDWARE SIMULATION ONCE
# -------------------------------------------------------------
print("[Setup] Compiling Verilog Parser & Testbench...")
compile_cmd = [IVERILOG_BIN, "-s", "tb_parser", "-o", "parser_sim", "packet_parser_top.v", "tb_parser.v"]
res_compile = subprocess.run(compile_cmd, capture_output=True, text=True)

if res_compile.returncode != 0:
    print("[Error] Icarus Verilog compilation failed:\n", res_compile.stderr)
    sys.exit(1)

print("[Setup] Compilation successful! Listening for live web traffic...\n")
print(f"{'PKT #':<6} | {'SRC IP':<15} | {'DST IP':<15} | {'SPORT':<5} | {'DPORT':<5} | {'PAYLOAD (BYTES)':<15} | {'PAYLOAD SAMPLE (HEX)':<20} | {'STATUS'}")
print("-" * 115)

packet_counter = 0

# -------------------------------------------------------------
# 2. PACKET INTERCEPT & EXTRACTION CALLBACK
# -------------------------------------------------------------
def process_live_packet(pkt):
    global packet_counter
    packet_counter += 1

    raw_bytes = bytes(pkt)
    src_ip_str = pkt[IP].src
    dst_ip_str = pkt[IP].dst
    src_port   = pkt[TCP].sport
    dst_port   = pkt[TCP].dport

    exp_src_ip = f"{int.from_bytes(bytes(map(int, src_ip_str.split('.'))), 'big'):08x}"
    exp_dst_ip = f"{int.from_bytes(bytes(map(int, dst_ip_str.split('.'))), 'big'):08x}"
    
    # Expected payload directly from Scapy Layer
    scapy_payload = bytes(pkt[Raw].load) if pkt.haslayer(Raw) else b""
    exp_payload_len = len(scapy_payload)
    exp_payload_hex = scapy_payload[:32].hex().lower()

    # Write full frame bytes to hex file
    with open("packet_data.hex", "w") as f:
        for b in raw_bytes:
            f.write(f"{b:02x}\n")

    # Run compiled simulation
    res_sim = subprocess.run([VVP_BIN, "parser_sim"], capture_output=True, text=True)
    sim_out = res_sim.stdout

    # Parse simulation output
    src_match     = re.search(r"Source IP\s*:\s*([0-9a-fA-F]{8})", sim_out)
    dst_match     = re.search(r"Destination IP\s*:\s*([0-9a-fA-F]{8})", sim_out)
    sport_match   = re.search(r"Source Port\s*:\s*(\d+)", sim_out)
    dport_match   = re.search(r"Destination Port\s*:\s*(\d+)", sim_out)
    present_match = re.search(r"Payload Present\s*:\s*(\d+)", sim_out)
    bytes_match   = re.search(r"Payload Bytes\s*:\s*(\d+)", sim_out)
    hex_match     = re.search(r"Payload Hex\s*:\s*([0-9a-fA-F]*)", sim_out)

    if all([src_match, dst_match, sport_match, dport_match, present_match, bytes_match]):
        hw_src_ip    = src_match.group(1).lower()
        hw_dst_ip    = dst_match.group(1).lower()
        hw_sport     = int(sport_match.group(1))
        hw_dport     = int(dport_match.group(1))
        hw_p_present = int(present_match.group(1))
        hw_p_len     = int(bytes_match.group(1))
        hw_p_hex     = hex_match.group(1).lower() if hex_match else ""

        # Validate Headers
        headers_ok = (hw_src_ip == exp_src_ip and hw_dst_ip == exp_dst_ip and 
                      hw_sport == src_port and hw_dport == dst_port)
        
        # Validate Payload:
        # Check byte count and the hex sample slice that was captured
        sample_len = min(len(hw_p_hex), len(exp_payload_hex))
        if exp_payload_len == 0:
            payload_ok = (hw_p_len == 0)
        else:
            payload_bytes_ok = (hw_p_len == exp_payload_len)
            payload_sample_ok = (hw_p_hex[:sample_len] == exp_payload_hex[:sample_len]) if sample_len > 0 else True
            payload_ok = payload_bytes_ok and payload_sample_ok

        if headers_ok and payload_ok:
            status = "[MATCHED]"
        elif headers_ok and not payload_ok:
            status = "[PAYLOAD MISMATCH]"
        else:
            status = "[HEADER MISMATCH]"

        payload_preview = hw_p_hex[:16] + "..." if len(hw_p_hex) > 16 else (hw_p_hex if hw_p_hex else "NONE")
        payload_desc = f"{hw_p_len} B" if hw_p_present else "0 B (ACK/SYN)"

        print(f"{packet_counter:<6} | {src_ip_str:<15} | {dst_ip_str:<15} | {src_port:<5} | {dst_port:<5} | {payload_desc:<15} | {payload_preview:<20} | {status}")
    else:
        print(f"{packet_counter:<6} | {src_ip_str:<15} | {dst_ip_str:<15} | {src_port:<5} | {dst_port:<5} | {'ERROR':<15} | {'NO_PARSE':<20} | [PARSE FAIL]")

# -------------------------------------------------------------
# 3. START STREAMING INTERCEPT
# -------------------------------------------------------------
filter_rule = "ip and tcp and (port 80 or port 443)"
try:
    sniff(filter=filter_rule, prn=process_live_packet, store=False)
except KeyboardInterrupt:
    print("\n[Stopped] Live packet processing terminated by user.")