from scapy.all import Ether, IP, TCP, Raw

pkt = Ether(src="aa:bb:cc:dd:ee:01", dst="aa:bb:cc:dd:ee:02") / \
      IP(src="10.0.0.45", dst="172.16.1.99") / \
      TCP(sport=54321, dport=443) / \
      Raw(load="TEST_SCAPY_PAYLOAD")

raw_bytes = bytes(pkt)
print(f"Generated packet length: {len(raw_bytes)} bytes")

with open("packet_data.hex", "w") as f:
    for b in raw_bytes:
        f.write(f"{b:02x}\n")

print("Saved to packet_data.hex!")