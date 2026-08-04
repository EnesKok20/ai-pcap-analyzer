"""AI-PCAP-Analyzer - PCAP dosyalarindaki paketleri ozetleyen baslangic scripti."""

import sys

from scapy.all import IP, TCP, UDP, rdpcap


def summarize_packet(index, packet):
    if IP not in packet:
        return f"[{index}] IP katmani yok, atlandi ({packet.summary()})"

    ip_layer = packet[IP]
    src_ip = ip_layer.src
    dst_ip = ip_layer.dst

    if TCP in packet:
        proto = "TCP"
        src_port = packet[TCP].sport
        dst_port = packet[TCP].dport
    elif UDP in packet:
        proto = "UDP"
        src_port = packet[UDP].sport
        dst_port = packet[UDP].dport
    else:
        proto = ip_layer.get_field("proto").i2s.get(ip_layer.proto, str(ip_layer.proto))
        src_port = dst_port = "-"

    return f"[{index}] {proto:<4} {src_ip}:{src_port} -> {dst_ip}:{dst_port}"


def analyze_pcap(file_path):
    try:
        packets = rdpcap(file_path)
    except FileNotFoundError:
        print(f"Hata: '{file_path}' dosyasi bulunamadi.")
        sys.exit(1)

    print(f"'{file_path}' dosyasinda {len(packets)} paket bulundu.\n")

    for index, packet in enumerate(packets, start=1):
        print(summarize_packet(index, packet))


def main():
    if len(sys.argv) != 2:
        print("Kullanim: python main.py <pcap_dosyasi>")
        sys.exit(1)

    analyze_pcap(sys.argv[1])


if __name__ == "__main__":
    main()
