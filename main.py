"""AI-PCAP-Analyzer - PCAP dosyalarindaki paketleri ozetleyen ve
isteğe bagli olarak yapay zeka destekli analiz yapan CLI araci."""

import argparse
import sys

from dotenv import load_dotenv
from scapy.all import IP, TCP, UDP, rdpcap

# AI analizine gonderilecek paket ozeti sayisinin ust siniri.
# Cok buyuk pcap dosyalarinda maliyeti ve gecikmeyi kontrol altinda tutar;
# terminal ciktisi (tum paketler) bu siniirdan etkilenmez.
AI_SUMMARY_PACKET_LIMIT = 500


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


def analyze_with_ai(summaries):
    """Paket ozetlerini yapay zeka modeline gonderip supheli davranislar hakkinda yorum alir."""
    try:
        from anthropic import Anthropic, AuthenticationError
    except ImportError:
        print("\n[AI] Hata: 'anthropic' paketi kurulu degil. `pip install -r requirements.txt` calistirin.")
        return

    summary_text = "\n".join(summaries)
    truncated = False
    if len(summaries) > AI_SUMMARY_PACKET_LIMIT:
        summary_text = "\n".join(summaries[:AI_SUMMARY_PACKET_LIMIT])
        truncated = True

    client = Anthropic()

    print("\n[AI] Yapay zeka ile analiz ediliyor...\n")

    try:
        response = client.messages.create(
            model="claude-opus-5",
            max_tokens=2048,
            output_config={"effort": "low"},
            system=(
                "Sen bir ag guvenligi analistisin. Sana verilen ham paket ozetlerini "
                "(protokol, kaynak/hedef IP ve port) inceleyip supheli olabilecek "
                "davranislari (port taramasi, alisilmadik protokoller/portlar, "
                "anormal trafik yogunlugu vb.) Turkce, kisa ve net maddeler halinde "
                "raporla. Hicbir supheli durum yoksa bunu acikca belirt."
            ),
            messages=[{"role": "user", "content": summary_text}],
        )
    except AuthenticationError:
        print(
            "[AI] Hata: Gecersiz veya eksik ANTHROPIC_API_KEY. "
            ".env dosyanizi kontrol edin."
        )
        return
    except Exception as exc:  # API'den gelebilecek diger hatalar
        print(f"[AI] Hata: Istek basarisiz oldu ({exc}).")
        return

    if response.stop_reason == "refusal":
        print("[AI] Model bu istegi yanitlamayi reddetti (guvenlik politikasi).")
        return

    text = next((block.text for block in response.content if block.type == "text"), "")
    print(text)

    if truncated:
        print(
            f"\n[AI] Not: {len(summaries)} paketten ilk {AI_SUMMARY_PACKET_LIMIT} "
            "tanesi analiz edildi."
        )


def analyze_pcap(file_path, use_ai=False):
    try:
        packets = rdpcap(file_path)
    except FileNotFoundError:
        print(f"Hata: '{file_path}' dosyasi bulunamadi.")
        sys.exit(1)

    print(f"'{file_path}' dosyasinda {len(packets)} paket bulundu.\n")

    summaries = []
    for index, packet in enumerate(packets, start=1):
        summary = summarize_packet(index, packet)
        print(summary)
        summaries.append(summary)

    if use_ai:
        analyze_with_ai(summaries)


def main():
    load_dotenv()

    parser = argparse.ArgumentParser(
        description="PCAP dosyalarindaki paketleri ozetler ve isteğe bagli olarak yapay zeka ile analiz eder."
    )
    parser.add_argument("pcap_file", help="Analiz edilecek pcap dosyasinin yolu")
    parser.add_argument(
        "--ai",
        action="store_true",
        help="Paket ozetlerini yapay zeka modeline gonderip destekli analiz al",
    )
    args = parser.parse_args()

    analyze_pcap(args.pcap_file, use_ai=args.ai)


if __name__ == "__main__":
    main()
