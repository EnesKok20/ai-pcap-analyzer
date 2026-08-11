"""AI-PCAP-Analyzer - PCAP dosyalarindaki paketleri ozetleyen ve
isteğe bagli olarak yapay zeka destekli analiz yapan CLI araci."""

import argparse
import sys

from dotenv import load_dotenv
from scapy.all import IP, TCP, UDP, rdpcap
from scapy.layers.dns import DNS
from scapy.layers.http import HTTPRequest, HTTPResponse
from scapy.layers.l2 import ARP
from scapy.layers.tls.all import TLSClientHello
from scapy.layers.tls.extensions import TLS_Ext_ServerName

# AI analizine gonderilecek paket ozeti sayisinin ust siniri.
# Cok buyuk pcap dosyalarinda maliyeti ve gecikmeyi kontrol altinda tutar;
# terminal ciktisi (tum paketler) bu siniirdan etkilenmez.
AI_SUMMARY_PACKET_LIMIT = 500


def _decode(value, default="?"):
    if value is None:
        return default
    if isinstance(value, bytes):
        return value.decode(errors="replace")
    return str(value)


def summarize_arp(index, packet):
    arp = packet[ARP]
    op = {1: "who-has", 2: "is-at"}.get(arp.op, str(arp.op))
    return f"[{index}] ARP  {arp.psrc} {op} {arp.pdst}"


def summarize_dns(dns):
    qname = _decode(dns.qd.qname, None) if dns.qd else None
    qname = qname.rstrip(".") if qname else "?"

    if dns.qr == 0:
        return f"| DNS sorgu: {qname}"

    answers = []
    record = dns.an
    while record is not None and hasattr(record, "rdata") and len(answers) < 5:
        answers.append(_decode(record.rdata))
        record = record.payload if hasattr(record.payload, "rdata") else None
    answer_text = ", ".join(answers) if answers else "yanit yok"
    return f"| DNS yanit: {qname} -> {answer_text}"


def summarize_http(packet):
    if packet.haslayer(HTTPRequest):
        req = packet[HTTPRequest]
        method = _decode(req.Method)
        host = _decode(req.Host, "")
        path = _decode(req.Path, "")
        return f"| HTTP istek: {method} {host}{path}"
    if packet.haslayer(HTTPResponse):
        resp = packet[HTTPResponse]
        status = _decode(resp.Status_Code)
        reason = _decode(resp.Reason_Phrase, "")
        return f"| HTTP yanit: {status} {reason}".rstrip()
    return None


def summarize_tls(packet):
    if not packet.haslayer(TLSClientHello):
        return None

    for ext in packet[TLSClientHello].ext or []:
        if isinstance(ext, TLS_Ext_ServerName) and ext.servernames:
            name = ext.servernames[0]
            name = getattr(name, "servername", name)
            sni = _decode(name, None)
            if sni:
                return f"| TLS ClientHello, SNI: {sni}"

    return "| TLS ClientHello"


def summarize_packet(index, packet):
    if ARP in packet:
        return summarize_arp(index, packet)

    if IP not in packet:
        return f"[{index}] IP katmani yok, atlandi ({packet.summary()})"

    ip_layer = packet[IP]
    src_ip = ip_layer.src
    dst_ip = ip_layer.dst
    detail = None

    try:
        if TCP in packet:
            proto = "TCP"
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport
            detail = summarize_http(packet) or summarize_tls(packet)
        elif UDP in packet:
            proto = "UDP"
            src_port = packet[UDP].sport
            dst_port = packet[UDP].dport
            if DNS in packet:
                detail = summarize_dns(packet[DNS])
        else:
            proto = ip_layer.get_field("proto").i2s.get(ip_layer.proto, str(ip_layer.proto))
            src_port = dst_port = "-"
    except Exception:
        # Bozuk/eksik katmanli paketlerde detay cikarimini atla, temel ozeti koru.
        detail = None

    base = f"[{index}] {proto:<4} {src_ip}:{src_port} -> {dst_ip}:{dst_port}"
    return f"{base} {detail}" if detail else base


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
