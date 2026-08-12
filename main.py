"""AI-PCAP-Analyzer - PCAP dosyalarindaki paketleri ozetleyen ve
isteğe bagli olarak yapay zeka destekli analiz yapan CLI araci."""

import argparse
import sys
from collections import Counter, defaultdict

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

# Bir kaynak IP'nin, port taramasi supheli sayilmasi icin temas etmesi
# gereken minimum farkli hedef port sayisi. Basit bir sezgisel esiktir.
PORT_SCAN_THRESHOLD = 15

# Ozet bloklarinda gosterilecek en cok trafik ureten IP / port sayisi.
TOP_N = 5


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
    # scapy 2.7+ suruumunde dns.qd / dns.an artik birer liste (PacketListField);
    # tekil nesne gibi erisim (dns.qd.qname) deprecated oldugu icin listeden
    # ilk elemanlari aliyoruz.
    questions = dns.qd or []
    qname = _decode(questions[0].qname, None) if questions else None
    qname = qname.rstrip(".") if qname else "?"

    if dns.qr == 0:
        return f"| DNS sorgu: {qname}"

    answers = [_decode(getattr(rr, "rdata", None)) for rr in (dns.an or [])[:5]]
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


def build_flow_stats(packets):
    """Paket listesinden protokol/IP/port dagilimlarini ve olasi port taramasi
    supheli IP'leri cikaran akis (flow) bazli istatistik cikarir."""
    protocol_counts = Counter()
    talker_counts = Counter()
    port_counts = Counter()
    flows = set()
    dst_ports_by_src = defaultdict(set)

    for packet in packets:
        if ARP in packet:
            protocol_counts["ARP"] += 1
            continue

        if IP not in packet:
            protocol_counts["diger"] += 1
            continue

        ip_layer = packet[IP]
        src_ip, dst_ip = ip_layer.src, ip_layer.dst
        talker_counts[src_ip] += 1
        talker_counts[dst_ip] += 1

        if TCP in packet:
            proto = "TCP"
            dst_port = packet[TCP].dport
        elif UDP in packet:
            proto = "UDP"
            dst_port = packet[UDP].dport
        else:
            proto = ip_layer.get_field("proto").i2s.get(ip_layer.proto, str(ip_layer.proto))
            dst_port = None

        protocol_counts[proto] += 1
        flows.add((src_ip, dst_ip, proto))

        if dst_port is not None:
            port_counts[(proto, dst_port)] += 1
            dst_ports_by_src[src_ip].add(dst_port)

    scan_suspects = {
        ip: ports for ip, ports in dst_ports_by_src.items() if len(ports) >= PORT_SCAN_THRESHOLD
    }

    return {
        "protocol_counts": protocol_counts,
        "talker_counts": talker_counts,
        "port_counts": port_counts,
        "flow_count": len(flows),
        "scan_suspects": scan_suspects,
    }


def format_flow_stats(stats):
    lines = ["", "===== Trafik Ozeti =====", f"Benzersiz akis sayisi (kaynak IP, hedef IP, protokol): {stats['flow_count']}"]

    lines.append("\nProtokol dagilimi:")
    for proto, count in stats["protocol_counts"].most_common():
        lines.append(f"  {proto:<6} {count} paket")

    lines.append(f"\nEn cok trafige karisan {TOP_N} IP:")
    for ip, count in stats["talker_counts"].most_common(TOP_N):
        lines.append(f"  {ip:<16} {count} paket")

    if stats["port_counts"]:
        lines.append(f"\nEn cok hedeflenen {TOP_N} port:")
        for (proto, port), count in stats["port_counts"].most_common(TOP_N):
            lines.append(f"  {proto}/{port:<6} {count} paket")

    if stats["scan_suspects"]:
        lines.append(f"\n[!] Olasi port taramasi supheli IP'ler (>= {PORT_SCAN_THRESHOLD} farkli hedef port):")
        for ip, ports in sorted(stats["scan_suspects"].items(), key=lambda kv: -len(kv[1])):
            lines.append(f"  {ip:<16} {len(ports)} farkli port")

    return "\n".join(lines)


def run_ai_analysis(summaries, stats_text=""):
    """Paket ozetlerini (ve trafik ozetini) yapay zeka modeline gonderip
    supheli davranislar hakkinda yorum metni dondurur. Hem CLI'den hem de
    web arayuzunden cagrilabilmesi icin sonucu print etmez, dondurur;
    hata durumunda istisna firlatmak yerine okunabilir bir hata metni
    dondurur."""
    try:
        from anthropic import Anthropic, AuthenticationError
    except ImportError:
        return "Hata: 'anthropic' paketi kurulu degil. `pip install -r requirements.txt` calistirin."

    truncated = len(summaries) > AI_SUMMARY_PACKET_LIMIT
    packet_lines = "\n".join(summaries[:AI_SUMMARY_PACKET_LIMIT])
    summary_text = f"{stats_text}\n\n--- Paket Ozetleri ---\n{packet_lines}" if stats_text else packet_lines

    client = Anthropic()

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
        return "Hata: Gecersiz veya eksik ANTHROPIC_API_KEY. .env dosyanizi kontrol edin."
    except Exception as exc:  # API'den gelebilecek diger hatalar
        return f"Hata: Istek basarisiz oldu ({exc})."

    if response.stop_reason == "refusal":
        return "Model bu istegi yanitlamayi reddetti (guvenlik politikasi)."

    text = next((block.text for block in response.content if block.type == "text"), "")

    if truncated:
        text += (
            f"\n\n[Not: {len(summaries)} paketten ilk {AI_SUMMARY_PACKET_LIMIT} "
            "tanesi analiz edildi.]"
        )

    return text


def analyze_with_ai(summaries, stats_text=""):
    """CLI icin: run_ai_analysis sonucunu ekrana yazdirir."""
    print("\n[AI] Yapay zeka ile analiz ediliyor...\n")
    print(run_ai_analysis(summaries, stats_text))


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

    stats_text = format_flow_stats(build_flow_stats(packets))
    print(stats_text)

    if use_ai:
        analyze_with_ai(summaries, stats_text)


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
