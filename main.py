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

from rules import SecurityRuleEngine, SecurityAlert

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


class FlowStatsAccumulator:
    """Paketleri tek tek (streaming) isleyerek trafik istatistiklerini
    biriktirir. Butun paketleri bellekte tutmadan calisir; bu sayede hem
    dosyadan toplu analizde hem de uzun sureli canli yakalamada (capture.py)
    ayni mantik kullanilabilir."""

    def __init__(self):
        self.protocol_counts = Counter()
        self.talker_counts = Counter()
        self.port_counts = Counter()
        self.flows = set()
        self.packet_count = 0
        self._dst_ports_by_src = defaultdict(set)

    def add(self, packet):
        self.packet_count += 1

        if ARP in packet:
            self.protocol_counts["ARP"] += 1
            return

        if IP not in packet:
            self.protocol_counts["diger"] += 1
            return

        ip_layer = packet[IP]
        src_ip, dst_ip = ip_layer.src, ip_layer.dst
        self.talker_counts[src_ip] += 1
        self.talker_counts[dst_ip] += 1

        if TCP in packet:
            proto = "TCP"
            dst_port = packet[TCP].dport
        elif UDP in packet:
            proto = "UDP"
            dst_port = packet[UDP].dport
        else:
            proto = ip_layer.get_field("proto").i2s.get(ip_layer.proto, str(ip_layer.proto))
            dst_port = None

        self.protocol_counts[proto] += 1
        self.flows.add((src_ip, dst_ip, proto))

        if dst_port is not None:
            self.port_counts[(proto, dst_port)] += 1
            self._dst_ports_by_src[src_ip].add(dst_port)

    def as_stats(self):
        scan_suspects = {
            ip: ports for ip, ports in self._dst_ports_by_src.items() if len(ports) >= PORT_SCAN_THRESHOLD
        }
        return {
            "protocol_counts": self.protocol_counts,
            "talker_counts": self.talker_counts,
            "port_counts": self.port_counts,
            "flow_count": len(self.flows),
            "scan_suspects": scan_suspects,
        }


def build_flow_stats(packets):
    """Paket listesinden protokol/IP/port dagilimlarini ve olasi port taramasi
    supheli IP'leri cikaran akis (flow) bazli istatistik cikarir."""
    accumulator = FlowStatsAccumulator()
    for packet in packets:
        accumulator.add(packet)
    return accumulator.as_stats()


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


def run_ai_analysis(summaries, stats_text="", alerts_text="", provider="claude"):
    """Paket ozetlerini, trafik ozetini ve kural motorunun buldugu alarmlari
    yapay zeka modeline gonderip siber guvenlik analizi dondurur.
    Turkce, guzel bicimlendirilmis Markdown formatinda rapor uretir.
    provider="claude" veya "ollama" olabilir."""
    import os
    import requests

    truncated = len(summaries) > AI_SUMMARY_PACKET_LIMIT
    packet_lines = "\n".join(summaries[:AI_SUMMARY_PACKET_LIMIT])

    parts = []
    if stats_text:
        parts.append(stats_text)
    if alerts_text:
        parts.append(f"--- Kural Motorunun Urettigi Alarmlar ---\n{alerts_text}")
    if packet_lines:
        parts.append(f"--- Paket Ozetleri ---\n{packet_lines}")
    
    summary_text = "\n\n".join(parts) if parts else "(veri yok)"

    system_prompt = (
        "Sen kıdemli bir ağ güvenliği analistisin. Sana verilen trafik özetini, "
        "kural motorunun tespit ettiği alarmları ve paket özetlerini inceleyerek "
        "detaylı bir siber güvenlik analizi raporu hazırla.\n\n"
        "Raporunu mutlaka Türkçe, profesyonel, okunaklı ve şu başlıkları içeren "
        "güzel bir Markdown formatında sun:\n"
        "1. **Yönetici Özeti** (Trafiğin genel durumu ve en büyük riskler)\n"
        "2. **Tespit Edilen Güvenlik Tehditleri ve Anomaliler** (Kural motoru uyarılarını ve paketleri "
        "yorumlayarak ne tür saldırı veya anormal durumlar olduğunu açıkla)\n"
        "3. **Etkilenen veya Risk Altındaki Sistemler** (Hangi IP'lerin hedef alındığını veya saldırgan olduğunu belirt)\n"
        "4. **Önerilen Çözüm ve İyileştirme Adımları** (Sistem yöneticisinin ne yapması gerektiğine dair net öneriler)\n\n"
        "Eğer hiçbir şüpheli durum saptanmadıysa bunu yönetici özetinde açıkça belirt."
    )

    if provider == "ollama":
        ollama_url = os.getenv("OLLAMA_API_URL", "http://localhost:11434/api/chat")
        model = os.getenv("OLLAMA_MODEL", "llama3")
        
        payload = {
            "model": model,
            "messages": [
                {
                    "role": "system",
                    "content": system_prompt
                },
                {
                    "role": "user",
                    "content": summary_text
                }
            ],
            "stream": False
        }
        
        try:
            res = requests.post(ollama_url, json=payload, timeout=30)
            if res.status_code == 200:
                res_data = res.json()
                text = res_data["message"]["content"]
            else:
                # res.text kullanicinin kendi yerel Ollama sunucusundan geliyor
                # olsa da beklenmeyen/asiri uzun icerik tasiyabilir; sadece
                # durum kodu ve eylem onerisi donduruluyor.
                return f"Hata: Yerel Ollama sunucusu hata kodu döndürdü (HTTP {res.status_code}). Modelin doğru yüklendiğinden ve '{ollama_url}' adresinin doğru olduğundan emin olun."
        except Exception as e:
            return (
                f"Hata: Yerel Ollama sunucusuna bağlanılamadı ({type(e).__name__}).\n"
                f"Lütfen arka planda Ollama sunucusunun çalıştığından (örneğin 'ollama run {model}') "
                f"ve '{ollama_url}' adresine erişilebilir olduğundan emin olun."
            )
    elif provider == "gemini":
        gemini_key = os.getenv("GEMINI_API_KEY", "").strip().strip('"').strip("'")
        if not gemini_key:
            return "Hata: Gecersiz veya eksik GEMINI_API_KEY. .env dosyanizi kontrol edin."
            
        # API anahtari URL query string'i yerine header'da gonderiliyor;
        # aksi halde anahtar proxy/erisim loglarina ve (istek basarisiz
        # olup URL'i iceren bir exception firlatilirsa) kullaniciya donen
        # hata mesajina sizabilirdi.
        url = "https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-flash:generateContent"
        headers = {"Content-Type": "application/json", "x-goog-api-key": gemini_key}
        
        # Daha uyumlu ve saglam payload yapisi
        payload = {
            "contents": [
                {
                    "parts": [
                        {
                            "text": f"{system_prompt}\n\nİşte analiz edilecek PCAP ağ verileri özetleri ve kurallar:\n\n{summary_text}"
                        }
                    ]
                }
            ],
            "generationConfig": {
                "temperature": 0.2
            }
        }
        
        try:
            res = requests.post(url, json=payload, headers=headers, timeout=30)
            if res.status_code == 200:
                res_data = res.json()
                try:
                    text = res_data["candidates"][0]["content"]["parts"][0]["text"]
                except (KeyError, IndexError):
                    return "Hata: Gemini yanıtı çözümlenemedi (beklenmeyen yanıt formatı)."
            else:
                # res.text Google'in ham hata govdesini iceriyor; kullaniciya
                # sadece durum kodu ve eylem onerisi donduruluyor.
                return f"Hata: Gemini API hata kodu döndürdü (HTTP {res.status_code}). API anahtarınızı ve kullanım kotanızı kontrol edin."
        except Exception as e:
            return f"Hata: Gemini API isteği başarısız oldu ({type(e).__name__})."
    else:  # Claude
        try:
            from anthropic import Anthropic, AuthenticationError
        except ImportError:
            return "Hata: 'anthropic' paketi kurulu degil. `pip install -r requirements.txt` calistirin."

        if "ANTHROPIC_API_KEY" in os.environ:
            os.environ["ANTHROPIC_API_KEY"] = os.environ["ANTHROPIC_API_KEY"].strip().strip('"').strip("'")

        client = Anthropic()

        try:
            response = client.messages.create(
                model="claude-3-5-sonnet-20241022",
                max_tokens=2048,
                system=system_prompt,
                messages=[{"role": "user", "content": summary_text}],
            )
        except AuthenticationError:
            return "Hata: Gecersiz veya eksik ANTHROPIC_API_KEY. .env dosyanizi kontrol edin."
        except Exception as exc:
            return f"Hata: İstek başarısız oldu ({type(exc).__name__})."

        if response.stop_reason == "refusal":
            return "Model bu istegi yanitlamayi reddetti (guvenlik politikasi)."

        text = next((block.text for block in response.content if block.type == "text"), "")

    if truncated:
        text += (
            f"\n\n---\n*Not: {len(summaries)} paketten ilk {AI_SUMMARY_PACKET_LIMIT} "
            "tanesi analiz edilerek bu rapor olusturulmustur.*"
        )

    return text


def analyze_with_ai(summaries, stats_text="", alerts_text=""):
    """CLI icin: run_ai_analysis sonucunu ekrana yazdirir."""
    print("\n[AI] Yapay zeka ile analiz ediliyor...\n")
    print(run_ai_analysis(summaries, stats_text, alerts_text))


def analyze_pcap(file_path, use_ai=False):
    try:
        packets = rdpcap(file_path)
    except FileNotFoundError:
        print(f"Hata: '{file_path}' dosyasi bulunamadi.")
        sys.exit(1)

    print(f"'{file_path}' dosyasinda {len(packets)} paket bulundu.\n")

    engine = SecurityRuleEngine()
    summaries = []
    alerts = []
    
    for index, packet in enumerate(packets, start=1):
        summary = summarize_packet(index, packet)
        print(summary)
        summaries.append(summary)
        
        # Guvenlik kural analizini calistir
        packet_alerts = engine.analyze_packet(index, packet)
        for alert in packet_alerts:
            print(f"  [!] {alert}")
            alerts.append(alert)

    # Toplu analiz alarmlarini al
    summary_alerts = engine.get_summary_alerts()
    for alert in summary_alerts:
        print(f"\n[!] {alert}")
        alerts.append(alert)

    stats_text = format_flow_stats(build_flow_stats(packets))
    print(stats_text)

    if use_ai:
        alerts_text = "\n".join([str(a) for a in alerts])
        analyze_with_ai(summaries, stats_text, alerts_text)


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
