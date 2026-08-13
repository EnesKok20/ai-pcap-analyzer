"""Siber güvenlik tehditlerini ve şüpheli ağ aktivitelerini tespit eden
kural motoru (Rule Engine). Heuristik ve imza tabanlı kurallar içerir."""

import re
from collections import defaultdict
from urllib.parse import unquote
from scapy.all import IP, TCP, UDP, ARP
from scapy.layers.dns import DNS
from scapy.layers.http import HTTPRequest

# Tehdit dereceleri
SEVERITY_CRITICAL = "CRITICAL"
SEVERITY_HIGH = "HIGH"
SEVERITY_MEDIUM = "MEDIUM"
SEVERITY_LOW = "LOW"
SEVERITY_INFO = "INFO"

# Yaygın saldırı imzaları için regex tanımlamaları
SQLI_REGEX = re.compile(
    r"(union\s+select|select\s+.*\s+from|insert\s+into|update\s+.*\s+set|delete\s+from|or\s+\d+=\d+|'\s*or\s*'\d+'\s*=\s*'\d+)",
    re.IGNORECASE
)
XSS_REGEX = re.compile(
    r"(<script|onerror\s*=|onload\s*=|<iframe|javascript:|alert\()",
    re.IGNORECASE
)
PATH_TRAVERSAL_REGEX = re.compile(
    r"(\.\./|\.\.\\|/etc/passwd|/etc/shadow|win\.ini|boot\.ini)",
    re.IGNORECASE
)
SUSPICIOUS_UA_REGEX = re.compile(
    r"(sqlmap|nmap|nikto|dirbuster|gobuster|w3af|hydra|acunetix|nessus)",
    re.IGNORECASE
)

# Zararlı/Şüpheli kabul edilen portlar ve açıklamaları
SUSPICIOUS_PORTS = {
    4444: ("Metasploit / Ters Bağlantı (Reverse Shell)", SEVERITY_HIGH),
    6667: ("IRC Protokolü (Potansiyel Botnet C2 İletişimi)", SEVERITY_MEDIUM),
    23: ("Telnet Açık Metin İletişimi (Güvensiz Protokol)", SEVERITY_MEDIUM),
    21: ("FTP Açık Metin İletişimi (Güvensiz Protokol)", SEVERITY_LOW),
    69: ("TFTP Açık Metin İletişimi (Güvensiz Protokol)", SEVERITY_LOW),
    31337: ("Back Orifice / Eski Trojan Portu", SEVERITY_HIGH),
}

# Şifre alanlarını yakalamak için anahtar kelimeler
PASSWORD_KEYWORDS = re.compile(
    r"(password|passwd|user_password|pass|sifre|şifre|token|api_key|secret)\s*=\s*([^&]+)",
    re.IGNORECASE
)


class SecurityAlert:
    """Tespit edilen bir tehdide ait alarm verisi sınıfı."""

    def __init__(self, severity, title, description, src_ip="-", dst_ip="-", proto="-", packet_index=None):
        self.severity = severity
        self.title = title
        self.description = description
        self.src_ip = src_ip
        self.dst_ip = dst_ip
        self.proto = proto
        self.packet_index = packet_index

    def to_dict(self):
        return {
            "severity": self.severity,
            "title": self.title,
            "description": self.description,
            "src_ip": self.src_ip,
            "dst_ip": self.dst_ip,
            "proto": self.proto,
            "packet_index": self.packet_index
        }

    def __str__(self):
        prefix = f"[{self.severity}]"
        pkt_info = f" (Paket #{self.packet_index})" if self.packet_index else ""
        return f"{prefix} {self.title} | {self.src_ip} -> {self.dst_ip} ({self.proto}){pkt_info}: {self.description}"


class SecurityRuleEngine:
    """Paketleri analiz eden ve güvenlik kurallarını işleten ana motor."""

    def __init__(self, port_scan_threshold=15, flood_threshold_pps=50):
        self.port_scan_threshold = port_scan_threshold
        self.flood_threshold_pps = flood_threshold_pps
        
        # State verileri (Paketler arası analiz için)
        self.arp_table = {}  # IP -> MAC mapping
        self.dst_ports_by_src = defaultdict(set)  # src_ip -> set(dst_ports)
        self.packet_times_by_src = defaultdict(list)  # src_ip -> list(timestamps)
        self.syn_times_by_src = defaultdict(list)  # src_ip -> list(timestamps)
        
        # Tespit edilen alarmlar
        self.alerts = []

    def analyze_packet(self, index, packet):
        """Tek bir paketi analiz eder ve yakalanan alarmları listeler."""
        packet_alerts = []

        # 1. ARP Spoofing / Poisoning Tespiti
        if ARP in packet:
            arp = packet[ARP]
            # op = 2 (is-at / ARP yanıtı)
            if arp.op == 2:
                ip_src = arp.psrc
                mac_src = arp.hwsrc
                if ip_src in self.arp_table and self.arp_table[ip_src] != mac_src:
                    alert = SecurityAlert(
                        severity=SEVERITY_CRITICAL,
                        title="ARP Spoofing / Poisoning Tespiti",
                        description=f"Aynı IP ({ip_src}) farklı MAC adresleriyle eşleşti! Önceki MAC: {self.arp_table[ip_src]}, Yeni MAC: {mac_src}",
                        src_ip=ip_src,
                        proto="ARP",
                        packet_index=index
                    )
                    packet_alerts.append(alert)
                else:
                    self.arp_table[ip_src] = mac_src

        # IP Katmanı Analizleri
        if IP in packet:
            ip_layer = packet[IP]
            src_ip = ip_layer.src
            dst_ip = ip_layer.dst
            
            # Paket zaman damgası (varsayılan olarak epoch saniye)
            pkt_time = float(packet.time) if packet.time else None

            # 2. DoS / Flood Tespiti (Canlı capture ve zaman damgası olan pcap'ler için)
            if pkt_time:
                # Genel trafik flood tespiti
                self.packet_times_by_src[src_ip].append(pkt_time)
                # Son 1 saniyedeki paketleri filtrele
                recent_packets = [t for t in self.packet_times_by_src[src_ip] if pkt_time - t <= 1.0]
                self.packet_times_by_src[src_ip] = recent_packets
                if len(recent_packets) >= self.flood_threshold_pps:
                    # Saniyede threshold'dan fazla paket göndermişse
                    # Çok sık alarm vermemek için her 50 pakette bir alarm üretelim
                    if len(recent_packets) % 25 == 0:
                        alert = SecurityAlert(
                            severity=SEVERITY_HIGH,
                            title="DoS / Trafik Flood Saldırı Şüphesi",
                            description=f"Kaynak IP saniyede {len(recent_packets)} paket gönderiyor! (Limit: {self.flood_threshold_pps})",
                            src_ip=src_ip,
                            dst_ip=dst_ip,
                            proto="IP",
                            packet_index=index
                        )
                        packet_alerts.append(alert)

            # TCP Analizleri
            if TCP in packet:
                tcp_layer = packet[TCP]
                dst_port = tcp_layer.dport
                
                # SYN Flood Tespiti
                if pkt_time and tcp_layer.flags == "S":  # Yalnızca SYN bayrağı set edilmişse
                    self.syn_times_by_src[src_ip].append(pkt_time)
                    recent_syns = [t for t in self.syn_times_by_src[src_ip] if pkt_time - t <= 1.0]
                    self.syn_times_by_src[src_ip] = recent_syns
                    if len(recent_syns) >= 15:  # Saniyede 15+ SYN paketi
                        if len(recent_syns) % 10 == 0:
                            alert = SecurityAlert(
                                severity=SEVERITY_HIGH,
                                title="SYN Flood (Hizmet Dışı Bırakma) Şüphesi",
                                description=f"Kaynak IP saniyede {len(recent_syns)} TCP SYN paketi gönderiyor!",
                                src_ip=src_ip,
                                dst_ip=dst_ip,
                                proto="TCP",
                                packet_index=index
                            )
                            packet_alerts.append(alert)

                # Port Tarama Tespiti için port kaydı
                self.dst_ports_by_src[src_ip].add(dst_port)

                # 3. Şüpheli Port Analizleri
                if dst_port in SUSPICIOUS_PORTS:
                    explanation, severity = SUSPICIOUS_PORTS[dst_port]
                    alert = SecurityAlert(
                        severity=severity,
                        title="Şüpheli/Güvensiz Port İletişimi",
                        description=f"Hedef port {dst_port} üzerinde iletişim kuruldu. Açıklama: {explanation}",
                        src_ip=src_ip,
                        dst_ip=dst_ip,
                        proto="TCP",
                        packet_index=index
                    )
                    packet_alerts.append(alert)

                # 4. HTTP Payload Güvenlik Analizi
                if packet.haslayer(HTTPRequest):
                    req = packet[HTTPRequest]
                    path_raw = req.Path.decode(errors="replace") if req.Path else ""
                    path = unquote(path_raw)
                    host = req.Host.decode(errors="replace") if req.Host else ""
                    user_agent = ""
                    
                    # HTTP Header'larını çıkaralım
                    headers_raw = bytes(req.payload)
                    try:
                        headers_text = headers_raw.decode(errors="replace")
                        for line in headers_text.split("\r\n"):
                            if line.lower().startswith("user-agent:"):
                                user_agent = line.split(":", 1)[1].strip()
                                break
                    except Exception:
                        pass

                    full_uri = f"{host}{path}"

                    # SQL Injection Tespiti
                    if SQLI_REGEX.search(path):
                        alert = SecurityAlert(
                            severity=SEVERITY_HIGH,
                            title="SQL Injection (SQLi) Denemesi",
                            description=f"HTTP istek yolunda SQL enjeksiyon örüntüsü saptandı: {path}",
                            src_ip=src_ip,
                            dst_ip=dst_ip,
                            proto="HTTP",
                            packet_index=index
                        )
                        packet_alerts.append(alert)

                    # XSS Tespiti
                    if XSS_REGEX.search(path):
                        alert = SecurityAlert(
                            severity=SEVERITY_HIGH,
                            title="Cross-Site Scripting (XSS) Denemesi",
                            description=f"HTTP istek yolunda XSS script örüntüsü saptandı: {path}",
                            src_ip=src_ip,
                            dst_ip=dst_ip,
                            proto="HTTP",
                            packet_index=index
                        )
                        packet_alerts.append(alert)

                    # Path Traversal Tespiti
                    if PATH_TRAVERSAL_REGEX.search(path):
                        alert = SecurityAlert(
                            severity=SEVERITY_HIGH,
                            title="Dizin Geçişi (Path Traversal) Denemesi",
                            description=f"HTTP istek yolunda hassas dosya/dizin erişim denemesi: {path}",
                            src_ip=src_ip,
                            dst_ip=dst_ip,
                            proto="HTTP",
                            packet_index=index
                        )
                        packet_alerts.append(alert)

                    # Şüpheli Güvenlik Tarayıcısı Tespiti
                    if user_agent and SUSPICIOUS_UA_REGEX.search(user_agent):
                        alert = SecurityAlert(
                            severity=SEVERITY_MEDIUM,
                            title="Şüpheli Güvenlik Tarayıcısı Tespiti",
                            description=f"Güvenlik tarama aracı algılandı: User-Agent='{user_agent}'",
                            src_ip=src_ip,
                            dst_ip=dst_ip,
                            proto="HTTP",
                            packet_index=index
                        )
                        packet_alerts.append(alert)

                    # HTTP Basic Auth veya Açık Metin Şifre İletimi
                    if "authorization: basic" in headers_text.lower():
                        alert = SecurityAlert(
                            severity=SEVERITY_MEDIUM,
                            title="Açık Metin Kimlik Doğrulama İletimi",
                            description="Şifrelenmemiş HTTP üzerinde Basic Authentication kimlik bilgisi tespit edildi!",
                            src_ip=src_ip,
                            dst_ip=dst_ip,
                            proto="HTTP",
                            packet_index=index
                        )
                        packet_alerts.append(alert)

                # 5. Açık Metin TCP Payload Hassas Veri Tespiti (HTTP POST, FTP vb.)
                try:
                    payload_bytes = bytes(tcp_layer.payload)
                    if payload_bytes:
                        payload_text = payload_bytes.decode(errors="replace")
                        
                        # HTTP POST veya diğer ham verilerde şifre parametresi arama
                        pw_match = PASSWORD_KEYWORDS.search(payload_text)
                        if pw_match:
                            param, value = pw_match.groups()
                            # Sadece HTTP/FTP gibi plaintext veya şüpheli portlarda uyaralım
                            if dst_port in [80, 21, 23, 8080]:
                                alert = SecurityAlert(
                                    severity=SEVERITY_HIGH,
                                    title="Açık Metin Hassas Veri Sızıntısı",
                                    description=f"Şifrelenmemiş kanal üzerinden şifre/veri parametresi gönderildi: '{param}'",
                                    src_ip=src_ip,
                                    dst_ip=dst_ip,
                                    proto="TCP",
                                    packet_index=index
                                )
                                packet_alerts.append(alert)
                        
                        # FTP Açık Şifre Tespiti
                        if dst_port == 21:
                            if payload_text.upper().startswith("USER "):
                                user_val = payload_text.strip().split(" ", 1)[1]
                                alert = SecurityAlert(
                                    severity=SEVERITY_MEDIUM,
                                    title="FTP Kimlik Bilgisi (Kullanıcı Adı)",
                                    description=f"Şifrelenmemiş FTP kullanıcı adı tespit edildi: {user_val}",
                                    src_ip=src_ip,
                                    dst_ip=dst_ip,
                                    proto="FTP",
                                    packet_index=index
                                )
                                packet_alerts.append(alert)
                            elif payload_text.upper().startswith("PASS "):
                                alert = SecurityAlert(
                                    severity=SEVERITY_HIGH,
                                    title="FTP Kimlik Bilgisi (Şifre)",
                                    description="Şifrelenmemiş FTP şifresi (PASS) ağ trafiğinde açıkça tespit edildi!",
                                    src_ip=src_ip,
                                    dst_ip=dst_ip,
                                    proto="FTP",
                                    packet_index=index
                                )
                                packet_alerts.append(alert)
                except Exception:
                    pass

            # UDP Analizleri
            elif UDP in packet:
                udp_layer = packet[UDP]
                dst_port = udp_layer.dport
                self.dst_ports_by_src[src_ip].add(dst_port)

                # Şüpheli Port Analizleri (UDP)
                if dst_port in SUSPICIOUS_PORTS:
                    explanation, severity = SUSPICIOUS_PORTS[dst_port]
                    alert = SecurityAlert(
                        severity=severity,
                        title="Şüpheli/Güvensiz Port İletişimi (UDP)",
                        description=f"Hedef port {dst_port} üzerinde iletişim kuruldu. Açıklama: {explanation}",
                        src_ip=src_ip,
                        dst_ip=dst_ip,
                        proto="UDP",
                        packet_index=index
                    )
                    packet_alerts.append(alert)

        self.alerts.extend(packet_alerts)
        return packet_alerts

    def get_summary_alerts(self):
        """Tüm paketler işlendikten sonra üretilen toplu analiz/stateful alarmlarını döner."""
        summary_alerts = []

        # Port Tarama Analizi
        for src_ip, ports in self.dst_ports_by_src.items():
            if len(ports) >= self.port_scan_threshold:
                alert = SecurityAlert(
                    severity=SEVERITY_HIGH,
                    title="Port Taraması Algılandı",
                    description=f"Kaynak IP adresi kısa süre içerisinde {len(ports)} farklı hedef porta bağlandı. Potansiyel sızma öncesi tarama (Reconnaissance) faaliyeti.",
                    src_ip=src_ip,
                    proto="IP"
                )
                summary_alerts.append(alert)

        return summary_alerts
