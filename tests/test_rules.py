"""rules.py kural motoru için pytest test paketi."""

import pytest
from scapy.all import IP, TCP, UDP, ARP, Raw
from scapy.layers.http import HTTPRequest
from rules import SecurityRuleEngine, SEVERITY_CRITICAL, SEVERITY_HIGH, SEVERITY_MEDIUM

def _roundtrip(packet):
    """Katman baglamalarinin dogru calismasi icin paketi byte seviyesine
    indirgeyip tekrar IP paketi olarak olusturur."""
    return IP(bytes(packet))

class TestSecurityRuleEngine:
    def test_arp_spoofing_tespit_ediliyor(self):
        engine = SecurityRuleEngine()
        
        # 1. Normal ARP eşleşmesi (IP 10.0.0.1 -> MAC AA:AA:AA:AA:AA:AA)
        pkt1 = ARP(op=2, psrc="10.0.0.1", hwsrc="AA:AA:AA:AA:AA:AA")
        alerts1 = engine.analyze_packet(1, pkt1)
        assert len(alerts1) == 0
        
        # 2. Değişen ARP eşleşmesi (IP 10.0.0.1 -> MAC BB:BB:BB:BB:BB:BB) - Saldırı şüphesi
        pkt2 = ARP(op=2, psrc="10.0.0.1", hwsrc="BB:BB:BB:BB:BB:BB")
        alerts2 = engine.analyze_packet(2, pkt2)
        assert len(alerts2) == 1
        assert alerts2[0].severity == SEVERITY_CRITICAL
        assert "ARP Spoofing" in alerts2[0].title

    def test_suspicious_port_tespit_ediliyor(self):
        engine = SecurityRuleEngine()
        
        # Metasploit portu (4444)
        pkt = IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=1234, dport=4444)
        alerts = engine.analyze_packet(1, pkt)
        assert len(alerts) == 1
        assert alerts[0].severity == SEVERITY_HIGH
        assert "Şüpheli/Güvensiz Port" in alerts[0].title

    def test_sqli_http_istek_tespit_ediliyor(self):
        engine = SecurityRuleEngine()
        
        # SQL Injection içeren HTTP isteği
        pkt = _roundtrip(
            IP(src="10.0.0.1", dst="10.0.0.2") /
            TCP(sport=1234, dport=80) /
            HTTPRequest(Method=b"GET", Path=b"/product?id=1%20union%20select%20null,username,password%20from%20users")
        )
        alerts = engine.analyze_packet(1, pkt)
        assert len(alerts) == 1
        assert alerts[0].severity == SEVERITY_HIGH
        assert "SQL Injection" in alerts[0].title

    def test_xss_http_istek_tespit_ediliyor(self):
        engine = SecurityRuleEngine()
        
        # XSS içeren HTTP isteği
        pkt = _roundtrip(
            IP(src="10.0.0.1", dst="10.0.0.2") /
            TCP(sport=1234, dport=80) /
            HTTPRequest(Method=b"GET", Path=b"/search?q=<script>alert(1)</script>")
        )
        alerts = engine.analyze_packet(1, pkt)
        assert len(alerts) == 1
        assert alerts[0].severity == SEVERITY_HIGH
        assert "Cross-Site Scripting" in alerts[0].title

    def test_path_traversal_http_istek_tespit_ediliyor(self):
        engine = SecurityRuleEngine()
        
        # Path Traversal içeren HTTP isteği
        pkt = _roundtrip(
            IP(src="10.0.0.1", dst="10.0.0.2") /
            TCP(sport=1234, dport=80) /
            HTTPRequest(Method=b"GET", Path=b"/view?file=../../../../etc/passwd")
        )
        alerts = engine.analyze_packet(1, pkt)
        assert len(alerts) == 1
        assert alerts[0].severity == SEVERITY_HIGH
        assert "Dizin Geçişi" in alerts[0].title

    def test_suspicious_user_agent_tespit_ediliyor(self):
        engine = SecurityRuleEngine()
        
        # SQLMap User-Agent'lı HTTP isteği
        pkt = _roundtrip(
            IP(src="10.0.0.1", dst="10.0.0.2") /
            TCP(sport=1234, dport=80) /
            HTTPRequest(Method=b"GET", Path=b"/index.php") /
            Raw(b"GET /index.php HTTP/1.1\r\nUser-Agent: sqlmap/1.4.12#stable (http://sqlmap.org)\r\n\r\n")
        )
        
        alerts = engine.analyze_packet(1, pkt)
        assert len(alerts) == 1
        assert alerts[0].severity == SEVERITY_MEDIUM
        assert "Güvenlik Tarayıcısı" in alerts[0].title

    def test_cleartext_credential_sızıntısı_tespit_ediliyor(self):
        engine = SecurityRuleEngine()
        
        # Şifrelenmemiş HTTP POST verisi içeren TCP paketi
        pkt = _roundtrip(
            IP(src="10.0.0.1", dst="10.0.0.2") / 
            TCP(sport=1234, dport=80) /
            Raw(b"POST /login HTTP/1.1\r\nContent-Length: 30\r\n\r\nusername=admin&password=verysecret123")
        )
        
        alerts = engine.analyze_packet(1, pkt)
        assert len(alerts) == 1
        assert alerts[0].severity == SEVERITY_HIGH
        assert "Kimlik Bilgisi" in alerts[0].title or "Hassas Veri Sızıntısı" in alerts[0].title

    def test_port_scan_toplu_tespit_ediliyor(self):
        engine = SecurityRuleEngine()
        
        # Eşik değeri aşacak şekilde farklı portlara istek atılması
        # default threshold = 15
        for port in range(1, 20):
            pkt = IP(src="10.0.0.10", dst="10.0.0.2") / TCP(sport=5000, dport=port)
            engine.analyze_packet(port, pkt)
            
        summary_alerts = engine.get_summary_alerts()
        assert len(summary_alerts) == 1
        assert summary_alerts[0].severity == SEVERITY_HIGH
        assert "Port Taraması Algılandı" in summary_alerts[0].title
        assert summary_alerts[0].src_ip == "10.0.0.10"
