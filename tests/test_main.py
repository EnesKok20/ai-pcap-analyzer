"""main.py icin pytest test paketi: paket ozetleme, protokol cikarimlari
(ARP/DNS/HTTP/TLS) ve akis bazli trafik istatistikleri."""

from pathlib import Path

import pytest
from scapy.all import IP, TCP, UDP, Ether
from scapy.layers.dns import DNS, DNSQR, DNSRR
from scapy.layers.http import HTTPRequest, HTTPResponse
from scapy.layers.l2 import ARP
from scapy.layers.tls.all import TLS
from scapy.layers.tls.extensions import TLS_Ext_ServerName
from scapy.layers.tls.handshake import TLSClientHello

from main import (
    PORT_SCAN_THRESHOLD,
    analyze_pcap,
    build_flow_stats,
    format_flow_stats,
    summarize_packet,
)


def _roundtrip(packet):
    """Paketi ham byte'lara cevirip yeniden ayristirir; gercek bir pcap
    dosyasindan okumayi simule eder (katman baglamalarinin devreye
    girmesi icin gereklidir)."""
    return IP(bytes(packet))


class TestSummarizePacketTemel:
    def test_tcp_paketi(self):
        pkt = IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=1234, dport=80)
        assert summarize_packet(1, pkt) == "[1] TCP  10.0.0.1:1234 -> 10.0.0.2:80"

    def test_udp_paketi(self):
        pkt = IP(src="10.0.0.1", dst="10.0.0.2") / UDP(sport=5000, dport=53)
        result = summarize_packet(1, pkt)
        assert "UDP" in result
        assert "10.0.0.1:5000 -> 10.0.0.2:53" in result

    def test_ip_katmani_olmayan_paket(self):
        result = summarize_packet(1, Ether())
        assert "IP katmani yok" in result

    def test_arp_paketi(self):
        pkt = ARP(op=1, psrc="10.0.0.5", pdst="10.0.0.1")
        assert summarize_packet(1, pkt) == "[1] ARP  10.0.0.5 who-has 10.0.0.1"


class TestSummarizePacketProtokolDetaylari:
    def test_dns_sorgu(self):
        pkt = _roundtrip(IP() / UDP(dport=53) / DNS(rd=1, qd=DNSQR(qname="ornek.com")))
        assert "DNS sorgu: ornek.com" in summarize_packet(1, pkt)

    def test_dns_yanit(self):
        pkt = _roundtrip(
            IP()
            / UDP(sport=53)
            / DNS(qr=1, qd=DNSQR(qname="ornek.com"), an=DNSRR(rrname="ornek.com", rdata="1.2.3.4"))
        )
        assert "DNS yanit: ornek.com -> 1.2.3.4" in summarize_packet(1, pkt)

    def test_http_istek(self):
        pkt = _roundtrip(
            IP() / TCP(dport=80) / HTTPRequest(Method=b"GET", Path=b"/gizli", Host=b"sirket.com")
        )
        assert "HTTP istek: GET sirket.com/gizli" in summarize_packet(1, pkt)

    def test_http_yanit(self):
        pkt = _roundtrip(IP() / TCP(sport=80) / HTTPResponse(Status_Code=b"200", Reason_Phrase=b"OK"))
        assert "HTTP yanit: 200 OK" in summarize_packet(1, pkt)

    def test_tls_client_hello_sni(self):
        sni_ext = TLS_Ext_ServerName(servernames=[b"guvenli.com"])
        client_hello = TLSClientHello(ext=[sni_ext])
        pkt = _roundtrip(IP() / TCP(dport=443) / TLS(msg=[client_hello]))
        assert "TLS ClientHello" in summarize_packet(1, pkt)


class TestFlowStats:
    @staticmethod
    def _port_scan_paketleri(count, src="10.0.0.9", dst="10.0.0.50"):
        return [IP(src=src, dst=dst) / TCP(sport=44000, dport=port) for port in range(1, count + 1)]

    def test_protokol_ve_konusan_ip_sayaclari(self):
        packets = [
            IP(src="10.0.0.1", dst="10.0.0.2") / TCP(dport=80),
            IP(src="10.0.0.1", dst="10.0.0.2") / UDP(dport=53),
        ]
        stats = build_flow_stats(packets)
        assert stats["protocol_counts"]["TCP"] == 1
        assert stats["protocol_counts"]["UDP"] == 1
        assert stats["talker_counts"]["10.0.0.1"] == 2

    def test_port_taramasi_tespit_ediliyor(self):
        stats = build_flow_stats(self._port_scan_paketleri(PORT_SCAN_THRESHOLD))
        assert "10.0.0.9" in stats["scan_suspects"]

    def test_esik_altinda_yanlis_pozitif_yok(self):
        stats = build_flow_stats(self._port_scan_paketleri(PORT_SCAN_THRESHOLD - 1))
        assert "10.0.0.9" not in stats["scan_suspects"]

    def test_format_flow_stats_bolumleri_iceriyor(self):
        stats = build_flow_stats(self._port_scan_paketleri(PORT_SCAN_THRESHOLD))
        text = format_flow_stats(stats)
        assert "Trafik Ozeti" in text
        assert "Protokol dagilimi" in text
        assert "Olasi port taramasi" in text


class TestAnalyzePcap:
    def test_olmayan_dosya_cikis_kodu_1_ile_sonlanir(self, capsys):
        with pytest.raises(SystemExit) as exc_info:
            analyze_pcap("bu_dosya_yok.pcap")
        assert exc_info.value.code == 1
        assert "bulunamadi" in capsys.readouterr().out

    def test_gercek_pcap_dosyasi_cokmeden_calisir(self, capsys):
        # Depoya dahil edilmeyen (.gitignore) yerel test.pcap varsa, gercek
        # (kismen bozuk/fuzz edilmis) veri uzerinde de dogrulama yapilir.
        pcap_path = Path(__file__).resolve().parent.parent / "test.pcap"
        if not pcap_path.exists():
            pytest.skip("Yerel test.pcap bulunamadi, atlaniyor.")

        analyze_pcap(str(pcap_path))
        output = capsys.readouterr().out
        assert "paket bulundu" in output
        assert "Trafik Ozeti" in output
