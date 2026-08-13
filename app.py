"""AI-PCAP-Analyzer - Flask Web Arayüzü.

PCAP dosyalarını yükleme, interaktif siber güvenlik analizi yapma ve
web arayüzünden doğrudan canlı ağ trafiği yakalama işlemlerini yönetir."""

import os
import tempfile
import json
import threading
import time
from datetime import datetime

from dotenv import load_dotenv
from flask import Flask, render_template, request, jsonify
from scapy.all import rdpcap, get_working_ifaces, sniff, PcapWriter

from main import build_flow_stats, format_flow_stats, run_ai_analysis, summarize_packet
from rules import SecurityRuleEngine

load_dotenv()

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 50 * 1024 * 1024  # 50 MB üst sınırı
ALLOWED_EXTENSIONS = {".pcap", ".pcapng", ".cap"}

def serialize_stats(stats):
    """Scapy Counter nesnelerini JSON formatına dönüştürür."""
    return {
        "protocol_counts": dict(stats["protocol_counts"]),
        "talker_counts": dict(stats["talker_counts"]),
        "port_counts": {f"{proto}/{port}": count for (proto, port), count in stats["port_counts"].items()},
        "flow_count": stats["flow_count"],
        "scan_suspects": {ip: list(ports) for ip, ports in stats["scan_suspects"].items()}
    }

class CaptureManager:
    """Canlı paket yakalama işlemini arka planda bir thread olarak yönetir."""

    def __init__(self):
        self.thread = None
        self.stop_event = threading.Event()
        self.is_running = False
        
        self.interface = None
        self.duration = None
        self.use_ai = False
        self.ai_provider = "claude"
        self.start_time = None
        self.packet_count = 0
        
        self.packets = []
        self.stats = None
        self.alerts = []
        self.ai_report = None
        self.temp_pcap_path = None
        self.pcap_writer = None
        
        self.accumulator = None
        self.rule_engine = None

    def start(self, interface, duration_seconds, use_ai=False, ai_provider="claude"):
        if self.is_running:
            return False
            
        self.is_running = True
        self.stop_event.clear()
        
        self.interface = interface
        self.duration = duration_seconds
        self.use_ai = use_ai
        self.ai_provider = ai_provider
        self.start_time = time.time()
        self.packet_count = 0
        self.packets = []
        self.alerts = []
        self.ai_report = None
        self.stats = None
        
        from main import FlowStatsAccumulator
        self.accumulator = FlowStatsAccumulator()
        self.rule_engine = SecurityRuleEngine()
        
        self.temp_pcap_path = tempfile.mktemp(suffix=".pcap")
        self.pcap_writer = PcapWriter(self.temp_pcap_path, append=True, sync=True)
        
        self.thread = threading.Thread(target=self._run_sniff)
        self.thread.daemon = True
        self.thread.start()
        return True

    def _run_sniff(self):
        def on_packet(packet):
            self.packet_count += 1
            self.accumulator.add(packet)
            if self.pcap_writer:
                self.pcap_writer.write(packet)
            
            # Paket özetleme ve kural analizini yap
            pkt_summary = summarize_packet(self.packet_count, packet)
            self.packets.append(pkt_summary)
            
            packet_alerts = self.rule_engine.analyze_packet(self.packet_count, packet)
            for alert in packet_alerts:
                self.alerts.append(alert.to_dict())

        try:
            # Sniff işlemi
            sniff(
                prn=on_packet,
                store=False,
                iface=self.interface if self.interface else None,
                stop_filter=lambda p: self.stop_event.is_set(),
                timeout=self.duration if self.duration else None
            )
        except Exception as e:
            print(f"Canlı capture sırasında hata oluştu: {e}")
        finally:
            self.is_running = False
            if self.pcap_writer:
                self.pcap_writer.close()
            
            # Toplu analizleri derle
            raw_stats = self.accumulator.as_stats()
            self.stats = serialize_stats(raw_stats)
            
            summary_alerts = self.rule_engine.get_summary_alerts()
            for alert in summary_alerts:
                self.alerts.append(alert.to_dict())
                
            if self.use_ai and self.packet_count > 0:
                stats_text = format_flow_stats(raw_stats)
                alerts_text = "\n".join([f"[{a['severity']}] {a['title']}: {a['description']}" for a in self.alerts])
                self.ai_report = run_ai_analysis(self.packets, stats_text, alerts_text, provider=self.ai_provider)

    def stop(self):
        if not self.is_running:
            return False
        self.stop_event.set()
        if self.thread:
            self.thread.join(timeout=3)
        return True

    def get_status(self):
        elapsed = 0
        if self.is_running and self.start_time:
            elapsed = time.time() - self.start_time
            
        return {
            "is_running": self.is_running,
            "packet_count": self.packet_count,
            "elapsed": round(elapsed, 1),
            "duration": self.duration,
            "interface": self.interface
        }

    def get_result_payload(self):
        if self.is_running:
            return None
            
        return {
            "dosya_adi": f"Canlı Ağ Yakalama ({self.interface or 'Varsayılan Arayüz'})",
            "paket_sayisi": self.packet_count,
            "stats": self.stats,
            "alerts": self.alerts,
            "packets": [{"index": i, "summary": s} for i, s in enumerate(self.packets, start=1)],
            "ai_report": self.ai_report,
            "use_ai": self.use_ai
        }

capture_manager = CaptureManager()

@app.route("/", methods=["GET"])
def index():
    return render_template("index.html")

@app.route("/live-sonuc", methods=["GET"])
def live_sonuc():
    payload = capture_manager.get_result_payload()
    if payload is None:
        return render_template("index.html", hata="Aktif canlı yakalama verisi bulunamadı.")
        
    return render_template(
        "results.html",
        dosya_adi=payload["dosya_adi"],
        paket_sayisi=payload["paket_sayisi"],
        data_json=json.dumps(payload),
    )

@app.route("/analiz", methods=["POST"])
def analiz():
    uploaded = request.files.get("pcap_file")
    if uploaded is None or uploaded.filename == "":
        return render_template("index.html", hata="Önce bir pcap dosyası seçmelisin.")

    _, ext = os.path.splitext(uploaded.filename)
    if ext.lower() not in ALLOWED_EXTENSIONS:
        return render_template(
            "index.html",
            hata=(
                f"Desteklenmeyen dosya türü: '{ext or '(uzantısız)'}'. "
                f"Desteklenenler: {', '.join(sorted(ALLOWED_EXTENSIONS))}"
            ),
        )

    use_ai = request.form.get("use_ai") == "on"
    ai_provider = request.form.get("ai_provider", "claude")

    with tempfile.NamedTemporaryFile(suffix=ext, delete=False) as tmp:
        uploaded.save(tmp.name)
        tmp_path = tmp.name

    try:
        packets = rdpcap(tmp_path)
    except Exception as exc:
        return render_template("index.html", hata=f"Dosya okunamadı: {exc}")
    finally:
        os.unlink(tmp_path)

    # Güvenlik Kural Motorunu ve İstatistikleri Çalıştır
    engine = SecurityRuleEngine()
    summaries = []
    alerts = []

    for index, packet in enumerate(packets, start=1):
        summary = summarize_packet(index, packet)
        summaries.append(summary)
        
        # Anlık kuralları işlet
        packet_alerts = engine.analyze_packet(index, packet)
        for alert in packet_alerts:
            alerts.append(alert.to_dict())

    # Toplu kuralları işlet
    summary_alerts = engine.get_summary_alerts()
    for alert in summary_alerts:
        alerts.append(alert.to_dict())

    raw_stats = build_flow_stats(packets)
    stats_text = format_flow_stats(raw_stats)
    serialized_stats = serialize_stats(raw_stats)

    alerts_text = "\n".join([f"[{a['severity']}] {a['title']}: {a['description']}" for a in alerts])
    ai_report = run_ai_analysis(summaries, stats_text, alerts_text, provider=ai_provider) if use_ai else None

    # Front-end'e aktarmak üzere tüm verileri JSON olarak paketleyelim
    payload = {
        "dosya_adi": uploaded.filename,
        "paket_sayisi": len(packets),
        "stats": serialized_stats,
        "alerts": alerts,
        "packets": [{"index": i, "summary": s} for i, s in enumerate(summaries, start=1)],
        "ai_report": ai_report,
        "use_ai": use_ai,
    }

    return render_template(
        "results.html",
        dosya_adi=uploaded.filename,
        paket_sayisi=len(packets),
        data_json=json.dumps(payload),
    )

# --- Canlı Paket Yakalama API Endpoint'leri ---

@app.route("/api/interfaces", methods=["GET"])
def get_interfaces():
    try:
        interfaces = []
        for iface in get_working_ifaces():
            interfaces.append({
                "name": iface.network_name,
                "description": f"{iface.name} ({iface.description or ''})"
            })
        return jsonify(interfaces)
    except Exception as e:
        return jsonify({"hata": str(e)}), 500

@app.route("/api/capture/start", methods=["POST"])
def start_capture():
    data = request.json or {}
    interface = data.get("interface")
    duration = data.get("duration", 60)
    use_ai = data.get("use_ai", False)
    ai_provider = data.get("ai_provider", "claude")
    
    if duration:
        try:
            duration = int(duration)
        except ValueError:
            duration = 60
            
    success = capture_manager.start(interface, duration, use_ai, ai_provider=ai_provider)
    if success:
        return jsonify({"status": "started", "message": "Canlı yakalama başlatıldı."})
    else:
        return jsonify({"status": "error", "message": "Zaten aktif bir canlı yakalama işlemi çalışıyor."}), 400

@app.route("/api/capture/stop", methods=["POST"])
def stop_capture():
    success = capture_manager.stop()
    if success:
        return jsonify({"status": "stopped", "message": "Canlı yakalama durduruldu."})
    else:
        return jsonify({"status": "error", "message": "Çalışan aktif bir canlı yakalama işlemi bulunamadı."}), 400

@app.route("/api/capture/live-data", methods=["GET"])
def get_capture_live_data():
    try:
        last_index = int(request.args.get("last_index", 0))
    except ValueError:
        last_index = 0
        
    status = capture_manager.get_status()
    
    all_packets = capture_manager.packets
    new_packets = []
    if last_index < len(all_packets):
        for idx in range(last_index, len(all_packets)):
            new_packets.append({
                "index": idx + 1,
                "summary": all_packets[idx]
            })
            
    return jsonify({
        "status": status,
        "new_packets": new_packets,
        "alerts": capture_manager.alerts
    })

@app.route("/api/capture/status", methods=["GET"])
def get_capture_status():
    return jsonify(capture_manager.get_status())

@app.route("/api/capture/result", methods=["GET"])
def get_capture_result():
    status = capture_manager.get_status()
    if status["is_running"]:
        return jsonify({"status": "running", "message": "Yakalama hala devam ediyor."}), 400
        
    payload = capture_manager.get_result_payload()
    if payload is None:
        return jsonify({"status": "empty", "message": "Gösterilecek sonuç bulunamadı."}), 404
        
    return jsonify(payload)

if __name__ == "__main__":
    app.run(debug=True)
