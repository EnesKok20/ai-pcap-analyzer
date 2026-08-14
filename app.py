"""AI-PCAP-Analyzer - Flask Web Arayüzü.

PCAP dosyalarını yükleme, interaktif siber güvenlik analizi yapma ve
web arayüzünden doğrudan canlı ağ trafiği yakalama işlemlerini yönetir."""

import os
import tempfile
import json
import base64
import logging
import threading
import time
import socket
from logging.handlers import RotatingFileHandler
from urllib.parse import urlparse
from datetime import datetime

from dotenv import load_dotenv
from flask import Flask, render_template, request, jsonify
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from scapy.all import rdpcap, get_working_ifaces, sniff, PcapWriter

from main import build_flow_stats, format_flow_stats, run_ai_analysis, summarize_packet
from rules import SecurityRuleEngine

load_dotenv()

DEBUG_MODE = os.getenv("FLASK_DEBUG", "false").strip().lower() == "true"

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 50 * 1024 * 1024  # 50 MB üst sınırı
ALLOWED_EXTENSIONS = {".pcap", ".pcapng", ".cap"}

# --- Logging: konsol yerine donen/boyutu sinirli dosya log'u ---
log_handler = RotatingFileHandler(
    os.path.join(os.path.dirname(__file__), "app.log"),
    maxBytes=1_000_000,
    backupCount=3,
    encoding="utf-8",
)
log_handler.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(name)s: %(message)s"))
app.logger.addHandler(log_handler)
app.logger.setLevel(logging.DEBUG if DEBUG_MODE else logging.INFO)

# --- Rate limiting: hassas endpoint'lerin kotu niyetli/hatali istemcilerce
# spamlenmesini (dosya analiz, canli yakalama baslatma, ayar degistirme) onler ---
limiter = Limiter(get_remote_address, app=app, default_limits=["200 per hour"], storage_uri="memory://")

# --- Guvenlik header'lari: XSS/clickjacking/mime-sniffing yuzeyini daraltir.
# Not: bilerek CORS acilmiyor - arayuz ayni origin'den servis edildigi icin
# tarayicilar zaten cross-origin isteklerini varsayilan olarak reddediyor;
# flask-cors eklemek bu korumayi gevsetir, bu yuzden eklenmedi. ---
@app.after_request
def set_security_headers(response):
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
    return response

@app.before_request
def reload_env_vars_on_request():
    load_dotenv(override=True)

@app.errorhandler(500)
def handle_internal_error(e):
    app.logger.exception("Beklenmeyen sunucu hatasi: %s", e)
    if request.path.startswith("/api/"):
        return jsonify({"hata": "Beklenmeyen bir sunucu hatasi olustu."}), 500
    return render_template("index.html", hata="Beklenmeyen bir sunucu hatasi olustu."), 500

# Bulut metadata servisleri: SSRF ile en cok istismar edilen hedefler.
# Ollama'nin bunlarin uzerinde mesru bir sekilde calismasi icin hicbir
# senaryo yok, bu yuzden dogrudan reddediliyor.
BLOCKED_SSRF_HOSTS = {
    "169.254.169.254",  # AWS/GCP/Azure/DigitalOcean metadata
    "metadata.google.internal",
    "metadata.azure.com",
    "100.100.100.200",  # Alibaba Cloud metadata
    "fd00:ec2::254",  # AWS IMDSv2 (IPv6)
}

def is_safe_ollama_url(url):
    """OLLAMA_API_URL kullaniciyla ayarlanabildigi icin (auth yok) sunucunun
    keyfi bir adrese istek atmasini (SSRF) engellemek amaciyla temel bir
    dogrulama yapar. Tam bir SSRF korumasi degildir (LAN'daki mesru Ollama
    sunucularina izin vermek gerekiyor) ama en tehlikeli, hicbir mesru
    kullanim senaryosu olmayan hedefleri (bulut metadata servisleri) ve
    gecersiz semalari (file://, gopher:// vb.) reddeder."""
    try:
        parsed = urlparse(url)
    except ValueError:
        return False
    if parsed.scheme not in ("http", "https"):
        return False
    if not parsed.hostname:
        return False
    return parsed.hostname.lower() not in BLOCKED_SSRF_HOSTS

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
        self.error_msg = None
        
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
        self.error_msg = None
        self.packets = []
        self.alerts = []
        self.ai_report = None
        self.stats = None
        
        from main import FlowStatsAccumulator
        self.accumulator = FlowStatsAccumulator()
        self.rule_engine = SecurityRuleEngine()
        
        with tempfile.NamedTemporaryFile(suffix=".pcap", delete=False) as tmp:
            self.temp_pcap_path = tmp.name
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
            self.error_msg = str(e)
            app.logger.exception("Canlı capture sırasında hata oluştu: %s", e)
        finally:
            self.is_running = False
            if self.pcap_writer:
                self.pcap_writer.close()

            # Ham pcap dosyası (şifresiz gerçek trafik içerebilir) sadece yazım
            # sırasında gerekli; hiçbir yerde okunmuyor, bu yüzden diskte
            # kalıcı olarak sızıntı riski oluşturmaması için hemen siliniyor.
            if self.temp_pcap_path and os.path.exists(self.temp_pcap_path):
                try:
                    os.remove(self.temp_pcap_path)
                except OSError as cleanup_err:
                    app.logger.warning("Geçici pcap dosyası silinemedi (%s): %s", self.temp_pcap_path, cleanup_err)
                finally:
                    self.temp_pcap_path = None

            # Eğer hiç paket yakalanamadıysa ve henüz bir hata atanmadıysa teşhis uyarısı ekle
            if self.packet_count == 0 and not self.error_msg:
                self.error_msg = (
                    f"Seçilen ağ kartında ('{self.interface or 'Varsayılan'}') hiç paket yakalanamadı. "
                    "Lütfen internet trafiğinizin geçtiği aktif Wi-Fi veya Ethernet kartını "
                    "doğru seçtiğinizden emin olun."
                )
            
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
            "interface": self.interface,
            "error": self.error_msg
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
        data_json=payload,
    )

@app.route("/analiz", methods=["POST"])
@limiter.limit("10 per minute")
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
        app.logger.exception("PCAP dosyasi okunamadi: %s", exc)
        return render_template("index.html", hata="Dosya okunamadı. Geçerli bir .pcap/.pcapng/.cap dosyası yüklediğinizden emin olun.")
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
        data_json=payload,
    )

# --- Sistem Yapılandırma (Settings) API Endpoint'leri ---

@app.route("/api/settings", methods=["GET"])
@limiter.limit("30 per minute")
def get_settings():
    try:
        claude_key = os.getenv("ANTHROPIC_API_KEY", "")
        gemini_key = os.getenv("GEMINI_API_KEY", "")
        
        masked_claude = ""
        if claude_key:
            if len(claude_key) > 12:
                masked_claude = f"{claude_key[:7]}...{claude_key[-4:]}"
            else:
                masked_claude = "********"
                
        masked_gemini = ""
        if gemini_key:
            if len(gemini_key) > 12:
                masked_gemini = f"{gemini_key[:7]}...{gemini_key[-4:]}"
            else:
                masked_gemini = "********"
                
        return jsonify({
            "claude_key": masked_claude,
            "gemini_key": masked_gemini,
            "ollama_url": os.getenv("OLLAMA_API_URL", "http://localhost:11434/api/chat"),
            "ollama_model": os.getenv("OLLAMA_MODEL", "llama3")
        })
    except Exception as e:
        app.logger.exception("Ayarlar okunamadi: %s", e)
        return jsonify({"hata": "Ayarlar okunamadı."}), 500

@app.route("/api/settings", methods=["POST"])
@limiter.limit("10 per minute")
def save_settings():
    try:
        data = request.json or {}
        claude_key = data.get("claude_key", "").strip()
        gemini_key = data.get("gemini_key", "").strip()
        ollama_url = data.get("ollama_url", "").strip()
        ollama_model = data.get("ollama_model", "").strip()

        if ollama_url and not is_safe_ollama_url(ollama_url):
            return jsonify({
                "status": "error",
                "message": "Geçersiz OLLAMA_API_URL: sadece http/https adresleri kabul edilir ve bulut metadata servisleri hedeflenemez."
            }), 400

        env_path = os.path.join(os.path.dirname(__file__), ".env")
        
        env_data = {}
        if os.path.exists(env_path):
            with open(env_path, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith("#") and "=" in line:
                        k, v = line.split("=", 1)
                        env_data[k.strip()] = v.strip()
                        
        if claude_key and "..." not in claude_key and "*" not in claude_key:
            env_data["ANTHROPIC_API_KEY"] = claude_key
        elif claude_key == "":
            env_data["ANTHROPIC_API_KEY"] = ""
            
        if gemini_key and "..." not in gemini_key and "*" not in gemini_key:
            env_data["GEMINI_API_KEY"] = gemini_key
        elif gemini_key == "":
            env_data["GEMINI_API_KEY"] = ""
            
        if ollama_url:
            env_data["OLLAMA_API_URL"] = ollama_url
        if ollama_model:
            env_data["OLLAMA_MODEL"] = ollama_model
            
        with open(env_path, "w", encoding="utf-8") as f:
            f.write("# AI-PCAP-Analyzer Konfigurasyon Dosyasi\n")
            for k, v in env_data.items():
                f.write(f"{k}={v}\n")

        # API anahtarlari duz metin sakliyor; en azindan dosyayi ayni kullanici
        # disinda kimsenin okuyamayacagi sekilde kisitla (POSIX'te etkili,
        # Windows'ta sessizce yok sayilir).
        try:
            os.chmod(env_path, 0o600)
        except OSError:
            pass

        load_dotenv(override=True)
        if "ANTHROPIC_API_KEY" in env_data:
            os.environ["ANTHROPIC_API_KEY"] = env_data["ANTHROPIC_API_KEY"]
        if "GEMINI_API_KEY" in env_data:
            os.environ["GEMINI_API_KEY"] = env_data["GEMINI_API_KEY"]
        if "OLLAMA_API_URL" in env_data:
            os.environ["OLLAMA_API_URL"] = env_data["OLLAMA_API_URL"]
        if "OLLAMA_MODEL" in env_data:
            os.environ["OLLAMA_MODEL"] = env_data["OLLAMA_MODEL"]
            
        return jsonify({"status": "success", "message": "Ayarlar başarıyla kaydedildi ve uygulandı."})
    except Exception as e:
        app.logger.exception("Ayarlar kaydedilemedi: %s", e)
        return jsonify({"status": "error", "message": "Ayarlar kaydedilemedi."}), 500

# --- Canlı Paket Yakalama API Endpoint'leri ---

@app.route("/api/interfaces", methods=["GET"])
def get_interfaces():
    try:
        # Aktif internet çıkışı yapan yerel IP'yi tespit edelim
        active_ip = None
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            active_ip = s.getsockname()[0]
            s.close()
        except Exception:
            pass

        interfaces = []
        for iface in get_working_ifaces():
            ip_addr = getattr(iface, "ip", None)
            is_active = (ip_addr and ip_addr == active_ip)
            
            # Ağ kartı tipine göre simge ve açıklama hazırlayalım
            name_lower = iface.name.lower() if iface.name else ""
            desc_lower = iface.description.lower() if iface.description else ""
            
            if is_active:
                prefix = "📶 [TAVSİYE EDİLEN - AKTİF İNTERNET]"
            elif "wi-fi" in name_lower or "wireless" in name_lower or "wlan" in name_lower or "wi-fi" in desc_lower:
                prefix = "📶 Wi-Fi"
            elif "ethernet" in name_lower or "lan" in name_lower or "ethernet" in desc_lower:
                prefix = "🔌 Ethernet"
            elif "loopback" in name_lower or "loopback" in desc_lower or "software" in desc_lower:
                prefix = "🔄 Loopback (İç Trafik)"
            else:
                prefix = "🌐 Ağ Kartı"

            friendly_desc = f"{prefix} - {iface.name}"
            if iface.description and iface.description != iface.name:
                friendly_desc += f" ({iface.description})"
            if ip_addr and ip_addr != "0.0.0.0":
                friendly_desc += f" [IP: {ip_addr}]"

            interfaces.append({
                "name": iface.network_name,
                "description": friendly_desc,
                "is_active": is_active
            })

        # Öncelik sıralaması: Aktif internet > Wi-Fi/Ethernet > Diğer / Sanal > Loopback
        def get_sort_score(item):
            if item["is_active"]:
                return 0
            desc = item["description"]
            if "📶 Wi-Fi" in desc or "🔌 Ethernet" in desc:
                return 1
            if "🔄 Loopback" in desc:
                return 3
            return 2

        interfaces.sort(key=get_sort_score)
        return jsonify(interfaces)
    except Exception as e:
        app.logger.exception("Ag kartlari listelenemedi: %s", e)
        return jsonify({"hata": "Ağ kartları listelenemedi."}), 500

@app.route("/api/capture/start", methods=["POST"])
@limiter.limit("10 per minute")
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
    host = os.getenv("FLASK_HOST", "127.0.0.1")
    port = int(os.getenv("FLASK_PORT", "5000"))

    # HTTPS: bu araç localhost'ta çalışacak şekilde tasarlandı; gerçek bir
    # production dağıtımında TLS'i nginx/caddy gibi bir reverse proxy
    # üstlenmeli. Yine de doğrudan Flask üzerinden HTTPS test etmek
    # isteyenler için .env'e SSL_CERT_PATH/SSL_KEY_PATH tanımlanabilir.
    ssl_context = None
    cert_path = os.getenv("SSL_CERT_PATH")
    key_path = os.getenv("SSL_KEY_PATH")
    if cert_path and key_path:
        ssl_context = (cert_path, key_path)

    if DEBUG_MODE:
        app.logger.warning("FLASK_DEBUG=true - hata ayiklayici acik, sadece yerel gelistirmede kullanin.")

    app.run(debug=DEBUG_MODE, host=host, port=port, ssl_context=ssl_context)
