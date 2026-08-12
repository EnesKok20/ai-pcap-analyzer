"""AI-PCAP-Analyzer icin basit lokal web arayuzu (Flask).

Kullanici bir .pcap/.pcapng dosyasi yukler; paket ozetleri, trafik ozeti
ve isteğe bagli olarak yapay zeka analizi tarayicida gosterilir. Sadece
yerel kullanim icindir (canli ag yakalama yapmaz, sadece var olan bir
dosyayi analiz eder)."""

import os
import tempfile

from dotenv import load_dotenv
from flask import Flask, render_template, request
from scapy.all import rdpcap

from main import build_flow_stats, format_flow_stats, run_ai_analysis, summarize_packet

load_dotenv()

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 50 * 1024 * 1024  # 50 MB ust siniri

ALLOWED_EXTENSIONS = {".pcap", ".pcapng", ".cap"}


@app.route("/", methods=["GET"])
def index():
    return render_template("index.html")


@app.route("/analiz", methods=["POST"])
def analiz():
    uploaded = request.files.get("pcap_file")
    if uploaded is None or uploaded.filename == "":
        return render_template("index.html", hata="Once bir pcap dosyasi secmelisin.")

    _, ext = os.path.splitext(uploaded.filename)
    if ext.lower() not in ALLOWED_EXTENSIONS:
        return render_template(
            "index.html",
            hata=(
                f"Desteklenmeyen dosya turu: '{ext or '(uzantisiz)'}'. "
                f"Desteklenenler: {', '.join(sorted(ALLOWED_EXTENSIONS))}"
            ),
        )

    use_ai = request.form.get("use_ai") == "on"

    # Guvenlik: gecici dosya adi kullaniciya ait dosya adindan degil,
    # tempfile'in kendi rastgele adindan turetiliyor (path traversal riski yok).
    with tempfile.NamedTemporaryFile(suffix=ext, delete=False) as tmp:
        uploaded.save(tmp.name)
        tmp_path = tmp.name

    try:
        packets = rdpcap(tmp_path)
    except Exception as exc:
        return render_template("index.html", hata=f"Dosya okunamadi: {exc}")
    finally:
        os.unlink(tmp_path)

    summaries = [summarize_packet(index, packet) for index, packet in enumerate(packets, start=1)]
    stats_text = format_flow_stats(build_flow_stats(packets))

    ai_report = run_ai_analysis(summaries, stats_text) if use_ai else None

    return render_template(
        "results.html",
        dosya_adi=uploaded.filename,
        paket_sayisi=len(packets),
        ozet_metni="\n".join(summaries),
        trafik_ozeti=stats_text,
        ai_report=ai_report,
        use_ai=use_ai,
    )


if __name__ == "__main__":
    # Varsayilan olarak sadece localhost'ta dinler (127.0.0.1); disariya acik degildir.
    app.run(debug=True)
