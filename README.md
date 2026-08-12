# 🛡️ AI-PCAP-Analyzer

Üniversitedeki Wireshark ağ analizi ve kriptoloji derslerinde edindiğim teorik temelleri, modern Yapay Zeka teknolojileriyle harmanlayarak gerçek dünya senaryolarında kullanmak üzere geliştirdiğim açık kaynaklı bir ağ trafiği analiz aracı.

Wireshark gibi araçlar ağ trafiğini incelemede müthiş güçlü olsa da, binlerce satırlık paket dökümü arasında kaybolmak yorucu olabiliyor. Bu proje; bir `.pcap` dosyasını (ya da canlı ağ trafiğini) otomatik olarak özetleyip, akış bazlı istatistikler çıkarıp, isteğe bağlı olarak **Claude (Anthropic)** ile şüpheli davranışları doğal dilde yorumlayan pratik bir asistan olmayı hedefliyor.

---

## ✨ Özellikler

- **Protokol ayrıştırma** — IP, TCP, UDP, ARP, DNS (sorgu/yanıt), HTTP (istek/yanıt), TLS (ClientHello SNI)
- **Akış bazlı trafik özeti** — protokol dağılımı, en çok trafiğe karışan IP'ler, en çok hedeflenen portlar
- **Basit port taraması tespiti** — bir kaynak IP kısa sürede çok sayıda farklı porta temas ederse otomatik uyarı
- **Yapay zeka destekli analiz** — `--ai` bayrağıyla paket özetleri ve trafik özeti Claude'a gönderilip Türkçe, insan tarafından okunabilir bir rapor alınır
- **Web arayüzü** — Flask tabanlı, dosya yükle → sonucu tarayıcıda gör
- **Canlı paket yakalama** — `capture.py` ile ağ trafiğini gün boyu arka planda dinleyip, süre dolunca ya da durdurulunca özet rapor üretme
- **Bozuk/eksik paketlere dayanıklı** — hatalı katmanlı paketler programı çökertmeden atlanır
- **Test paketi** — pytest ile ayrıştırma mantığı ve AI entegrasyonu (mock istemciyle) test edilir

---

## 📸 Örnek Çıktı

Bir "fuzzing" PCAP dosyası üzerindeki terminal analiz çıktısı:

![Terminal Çıktısı](assets/01-terminal-udp-analiz-ciktisi.png)

---

## 🛠️ Kullanılan Teknolojiler

- **Python** — çekirdek mantık
- **Scapy** — paket okuma/ayrıştırma (IP, TCP, UDP, ARP, DNS, HTTP, TLS)
- **cryptography** — Scapy'nin TLS katmanı için
- **Anthropic Claude API** — yapay zeka destekli anomali/şüpheli davranış analizi
- **Flask** — web arayüzü
- **pytest** — test paketi
- **python-dotenv** — `.env` ile API anahtarı yönetimi

---

## ⚙️ Kurulum

```bash
# Projeyi klonlayın
git clone https://github.com/EnesKok20/ai-pcap-analyzer.git
cd ai-pcap-analyzer

# Gerekli kütüphaneleri yükleyin
pip install -r requirements.txt
```

Yapay zeka analizini kullanmak için bir [Anthropic API anahtarı](https://console.anthropic.com/settings/keys) gerekir:

```bash
# .env.example dosyasini .env olarak kopyalayin
cp .env.example .env

# .env dosyasini acip ANTHROPIC_API_KEY=... satirina kendi anahtarinizi yazin
```

`.env` dosyası `.gitignore`'dadır, GitHub'a asla gönderilmez.

---

## 🚀 Kullanım

### 1. Komut satırı — var olan bir pcap dosyasını analiz et

```bash
python main.py ornek.pcap
python main.py ornek.pcap --ai   # + yapay zeka yorumu
```

### 2. Web arayüzü — dosya yükle, tarayıcıda gör

```bash
python app.py
```

Ardından tarayıcıda `http://127.0.0.1:5000` adresine gidin, bir `.pcap`/`.pcapng` dosyası seçin, isterseniz "Yapay zeka ile analiz et" kutusunu işaretleyin.

### 3. Canlı yakalama — arka planda çalışıp özet rapor üret

```bash
python capture.py --sure 480 --ai --kaydet-pcap
```

- `--sure DAKIKA` — belirtilen süre sonunda otomatik durur (belirtilmezse `Ctrl+C` ile durdurulur)
- `--ai` — bitince trafiği Claude ile de yorumlatır
- `--kaydet-pcap` — ham paketleri de bir `.pcap` dosyasına kaydeder (Wireshark'ta incelemek için)

Rapor ve (varsa) `.pcap` dosyası `captures/` klasörüne kaydedilir (bu klasör de `.gitignore`'dadır — gerçek ağ trafiği hassas veri sayılır).

> **Not:** Canlı yakalama Windows'ta [Npcap](https://npcap.com/) gerektirir (Wireshark kuruluysa genelde zaten kuruludur). Bazı kurulumlarda terminali "Yönetici olarak çalıştır" ile açmanız gerekebilir.

---

## 🧪 Testler

```bash
pip install -r requirements-dev.txt
pytest -v
```

Testler gerçek Anthropic API'sine istek atmaz — sahte (mock) bir istemci kullanır.

---

## 📁 Proje Yapısı

```
main.py       - CLI aracı + paket ayrıştırma / trafik istatistiği çekirdek mantığı
app.py        - Flask web arayüzü
capture.py    - canlı paket yakalama ve gün sonu özet raporu
templates/    - web arayüzü HTML şablonları
static/       - web arayüzü CSS'i
tests/        - pytest test paketi
```

---

## 🗺️ Yol Haritası

- [ ] Canlı yakalamayı web arayüzünden de başlatabilme
- [ ] Analiz sonuçlarını JSON/Markdown olarak dışa aktarma
- [ ] Daha fazla protokol desteği (ICMP detayları, QUIC vb.)

Bu proje aktif olarak, gün gün geliştirilmeye devam ediyor.
