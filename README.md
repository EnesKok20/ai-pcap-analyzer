# 🛡️ AI Destekli Ağ Trafik ve Log Analizcisi (AI-PCAP-Analyzer)

Üniversitedeki Wireshark ağ analizi ve kriptoloji derslerinde edindiğim teorik temelleri, modern Yapay Zeka (AI) teknolojileriyle harmanlayarak gerçek dünya senaryolarında kullanmak üzere bu açık kaynaklı komut satırı (CLI) aracını geliştiriyorum.

---

## 🎯 Projenin Hedefi ve Amacı
Wireshark gibi araçlar ağ trafiğini incelemede müthiş güçlü olsa da, binlerce satırlık paket dökümleri arasında kaybolmak bazen çok yorucu olabiliyor. Bu projeyi geliştirirken temel amacım; ağ paket özetlerini ve log verilerini otomatik olarak işleyerek, şüpheli hareketleri ve anormal durumları **Yapay Zeka desteğiyle** saniyeler içinde tespit eden pratik bir asistan yaratmaktı.

---

## 🚀 Projenin Çözdüğü Problemler (Kullanım Alanları)
* **Teoriden Pratiğe Geçiş:** Okulda öğrendiğim ağ protokolleri ve trafik analizi mantığını, Python otomasyonu ve AI entegrasyonuyla canlı bir projeye döküyorum.
* **Hızlı Tehdit Avcılığı (Threat Hunting):** Kendi yerel ağımda veya analiz ettiğim PCAP dosyalarında olağan dışı port hareketlerini ve şüpheli bağlantıları hızlıca özetleyebiliyorum.
* **Zaman Tasarrufu:** Karmaşık log dosyalarını manuel incelemek yerine, yazdığım algoritmalar ve AI desteğiyle kritik anomalileri anında yakalıyorum.

---

## 📸 İlk Aşama: Scapy ile Ağ Analizi ve Terminal Çıktısı
Projenin ilk modülünde, ham PCAP dosyalarını başarıyla okuyan ve bağlantısız UDP trafiği içindeki kurumsal dosya sistemi ağlarını (NFS - Port 2049) ayrıştıran bir iskelet kurdum. Hatalı veya eksik katmanlı paketleri programı çökertmeden akıllıca bypass etmeyi başardım.

İşte yazdığım kodun bir "fuzzing" PCAP dosyası üzerindeki canlı analiz çıktısı:

![Terminal Çıktısı](01-terminal-udp-analiz-ciktisi.png)

---

## 🛠️ Kullanılan Teknolojiler ve Stack
Projeyi inşa ederken modern ve endüstri standardı araçları tercih ettim:
* **Python:** Otomasyon ve çekirdek mantık katmanı.
* **Scapy / Pyshark:** Ağ paketlerini okumak, çözümlemek ve ayrıştırmak için.
* **Yapay Zeka (AI) Modelleri:** Ağ verilerini yorumlayıp anomali tespiti yapmak için entegre ettiğim akıllı modül.
* **Git & GitHub:** Versiyon kontrolü ve projenin açık kaynak olarak sergilenmesi.

---

## ⚙️ Kurulum ve Çalıştırma (Yakında)

```bash
# Projeyi klonlayın
git clone [https://github.com/EnesKok20/ai-pcap-analyzer.git](https://github.com/EnesKok20/ai-pcap-analyzer.git)

# Proje klasörüne girin
cd ai-pcap-analyzer

# Gerekli kütüphaneleri yükleyin
pip install -r requirements.txt