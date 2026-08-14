# AI-PCAP-Analyzer'ı Adım Adım Nasıl Güvenli Hale Getirdim

*Taslak — yayınlamadan önce gözden geçirilmeli.*

AI-PCAP-Analyzer, başlangıçta Scapy ile PCAP dosyalarındaki paketleri okuyup
özetleyen basit bir CLI script'iydi. Zamanla üstüne bir Flask arayüzü, yapay
zeka destekli analiz ve canlı paket yakalama özellikleri eklendi. Ama bir
web arayüzü eklemek, aynı zamanda yeni bir saldırı yüzeyi eklemek demek.
Bu yazıda projeye özellik ekledikçe hangi güvenlik sorunlarıyla karşılaştığımı,
neden sorun olduklarını ve nasıl kapattığımı adım adım anlatıyorum.

## 1. Temel açıklar — XSS, dosya sızıntısı, sertleştirme

Web arayüzü ilk oturunca en can yakıcı üç şeyi kapattım:

- **XSS ve sızan pcap dosyası açığı**: Kullanıcıdan gelen veriler doğrudan
  şablonlara basılıyordu ve yüklenen pcap dosyaları beklenenden daha geniş
  bir alandan erişilebilir durumdaydı.
- **Production sertleştirme**: Debug modu kapatıldı, hata mesajları
  kullanıcıya iç detay sızdırmayacak şekilde sadeleştirildi, rate limiting
  ve loglama eklendi.
- **SSRF ve tedarik zinciri riskleri**: Dışarıdan URL kabul eden noktalar
  kısıtlandı, CDN üzerinden yüklenen script/style dosyaları yerine
  bağımlılıklar sabit sürümlere (pinned) bağlandı.

## 2. Kimlik doğrulama, CSRF, güvenli silme

Bir sonraki adım, uygulamayı "aynı ağdaki herkesin her şeyi yapabildiği"
bir araçtan çıkarmaktı:

- Kimlik doğrulama eklendi.
- CSRF koruması (Flask-WTF) devreye alındı.
- Dosya silme işlemleri güvenli hale getirildi (yol/traversal ve yetkisiz
  silme senaryolarına karşı).
- DoS ve SSRF için ek sıkılaştırmalar yapıldı.

## 3. Oturum, tarayıcı güvenliği, hata sızıntısı

Sonra tarayıcı tarafına ve oturum yönetimine odaklandım:

- Session timeout eklendi — açık kalan oturumların süresiz geçerli
  olmasının önüne geçildi.
- Content-Security-Policy (CSP) ve HSTS başlıkları eklendi.
- Hata mesajları sanitize edilerek stack trace / iç yol bilgisi gibi
  detayların dışarı sızması engellendi.

## 4. Statik analiz ve gerekçeli istisnalar

Elle bulduğum açıkların ötesinde otomatik bir statik analiz aracı (Bandit)
çalıştırıp raporundaki uyarıları tek tek gözden geçirdim:

- Genel `except Exception` blokları, nereye düştüğünü bilerek
  `except OSError` gibi daha dar istisna tiplerine indirgendi.
- Gerçekten güvenli olduğuna karar verdiğim tek bir false-positive için
  (`# nosec B104`), *neden* güvenli olduğunu açıklayan bir gerekçe
  yorumuyla birlikte bilinçli bir istisna bırakıldı — sessizce bastırmak
  yerine.
- Ardından bir `SECURITY.md` ekleyerek güvenlik açığı bildirim sürecini
  belgeledim.

## 5. Giriş ekranına yapılan son iyileştirme: zayıf şifre koruması

En son, giriş ekranını tekrar gözden geçirirken küçük ama gerçek bir boşluk
fark ettim: ilk çalıştırmada otomatik üretilen şifre ~96 bit entropiye sahip
olduğu için kaba kuvvetle pratikte kırılamıyordu, ama kullanıcı `.env`
dosyasına kendi kısa/zayıf bir şifre girerse aynı koruma geçerli değildi —
dakikada 10 denemelik rate limit, zayıf bir şifreye karşı tek başına yeterli
değil. Çözüm olarak uygulama artık `APP_PASSWORD` 8 karakterden kısaysa
başlamayı reddedip kullanıcıyı ya daha güçlü bir şifre seçmeye ya da satırı
silip otomatik üretilen güçlü şifreye dönmeye yönlendiriyor.

## Çıkarımlar

- Güvenlik tek seferlik bir görev değil, özellik eklendikçe tekrar tekrar
  gözden geçirilmesi gereken bir süreç.
- Otomatik araçlar (Bandit, dependency audit) elle bakışın kaçırdığı
  şeyleri yakalıyor — ama her uyarıyı kör kör susturmak yerine anlayıp
  gerekçelendirmek önemli.
- En büyük risk çoğu zaman "yeni özellik" ile birlikte gelen yeni giriş
  noktaları (dosya yükleme, canlı yakalama, dışarıdan URL) oluyor.

Kod ve commit geçmişi: [github.com/EnesKok20/ai-pcap-analyzer](https://github.com/EnesKok20/ai-pcap-analyzer)
