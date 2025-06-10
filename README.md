# Bilgisayar Ağları Dönem Projesi

Bu proje, güvenli dosya transferi, ağ analizi, paket inceleme ve güvenlik testleri özellikleri içeren kapsamlı bir ağ güvenliği uygulamasıdır.

## 🚀 Özellikler

###  Güvenli Dosya Transferi
- **RSA + AES Hibrit Şifreleme**: 2048-bit RSA ile anahtar değişimi, 256-bit AES ile veri şifreleme
- **Dijital İmza**: SHA-256 hash ile dosya bütünlük kontrolü
- **Büyük Dosya Desteği**: Parçalı transfer ve ilerleme takibi
- **Sunucu/İstemci Mimarisi**: Esnek bağlantı seçenekleri

###  Ağ Performans Monitörü
- **Gerçek Zamanlı İzleme**: Ping, bant genişliği, paket kaybı ölçümü
- **Görsel Grafikler**: Matplotlib ile performans grafikleri
- **Ağ Arayüzü Analizi**: Aktif bağlantılar ve istatistikler
- **Otomatik Raporlama**: Detaylı performans logları

###  Paket Analizi
- **TCP/IP Paket İnceleme**: Scapy ile detaylı paket analizi
- **Protokol Filtreleme**: TCP, UDP, ICMP, ARP protokol desteği
- **Trafik İstatistikleri**: Port analizi ve IP iletişim haritası
- **Real-time Capture**: Canlı paket yakalama ve analiz

###  Güvenlik Testleri
- **MITM Simülasyonu**: ARP spoofing, DNS spoofing, SSL strip
- **Port Tarama**: TCP/UDP port tarama ve servis tespiti
- **Güvenlik Açığı Analizi**: Otomatik vulnerability scanning
- **Koruma Önerileri**: Firewall ve güvenlik yapılandırma tavsiyeleri

## 📋 Gereksinimler

### Python Sürümü
- Python 3.8 veya üzeri

### Gerekli Kütüphaneler
```bash
pip install -r requirements.txt
```

### Sistem Gereksinimleri
- **Windows**: Windows 10/11 (Admin yetkisi önerilir)
- **Linux**: Ubuntu 18.04+ veya diğer dağıtımlar (sudo yetkisi gerekli)
- **macOS**: macOS 10.14+ (sudo yetkisi gerekli)

### Ek Gereksinimler
- **Scapy**: Paket analizi için (Linux'ta libpcap gerekebilir)
- **Admin/Root Yetkisi**: Ağ işlemleri için gerekli

## 🛠️ Kurulum

1. **Repoyu klonlayın:**
```bash
git clone [repo-url]
cd projebilgisaayaraglari
```

2. **Gerekli kütüphaneleri yükleyin:**
```bash
pip install -r requirements.txt
```

3. **Linux/macOS için ek adımlar:**
```bash
# Scapy için libpcap yükleme (Ubuntu/Debian)
sudo apt-get install libpcap-dev

# Scapy için libpcap yükleme (CentOS/RHEL)
sudo yum install libpcap-devel
```

4. **Uygulamayı çalıştırın:**
```bash
python main.py
```

## 💻 Kullanım

### İlk Çalıştırma
1. Uygulamayı yönetici yetkisi ile çalıştırın
2. Güvenlik uyarılarını kabul edin
3. Ağ arayüzü izinlerini verin

### Dosya Transferi
1. **Sunucu Modu**: "Sunucuyu Başlat" butonuna tıklayın
2. **İstemci Modu**: IP adresini girin ve "Bağlan" butonuna tıklayın
3. Dosya seçin ve "Gönder" butonuna tıklayın
4. Transfer ilerlemesini takip edin

### Ağ Monitörü
1. Hedef IP adresini girin (varsayılan: 8.8.8.8)
2. Ping aralığını ayarlayın
3. "Başlat" butonuna tıklayın
4. Gerçek zamanlı grafikleri inceleyin

### Paket Analizi
1. Ağ arayüzünü seçin
2. Protokol filtresini ayarlayın
3. "Yakalamayı Başlat" butonuna tıklayın
4. Paket listesinden detayları inceleyin

### Güvenlik Testleri
1. **MITM**: Hedef IP'yi girin ve saldırı türünü seçin
2. **Port Tarama**: IP aralığı ve port aralığını belirleyin
3. **Güvenlik Açığı**: Hedef sistemi tarayın
4. **Koruma**: Önerilen güvenlik kurallarını uygulayın

## 🔧 Konfigürasyon

### Ağ Ayarları
- Default port: 8888
- Timeout değerleri: 1-5 saniye
- Buffer boyutu: 8192 bytes

### Güvenlik Ayarları
- RSA anahtar boyutu: 2048 bit
- AES anahtar boyutu: 256 bit
- Hash algoritması: SHA-256

## 📊 Teknik Detaylar

### Şifreleme Algoritmaları
- **RSA-2048**: Asimetrik şifreleme (anahtar değişimi)
- **AES-256-CBC**: Simetrik şifreleme (veri koruması)
- **SHA-256**: Hash fonksiyonu (bütünlük kontrolü)
- **OAEP Padding**: RSA şifreleme güvenliği
- **PSS Padding**: Dijital imza güvenliği

### Ağ Protokolleri
- **TCP**: Güvenilir veri transferi
- **UDP**: Hızlı veri iletimi
- **ICMP**: Ağ tanılama
- **ARP**: Adres çözümleme

### Güvenlik Özellikleri
- End-to-end şifreleme
- Perfect Forward Secrecy
- Man-in-the-middle koruması
- Integrity verification
- Authentication

## ⚠️ Güvenlik Uyarıları

1. **Yasal Kullanım**: Bu araçları sadece kendi ağınızda veya izin verilen sistemlerde kullanın
2. **Etik Hacking**: Güvenlik testlerini sadece eğitim amaçlı yapın
3. **Yetki**: Paket yakalama için admin/root yetkisi gereklidir
4. **Sorumluluk**: Kötüye kullanımdan kullanıcı sorumludur

##  Bilinen Sorunlar

1. **Windows Defender**: Ağ araçları false positive verebilir
2. **Firewall**: Port dinleme izinleri gerekebilir
3. **Scapy**: Linux'ta kurulum sorunları olabilir
4. **Performance**: Yüksek trafik durumunda yavaşlama

## 🔄 Güncellemeler

### Versiyon 1.0
- İlk release
- Temel özellikler
- GUI arayüzü

### Planlanan Özellikler
- Database logging
- Network mapping
- Advanced MITM techniques
- Web interface
- API endpoints

##  Katkıda Bulunma

1. Fork yapın
2. Feature branch oluşturun
3. Değişikliklerinizi commit edin
4. Pull request gönderin

## 👨‍💻 Geliştirici

**Bilgisayar Ağları Dönem Projesi**
- Teknoloji: Python, Tkinter, Scapy, Cryptography
- Platform: Cross-platform (Windows, Linux, macOS)

## 📞 İletişim

Sorularınız için:
- Email: anilsurmeli2@gmail.com


---

**⚠️ DİKKAT: Bu uygulama eğitim amaçlıdır. Güvenlik testlerini sadece kendi sisteminizde veya izin verilen ortamlarda yapın!** 
