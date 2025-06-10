#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Test Kurulum Scripti
result_test klasörünü oluşturur ve test dosyalarını kontrol eder
"""

import os
import time

def setup_test_environment():
    """Test ortamını hazırla"""
    print("🔧 Test ortamı hazırlanıyor...")
    
    # result_test klasörünü oluştur
    test_dir = "result_test"
    if not os.path.exists(test_dir):
        os.makedirs(test_dir)
        print(f"✅ {test_dir} klasörü oluşturuldu")
    else:
        print(f"ℹ️  {test_dir} klasörü zaten mevcut")
    
    # Klasör içeriğini kontrol et
    files = os.listdir(test_dir)
    if files:
        print(f"📁 {test_dir} klasöründe {len(files)} dosya bulundu:")
        for file in files:
            file_path = os.path.join(test_dir, file)
            size = os.path.getsize(file_path)
            mod_time = time.ctime(os.path.getmtime(file_path))
            print(f"   - {file} ({size:,} bytes, {mod_time})")
    else:
        print(f"📂 {test_dir} klasörü boş")
    
    # Test dosyasını kontrol et
    test_file = "test_dosyasi.txt"
    if os.path.exists(test_file):
        size = os.path.getsize(test_file)
        print(f"✅ Test dosyası hazır: {test_file} ({size:,} bytes)")
    else:
        print(f"❌ Test dosyası bulunamadı: {test_file}")
    
    print("\n🚀 Test ortamı hazır!")
    print("\nTest adımları:")
    print("1. python main.py ile uygulamayı başlatın")
    print("2. Bir pencerede 'Sunucu' modunu seçin ve başlatın")
    print("3. Başka bir pencerede 'İstemci' modunu seçin")
    print("4. 127.0.0.1:8888 ile bağlanın")
    print("5. test_dosyasi.txt dosyasını seçin ve gönderin")
    print("6. Dosya otomatik olarak result_test/ klasörüne kaydedilecek")

def clean_test_results():
    """Test sonuçlarını temizle"""
    test_dir = "result_test"
    if os.path.exists(test_dir):
        files = os.listdir(test_dir)
        for file in files:
            file_path = os.path.join(test_dir, file)
            try:
                os.remove(file_path)
                print(f"🗑️  Silindi: {file}")
            except Exception as e:
                print(f"❌ Silinemedi {file}: {e}")
        print(f"🧹 {test_dir} klasörü temizlendi")
    else:
        print(f"❌ {test_dir} klasörü bulunamadı")

if __name__ == "__main__":
    import sys
    
    if len(sys.argv) > 1 and sys.argv[1] == "clean":
        clean_test_results()
    else:
        setup_test_environment() 