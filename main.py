#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Bilgisayar Ağları Dönem Projesi
Güvenli Dosya Transferi ve Ağ Analiz Uygulaması
"""

import tkinter as tk
from tkinter import ttk, messagebox, filedialog, scrolledtext
import threading
import sys
import os

# Alt modülleri import et
from file_transfer import FileTransferTab
from network_monitor import NetworkMonitorTab
from packet_analyzer import PacketAnalyzerTab
from security_tests import SecurityTestsTab

class NetworkSecurityApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Ağ Güvenliği ve Analiz Uygulaması")
        self.root.geometry("1200x800")
        self.root.configure(bg='#f0f0f0')
        
        # Ana stil ayarları
        self.setup_styles()
        
        # Ana notebook (sekmeler) oluştur
        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill='both', expand=True, padx=10, pady=10)
        
        # Sekmeleri oluştur
        self.create_tabs()
        
        # Durum çubuğu
        self.create_status_bar()
        
        # Pencere kapatma olayını yakala
        self.root.protocol("WM_DELETE_WINDOW", self.on_closing)
        
    def setup_styles(self):
        """GUI stil ayarlarını yapılandır"""
        style = ttk.Style()
        style.theme_use('clam')
        
        # Özel renkler
        style.configure('Title.TLabel', font=('Arial', 14, 'bold'), foreground='#2c3e50')
        style.configure('Header.TLabel', font=('Arial', 12, 'bold'), foreground='#34495e')
        style.configure('Info.TLabel', font=('Arial', 10), foreground='#7f8c8d')
        
    def create_tabs(self):
        """Ana sekmeleri oluştur"""
        try:
            # Dosya Transferi sekmesi
            self.file_transfer_frame = ttk.Frame(self.notebook)
            self.notebook.add(self.file_transfer_frame, text="📁 Dosya Transferi")
            self.file_transfer_tab = FileTransferTab(self.file_transfer_frame)
            
            # Ağ Monitörü sekmesi
            self.network_monitor_frame = ttk.Frame(self.notebook)
            self.notebook.add(self.network_monitor_frame, text="📊 Ağ Monitörü")
            self.network_monitor_tab = NetworkMonitorTab(self.network_monitor_frame)
            
            # Paket Analizi sekmesi
            self.packet_analyzer_frame = ttk.Frame(self.notebook)
            self.notebook.add(self.packet_analyzer_frame, text="🔍 Paket Analizi")
            self.packet_analyzer_tab = PacketAnalyzerTab(self.packet_analyzer_frame)
            
            # Güvenlik Testleri sekmesi
            self.security_tests_frame = ttk.Frame(self.notebook)
            self.notebook.add(self.security_tests_frame, text="🔐 Güvenlik Testleri")
            self.security_tests_tab = SecurityTestsTab(self.security_tests_frame)
            
        except Exception as e:
            messagebox.showerror("Hata", f"Sekmeler oluşturulurken hata: {str(e)}")
    
    def create_status_bar(self):
        """Durum çubuğunu oluştur"""
        self.status_frame = ttk.Frame(self.root)
        self.status_frame.pack(fill='x', side='bottom', padx=10, pady=5)
        
        self.status_label = ttk.Label(self.status_frame, text="Hazır", relief='sunken')
        self.status_label.pack(side='left', fill='x', expand=True)
        
        # Saat göstergesi
        self.time_label = ttk.Label(self.status_frame, text="", relief='sunken')
        self.time_label.pack(side='right', padx=(5, 0))
        
        self.update_time()
    
    def update_time(self):
        """Saati güncelle"""
        import datetime
        current_time = datetime.datetime.now().strftime("%H:%M:%S")
        self.time_label.config(text=current_time)
        self.root.after(1000, self.update_time)
    
    def update_status(self, message):
        """Durum çubuğunu güncelle"""
        self.status_label.config(text=message)
    
    def on_closing(self):
        """Uygulama kapanırken temizlik işlemleri"""
        try:
            # Aktif bağlantıları kapat
            if hasattr(self, 'file_transfer_tab'):
                self.file_transfer_tab.cleanup()
            if hasattr(self, 'packet_analyzer_tab'):
                self.packet_analyzer_tab.cleanup()
            if hasattr(self, 'security_tests_tab'):
                self.security_tests_tab.cleanup()
        except:
            pass
        finally:
            self.root.destroy()

def main():
    """Ana fonksiyon"""
    # Admin yetkisi kontrolü (Windows için)
    if sys.platform == "win32":
        try:
            import ctypes
            is_admin = ctypes.windll.shell32.IsUserAnAdmin()
            if not is_admin:
                messagebox.showwarning(
                    "Yönetici Yetkisi Gerekli",
                    "Bu uygulama bazı ağ işlemleri için yönetici yetkisi gerektirebilir.\n"
                    "Tam işlevsellik için uygulamayı yönetici olarak çalıştırın."
                )
        except:
            pass
    
    # Ana pencereyi oluştur ve başlat
    root = tk.Tk()
    app = NetworkSecurityApp(root)
    
    try:
        root.mainloop()
    except KeyboardInterrupt:
        print("\nUygulama kapatılıyor...")
    except Exception as e:
        messagebox.showerror("Kritik Hata", f"Beklenmeyen hata: {str(e)}")

if __name__ == "__main__":
    main() 