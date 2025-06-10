#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Paket Analizi Modülü - Basitleştirilmiş Versiyon
Paketlerin kaynak/hedef IP, protokol ve süre bilgilerini gösterir
"""

import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext
import threading
import time
from datetime import datetime
from collections import defaultdict

try:
    from scapy.all import sniff, IP, TCP, UDP, ICMP, ARP, get_if_list
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

class PacketAnalyzerTab:
    def __init__(self, parent):
        self.parent = parent
        self.capturing = False
        self.packet_count = 0
        self.start_time = None
        
        self.setup_ui()
        
        if not SCAPY_AVAILABLE:
            self.show_scapy_warning()
    
    def setup_ui(self):
        """Basitleştirilmiş kullanıcı arayüzünü oluştur"""
        # Ana çerçeve
        main_frame = ttk.Frame(self.parent)
        main_frame.pack(fill='both', expand=True, padx=10, pady=10)
        
        # Başlık
        title_label = ttk.Label(main_frame, text="📊 Paket Analizi", 
                               font=('Arial', 16, 'bold'), foreground='darkblue')
        title_label.pack(pady=(0, 20))
        
        # Kontrol paneli - Sadece başlatma/durdurma butonları
        control_frame = ttk.LabelFrame(main_frame, text="Paket Yakalama Kontrolü", padding=15)
        control_frame.pack(fill='x', pady=(0, 15))
        
        # Üst satır - Paket limiti ayarı
        settings_frame = ttk.Frame(control_frame)
        settings_frame.pack(pady=(0, 10))
        
        ttk.Label(settings_frame, text="Maksimum Paket Sayısı:", font=('Arial', 10, 'bold')).pack(side='left', padx=(0, 10))
        self.packet_limit_var = tk.StringVar(value="1000")
        limit_entry = ttk.Entry(settings_frame, textvariable=self.packet_limit_var, width=10, font=('Arial', 10))
        limit_entry.pack(side='left', padx=(0, 20))
        
        ttk.Label(settings_frame, text="(0 = Sınırsız)", font=('Arial', 9), foreground='gray').pack(side='left')
        
        # Alt satır - Kontrol butonları
        button_frame = ttk.Frame(control_frame)
        button_frame.pack()
        
        # Başlatma butonu
        self.start_button = ttk.Button(button_frame, text="🚀 Paket Yakalamayı Başlat", 
                                     command=self.start_capture, style='Accent.TButton')
        self.start_button.pack(side='left', padx=(0, 20))
        
        # Durdurma butonu
        self.stop_button = ttk.Button(button_frame, text="⏹️ Durdur", 
                                    command=self.stop_capture, state='disabled')
        self.stop_button.pack(side='left', padx=(0, 20))
        
        # Temizle butonu
        ttk.Button(button_frame, text="🗑️ Temizle", command=self.clear_data).pack(side='left')
        
        # Durum bilgisi
        status_frame = ttk.Frame(control_frame)
        status_frame.pack(pady=(10, 0))
        
        ttk.Label(status_frame, text="Durum:", font=('Arial', 10, 'bold')).pack(side='left', padx=(0, 10))
        self.status_label = ttk.Label(status_frame, text="Hazır", foreground='gray', font=('Arial', 10, 'bold'))
        self.status_label.pack(side='left', padx=(0, 30))
        
        ttk.Label(status_frame, text="Toplam Paket:", font=('Arial', 10, 'bold')).pack(side='left', padx=(0, 10))
        self.packet_count_label = ttk.Label(status_frame, text="0", foreground='blue', font=('Arial', 10, 'bold'))
        self.packet_count_label.pack(side='left', padx=(0, 10))
        
        # Limit durumu
        self.limit_status_label = ttk.Label(status_frame, text="", foreground='gray', font=('Arial', 9))
        self.limit_status_label.pack(side='left')
        
        # Paket listesi paneli
        packet_frame = ttk.LabelFrame(main_frame, text="Yakalanan Paketler", padding=10)
        packet_frame.pack(fill='both', expand=True)
        
        # Paket tablosu
        columns = ("No", "Süre", "Kaynak IP", "Hedef IP", "Protokol", "Port", "Boyut")
        self.packet_tree = ttk.Treeview(packet_frame, columns=columns, show='headings', height=20)
        
        # Sütun ayarları
        self.packet_tree.heading("No", text="No")
        self.packet_tree.column("No", width=60, anchor='center')
        
        self.packet_tree.heading("Süre", text="Süre")
        self.packet_tree.column("Süre", width=120, anchor='center')
        
        self.packet_tree.heading("Kaynak IP", text="Kaynak IP")
        self.packet_tree.column("Kaynak IP", width=140, anchor='center')
        
        self.packet_tree.heading("Hedef IP", text="Hedef IP")  
        self.packet_tree.column("Hedef IP", width=140, anchor='center')
        
        self.packet_tree.heading("Protokol", text="Protokol")
        self.packet_tree.column("Protokol", width=100, anchor='center')
        
        self.packet_tree.heading("Port", text="Port")
        self.packet_tree.column("Port", width=80, anchor='center')
        
        self.packet_tree.heading("Boyut", text="Boyut (bytes)")
        self.packet_tree.column("Boyut", width=100, anchor='center')
        
        # Scrollbar
        packet_scrollbar = ttk.Scrollbar(packet_frame, orient='vertical', command=self.packet_tree.yview)
        self.packet_tree.configure(yscrollcommand=packet_scrollbar.set)
        
        # Yerleştirme
        self.packet_tree.pack(side='left', fill='both', expand=True)
        packet_scrollbar.pack(side='right', fill='y')
        
        # Log paneli
        log_frame = ttk.LabelFrame(main_frame, text="Paket Yakalama Logları", padding=10)
        log_frame.pack(fill='x', pady=(10, 0))
        
        self.log_text = scrolledtext.ScrolledText(log_frame, height=6, wrap=tk.WORD)
        self.log_text.pack(fill='x')
    
    def show_scapy_warning(self):
        """Scapy uyarısını göster"""
        warning_frame = ttk.Frame(self.parent)
        warning_frame.pack(fill='x', padx=10, pady=10)
        
        warning_label = ttk.Label(warning_frame, 
                                text="⚠️ Scapy kütüphanesi bulunamadı. Paket analizi için 'pip install scapy' komutunu çalıştırın.",
                                foreground='red', font=('Arial', 10, 'bold'))
        warning_label.pack()
    
    def start_capture(self):
        """Paket yakalamayı başlat"""
        if not SCAPY_AVAILABLE:
            messagebox.showerror("Hata", "Scapy kütüphanesi bulunamadı!")
            return
        
        # Paket limiti kontrolü
        try:
            packet_limit = int(self.packet_limit_var.get())
            if packet_limit < 0:
                messagebox.showwarning("Uyarı", "Paket sayısı negatif olamaz!")
                return
        except ValueError:
            messagebox.showwarning("Uyarı", "Geçerli bir paket sayısı girin!")
            return
        
        if not self.capturing:
            self.capturing = True
            self.start_time = time.time()
            self.packet_count = 0
            
            # Buton durumları
            self.start_button.config(state='disabled')
            self.stop_button.config(state='normal')
            self.status_label.config(text="🟢 Yakalama Aktif", foreground='green')
            
            # Yakalama thread'i başlat
            capture_thread = threading.Thread(target=self.capture_packets, daemon=True)
            capture_thread.start()
            
            limit_text = "sınırsız" if packet_limit == 0 else f"{packet_limit} paket"
            self.log_message(f"Paket yakalama başlatıldı (Limit: {limit_text})")
    
    def stop_capture(self):
        """Paket yakalamayı durdur"""
        self.capturing = False
        self.start_button.config(state='normal')
        self.stop_button.config(state='disabled')
        self.status_label.config(text="🔴 Durduruldu", foreground='red')
        
        elapsed_time = time.time() - self.start_time if self.start_time else 0
        self.log_message(f"Paket yakalama durduruldu. Süre: {elapsed_time:.1f} saniye, Toplam paket: {self.packet_count}")
    
    def stop_capture_with_limit(self):
        """Paket limiti dolduğunda yakalamayı durdur"""
        if self.capturing:
            self.capturing = False
            self.start_button.config(state='normal')
            self.stop_button.config(state='disabled')
            self.status_label.config(text="✅ Limit Tamamlandı", foreground='green')
            
            elapsed_time = time.time() - self.start_time if self.start_time else 0
            packet_limit = int(self.packet_limit_var.get())
            self.log_message(f"Paket limiti ({packet_limit}) tamamlandı! Süre: {elapsed_time:.1f} saniye")
    
    def capture_packets(self):
        """Paketleri yakala"""
        try:
            # Paket yakalama
            sniff(prn=self.process_packet, stop_filter=lambda x: not self.capturing, timeout=1)
        except Exception as e:
            self.log_message(f"Paket yakalama hatası: {str(e)}")
            self.parent.after(0, self.stop_capture)
    
    def process_packet(self, packet):
        """Paketi işle ve tabloya ekle"""
        try:
            if not self.capturing:
                return
            
            self.packet_count += 1
            
            # Paket bilgilerini çıkar
            packet_info = self.extract_packet_info(packet)
            
            # UI'yi ana thread'de güncelle
            self.parent.after(0, lambda: self.add_packet_to_tree(packet_info))
            self.parent.after(0, lambda: self.update_packet_counter())
            
            # Paket limit kontrolü
            try:
                packet_limit = int(self.packet_limit_var.get())
                if packet_limit > 0 and self.packet_count >= packet_limit:
                    self.parent.after(0, self.stop_capture_with_limit)
            except ValueError:
                pass  # Limit kontrolü başarısız, devam et
            
        except Exception as e:
            self.log_message(f"Paket işleme hatası: {str(e)}")
    
    def extract_packet_info(self, packet):
        """Paketten temel bilgileri çıkar"""
        info = {
            'no': self.packet_count,
            'time': datetime.now().strftime("%H:%M:%S.%f")[:-3],
            'src_ip': 'N/A',
            'dst_ip': 'N/A', 
            'protocol': 'Unknown',
            'port': 'N/A',
            'size': len(packet)
        }
        
        try:
            # IP katmanı kontrolü
            if IP in packet:
                ip_layer = packet[IP]
                info['src_ip'] = ip_layer.src
                info['dst_ip'] = ip_layer.dst
                
                # Protokol tespiti
                if TCP in packet:
                    info['protocol'] = 'TCP'
                    info['port'] = f"{packet[TCP].sport} → {packet[TCP].dport}"
                elif UDP in packet:
                    info['protocol'] = 'UDP'
                    info['port'] = f"{packet[UDP].sport} → {packet[UDP].dport}"
                elif ICMP in packet:
                    info['protocol'] = 'ICMP'
                    info['port'] = f"Type {packet[ICMP].type}"
                else:
                    info['protocol'] = f"IP({ip_layer.proto})"
            
            # ARP kontrolü
            elif ARP in packet:
                arp_layer = packet[ARP]
                info['protocol'] = 'ARP'
                info['src_ip'] = arp_layer.psrc
                info['dst_ip'] = arp_layer.pdst
                info['port'] = f"{arp_layer.op}"
                
        except Exception as e:
            print(f"Paket analiz hatası: {e}")
        
        return info
    
    def add_packet_to_tree(self, packet_info):
        """Paketi tabloya ekle"""
        try:
            # Protokol rengini belirle
            protocol_colors = {
                'TCP': 'blue',
                'UDP': 'green', 
                'ICMP': 'red',
                'ARP': 'purple'
            }
            
            # Tabloya ekle
            item = self.packet_tree.insert('', 'end', values=(
                packet_info['no'],
                packet_info['time'],
                packet_info['src_ip'],
                packet_info['dst_ip'],
                packet_info['protocol'],
                packet_info['port'],
                packet_info['size']
            ))
            
            # Renk ayarla
            protocol = packet_info['protocol']
            if protocol in protocol_colors:
                self.packet_tree.set(item, 'Protokol', packet_info['protocol'])
            
            # Otomatik scroll
            self.packet_tree.see(item)
            
            # Her 10 pakette bir log yaz
            if packet_info['no'] % 10 == 0:
                self.log_message(f"Paket #{packet_info['no']}: {packet_info['src_ip']} → {packet_info['dst_ip']} ({packet_info['protocol']})")
                
        except Exception as e:
            print(f"Tablo ekleme hatası: {e}")
    
    def update_packet_counter(self):
        """Paket sayacını ve limit durumunu güncelle"""
        self.packet_count_label.config(text=str(self.packet_count))
        
        try:
            packet_limit = int(self.packet_limit_var.get())
            if packet_limit > 0:
                remaining = packet_limit - self.packet_count
                if remaining > 0:
                    self.limit_status_label.config(text=f"(Kalan: {remaining})", foreground='orange')
                else:
                    self.limit_status_label.config(text="(Limit Doldu)", foreground='red')
            else:
                self.limit_status_label.config(text="(Sınırsız)", foreground='gray')
        except ValueError:
            self.limit_status_label.config(text="(Geçersiz Limit)", foreground='red')
    
    def clear_data(self):
        """Tüm verileri temizle"""
        # Tabloyu temizle
        for item in self.packet_tree.get_children():
            self.packet_tree.delete(item)
        
        # Sayaçları sıfırla
        self.packet_count = 0
        self.update_packet_counter()
        
        # Log temizle
        self.log_text.delete(1.0, tk.END)
        
        # Durumu sıfırla
        if not self.capturing:
            self.status_label.config(text="Hazır", foreground='gray')
            self.limit_status_label.config(text="", foreground='gray')
        
        self.log_message("Paket verileri temizlendi")
    
    def log_message(self, message):
        """Log mesajı ekle"""
        timestamp = datetime.now().strftime("%H:%M:%S")
        log_entry = f"[{timestamp}] {message}\n"
        
        self.log_text.insert(tk.END, log_entry)
        self.log_text.see(tk.END)
    
    def cleanup(self):
        """Temizlik işlemleri"""
        if self.capturing:
            self.stop_capture() 