#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Ağ Monitörü Modülü
Bant genişliği, gecikme, paket kaybı ölçümü ve performans analizi
"""

import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext
import threading
import time
import socket
import subprocess
import platform
import psutil
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
import numpy as np
from collections import deque

class NetworkMonitorTab:
    def __init__(self, parent):
        self.parent = parent
        self.monitoring = False
        self.ping_data = deque(maxlen=50)  # Son 50 ping verisi
        self.bandwidth_data = deque(maxlen=50)  # Son 50 bant genişliği verisi
        self.packet_loss_data = deque(maxlen=50)  # Son 50 paket kaybı verisi
        
        # İstatistik değişkenleri
        self.total_tests = 0
        self.successful_pings = []
        self.start_time = None
        
        self.setup_ui()
        self.start_monitoring()
    
    def setup_ui(self):
        """Kullanıcı arayüzünü oluştur"""
        # Ana çerçeve
        main_frame = ttk.Frame(self.parent)
        main_frame.pack(fill='both', expand=True, padx=10, pady=10)
        
        # Başlık
        title_label = ttk.Label(main_frame, text="Ağ Performans Monitörü", style='Title.TLabel')
        title_label.pack(pady=(0, 20))
        
        # Üst panel - Kontroller
        control_frame = ttk.LabelFrame(main_frame, text="Kontrol Paneli", padding=10)
        control_frame.pack(fill='x', pady=(0, 10))
        
        # Hedef IP
        ttk.Label(control_frame, text="Hedef IP:").grid(row=0, column=0, sticky='w', padx=(0, 10))
        self.target_ip_var = tk.StringVar(value="8.8.8.8")
        target_ip_entry = ttk.Entry(control_frame, textvariable=self.target_ip_var, width=15)
        target_ip_entry.grid(row=0, column=1, padx=(0, 20))
        
        # Google DNS bilgisi
        google_info = ttk.Label(control_frame, text="(Google DNS)", font=('Arial', 8), foreground='gray')
        google_info.grid(row=1, column=1, sticky='w', padx=(0, 20))
        
        # Ping aralığı
        ttk.Label(control_frame, text="Monitörleme Aralığı (sn):").grid(row=0, column=2, sticky='w', padx=(0, 10))
        self.ping_interval_var = tk.StringVar(value="10")
        ping_interval_entry = ttk.Entry(control_frame, textvariable=self.ping_interval_var, width=10)
        ping_interval_entry.grid(row=0, column=3, padx=(0, 20))
        
        # Kontrol butonları
        self.start_button = ttk.Button(control_frame, text="Başlat", command=self.start_monitoring)
        self.start_button.grid(row=0, column=4, padx=(0, 10))
        
        self.stop_button = ttk.Button(control_frame, text="Durdur", command=self.stop_monitoring)
        self.stop_button.grid(row=0, column=5, padx=(0, 10))
        
        ttk.Button(control_frame, text="Temizle", command=self.clear_data).grid(row=0, column=6)
        
        # Orta panel - Gerçek zamanlı istatistikler
        stats_frame = ttk.LabelFrame(main_frame, text="Anlık İstatistikler", padding=10)
        stats_frame.pack(fill='x', pady=(0, 10))
        
        # İstatistik labelları
        stats_grid = ttk.Frame(stats_frame)
        stats_grid.pack(fill='x')
        
        # Google DNS Ping - İlk satır
        ttk.Label(stats_grid, text="Google DNS Ping:", font=('Arial', 10, 'bold')).grid(row=0, column=0, sticky='w', padx=(0, 10))
        self.ping_label = ttk.Label(stats_grid, text="-- ms", foreground='blue', font=('Arial', 11, 'bold'))
        self.ping_label.grid(row=0, column=1, sticky='w', padx=(0, 30))
        
        # Ortalama ping
        ttk.Label(stats_grid, text="Ortalama:", font=('Arial', 10, 'bold')).grid(row=0, column=2, sticky='w', padx=(0, 10))
        self.avg_ping_label = ttk.Label(stats_grid, text="-- ms", foreground='blue')
        self.avg_ping_label.grid(row=0, column=3, sticky='w', padx=(0, 30))
        
        # Bağlantı durumu
        ttk.Label(stats_grid, text="Durum:", font=('Arial', 10, 'bold')).grid(row=0, column=4, sticky='w', padx=(0, 10))
        self.status_label = ttk.Label(stats_grid, text="Bekleniyor", foreground='gray', font=('Arial', 10, 'bold'))
        self.status_label.grid(row=0, column=5, sticky='w')
        
        # İkinci satır
        # Paket kaybı
        ttk.Label(stats_grid, text="Paket Kaybı:", font=('Arial', 10, 'bold')).grid(row=1, column=0, sticky='w', padx=(0, 10))
        self.packet_loss_label = ttk.Label(stats_grid, text="--%", foreground='red', font=('Arial', 11, 'bold'))
        self.packet_loss_label.grid(row=1, column=1, sticky='w', padx=(0, 30))
        
        # En iyi ping
        ttk.Label(stats_grid, text="En İyi:", font=('Arial', 10, 'bold')).grid(row=1, column=2, sticky='w', padx=(0, 10))
        self.best_ping_label = ttk.Label(stats_grid, text="-- ms", foreground='green')
        self.best_ping_label.grid(row=1, column=3, sticky='w', padx=(0, 30))
        
        # En kötü ping
        ttk.Label(stats_grid, text="En Kötü:", font=('Arial', 10, 'bold')).grid(row=1, column=4, sticky='w', padx=(0, 10))
        self.worst_ping_label = ttk.Label(stats_grid, text="-- ms", foreground='red')
        self.worst_ping_label.grid(row=1, column=5, sticky='w')
        
        # Üçüncü satır - Bant genişliği
        ttk.Label(stats_grid, text="Download:", font=('Arial', 10, 'bold')).grid(row=2, column=0, sticky='w', padx=(0, 10))
        self.download_label = ttk.Label(stats_grid, text="-- MB/s", foreground='green', font=('Arial', 10, 'bold'))
        self.download_label.grid(row=2, column=1, sticky='w', padx=(0, 30))
        
        ttk.Label(stats_grid, text="Upload:", font=('Arial', 10, 'bold')).grid(row=2, column=2, sticky='w', padx=(0, 10))
        self.upload_label = ttk.Label(stats_grid, text="-- MB/s", foreground='orange', font=('Arial', 10, 'bold'))
        self.upload_label.grid(row=2, column=3, sticky='w', padx=(0, 30))
        
        # Toplam test sayısı
        ttk.Label(stats_grid, text="Toplam Test:", font=('Arial', 10, 'bold')).grid(row=2, column=4, sticky='w', padx=(0, 10))
        self.total_tests_label = ttk.Label(stats_grid, text="0", foreground='purple', font=('Arial', 10, 'bold'))
        self.total_tests_label.grid(row=2, column=5, sticky='w')
        
        # Grafik paneli
        graph_frame = ttk.LabelFrame(main_frame, text="Performans Grafikleri", padding=10)
        graph_frame.pack(fill='both', expand=True, pady=(0, 10))
        
        # Matplotlib grafikleri
        self.setup_graphs(graph_frame)
        
        # Log paneli
        log_frame = ttk.LabelFrame(main_frame, text="Ağ Logları", padding=10)
        log_frame.pack(fill='x', pady=(0, 10))
        
        self.log_text = scrolledtext.ScrolledText(log_frame, height=8, wrap=tk.WORD)
        self.log_text.pack(fill='x')
    
    def setup_graphs(self, parent):
        """Grafikleri oluştur"""
        # Figure oluştur
        self.fig, ((self.ax1, self.ax2), (self.ax3, self.ax4)) = plt.subplots(2, 2, figsize=(12, 8))
        
        # Grafik ayarları
        self.ax1.set_title('Ping (ms)')
        self.ax1.set_ylabel('Gecikme (ms)')
        self.ax1.grid(True)
        
        self.ax2.set_title('Bant Genişliği')
        self.ax2.set_ylabel('Hız (MB/s)')
        self.ax2.grid(True)
        
        self.ax3.set_title('Paket Kaybı')
        self.ax3.set_ylabel('Kayıp (%)')
        self.ax3.grid(True)
        
        self.ax4.set_title('Ağ Arayüzü Kullanımı')
        self.ax4.set_ylabel('Bytes/sn')
        self.ax4.grid(True)
        
        # Canvas oluştur
        self.canvas = FigureCanvasTkAgg(self.fig, parent)
        self.canvas.draw()
        self.canvas.get_tk_widget().pack(fill='both', expand=True)
        
        plt.tight_layout()
    
    def start_monitoring(self):
        """Monitörlemeyi başlat"""
        if not self.monitoring:
            self.monitoring = True
            self.start_button.config(state='disabled')
            self.stop_button.config(state='normal')
            
            # Monitörleme thread'leri başlat
            threading.Thread(target=self.ping_monitor, daemon=True).start()
            threading.Thread(target=self.bandwidth_monitor, daemon=True).start()
            threading.Thread(target=self.interface_monitor, daemon=True).start()
            threading.Thread(target=self.update_graphs, daemon=True).start()
            
            self.log_message("Ağ monitörleme başlatıldı")
    
    def stop_monitoring(self):
        """Monitörlemeyi durdur"""
        self.monitoring = False
        self.start_button.config(state='normal')
        self.stop_button.config(state='disabled')
        self.status_label.config(text="Durduruldu", foreground='red')
        self.log_message("Ağ monitörleme durduruldu")
    
    def clear_data(self):
        """Tüm verileri temizle"""
        self.ping_data.clear()
        self.bandwidth_data.clear()
        self.packet_loss_data.clear()
        self.successful_pings.clear()
        self.total_tests = 0
        self.start_time = time.time()
        
        # Labelları sıfırla
        self.ping_label.config(text="-- ms", foreground='blue')
        self.avg_ping_label.config(text="-- ms", foreground='blue')
        self.best_ping_label.config(text="-- ms", foreground='green')
        self.worst_ping_label.config(text="-- ms", foreground='red')
        self.packet_loss_label.config(text="--%", foreground='red')
        self.status_label.config(text="Bekleniyor", foreground='gray')
        self.total_tests_label.config(text="0", foreground='purple')
        self.download_label.config(text="-- MB/s", foreground='green')
        self.upload_label.config(text="-- MB/s", foreground='orange')
        
        self.log_text.delete(1.0, tk.END)
        self.log_message("Veriler temizlendi - Google DNS monitörleme yeniden başlatılıyor")
    
    def ping_monitor(self):
        """Ping monitörleme"""
        consecutive_failures = 0
        total_pings = 0
        failed_pings = 0
        
        # İstatistikler için
        if self.start_time is None:
            self.start_time = time.time()
        
        while self.monitoring:
            try:
                target_ip = self.target_ip_var.get()
                interval = float(self.ping_interval_var.get())
                
                # Ping komutunu oluştur (platform bağımsız)
                if platform.system().lower() == "windows":
                    cmd = ["ping", "-n", "1", "-w", "3000", target_ip]  # 3 saniye timeout
                else:
                    cmd = ["ping", "-c", "1", "-W", "3", target_ip]
                
                start_time = time.time()
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
                end_time = time.time()
                
                total_pings += 1
                self.total_tests = total_pings
                
                if result.returncode == 0:
                    # Ping başarılı
                    if platform.system().lower() == "windows":
                        # Windows ping çıktısından süreyi çıkar
                        output_lines = result.stdout.split('\n')
                        for line in output_lines:
                            if 'time=' in line.lower():
                                try:
                                    time_part = line.lower().split('time=')[1].split('ms')[0]
                                    ping_time = float(time_part.replace('<', ''))
                                    break
                                except:
                                    ping_time = (end_time - start_time) * 1000
                        else:
                            ping_time = (end_time - start_time) * 1000
                    else:
                        # Linux/Mac ping çıktısından süreyi çıkar
                        output_lines = result.stdout.split('\n')
                        for line in output_lines:
                            if 'time=' in line:
                                try:
                                    time_part = line.split('time=')[1].split(' ms')[0]
                                    ping_time = float(time_part)
                                    break
                                except:
                                    ping_time = (end_time - start_time) * 1000
                        else:
                            ping_time = (end_time - start_time) * 1000
                    
                    self.ping_data.append(ping_time)
                    self.successful_pings.append(ping_time)
                    
                    # Anlık ping göster
                    self.ping_label.config(text=f"{ping_time:.1f} ms", foreground='green')
                    consecutive_failures = 0
                    
                    # İstatistikleri güncelle
                    self.update_ping_statistics()
                    
                    # Log mesajı
                    self.log_message(f"Google DNS ({target_ip}) ping: {ping_time:.1f} ms")
                    
                else:
                    # Ping başarısız
                    failed_pings += 1
                    consecutive_failures += 1
                    self.ping_data.append(None)  # Başarısız ping için None
                    self.ping_label.config(text="Timeout", foreground='red')
                    self.log_message(f"Google DNS ({target_ip}) ping: TIMEOUT")
                
                # Paket kaybı hesapla
                packet_loss = (failed_pings / total_pings) * 100
                self.packet_loss_data.append(packet_loss)
                self.packet_loss_label.config(text=f"{packet_loss:.1f}%", 
                                            foreground='red' if packet_loss > 5 else 'green')
                
                # Bağlantı durumu
                if consecutive_failures >= 3:
                    self.status_label.config(text="❌ Bağlantı Kesildi", foreground='red')
                elif consecutive_failures == 0:
                    self.status_label.config(text="✅ Bağlı", foreground='green')
                else:
                    self.status_label.config(text="⚠️ Kararsız", foreground='orange')
                
                # Test sayısını güncelle
                self.total_tests_label.config(text=str(total_pings))
                
                time.sleep(interval)
                
            except subprocess.TimeoutExpired:
                failed_pings += 1
                consecutive_failures += 1
                total_pings += 1
                self.ping_data.append(None)
                self.ping_label.config(text="Timeout", foreground='red')
                self.log_message(f"Google DNS ping: TIMEOUT (command timeout)")
                time.sleep(1)
            except Exception as e:
                self.log_message(f"Ping hatası: {str(e)}")
                time.sleep(1)
    
    def update_ping_statistics(self):
        """Ping istatistiklerini güncelle"""
        if self.successful_pings:
            # Ortalama ping
            avg_ping = sum(self.successful_pings) / len(self.successful_pings)
            self.avg_ping_label.config(text=f"{avg_ping:.1f} ms")
            
            # En iyi ping
            best_ping = min(self.successful_pings)
            self.best_ping_label.config(text=f"{best_ping:.1f} ms")
            
            # En kötü ping
            worst_ping = max(self.successful_pings)
            self.worst_ping_label.config(text=f"{worst_ping:.1f} ms")
    
    def bandwidth_monitor(self):
        """Bant genişliği monitörleme"""
        prev_bytes_sent = 0
        prev_bytes_recv = 0
        prev_time = time.time()
        
        while self.monitoring:
            try:
                # Ağ istatistiklerini al
                net_io = psutil.net_io_counters()
                current_time = time.time()
                
                if prev_bytes_sent > 0:  # İlk ölçüm değilse
                    time_diff = current_time - prev_time
                    
                    # Upload hızı (MB/s)
                    upload_speed = (net_io.bytes_sent - prev_bytes_sent) / time_diff / (1024 * 1024)
                    # Download hızı (MB/s)
                    download_speed = (net_io.bytes_recv - prev_bytes_recv) / time_diff / (1024 * 1024)
                    
                    self.bandwidth_data.append((download_speed, upload_speed))
                    
                    self.download_label.config(text=f"{download_speed:.2f} MB/s")
                    self.upload_label.config(text=f"{upload_speed:.2f} MB/s")
                
                prev_bytes_sent = net_io.bytes_sent
                prev_bytes_recv = net_io.bytes_recv
                prev_time = current_time
                
                time.sleep(1)  # 1 saniye aralıkla ölç
                
            except Exception as e:
                self.log_message(f"Bant genişliği ölçüm hatası: {str(e)}")
                time.sleep(1)
    
    def interface_monitor(self):
        """Ağ arayüzü monitörleme"""
        while self.monitoring:
            try:
                # Ağ arayüzü bilgilerini topla
                interfaces = psutil.net_if_stats()
                addrs = psutil.net_if_addrs()
                
                active_interfaces = []
                for interface, stats in interfaces.items():
                    if stats.isup and interface in addrs:
                        for addr in addrs[interface]:
                            if addr.family == socket.AF_INET:  # IPv4
                                active_interfaces.append({
                                    'name': interface,
                                    'ip': addr.address,
                                    'speed': stats.speed if stats.speed > 0 else 'Unknown'
                                })
                
                if active_interfaces:
                    interface_info = ", ".join([f"{iface['name']} ({iface['ip']})" 
                                              for iface in active_interfaces])
                    self.log_message(f"Aktif arayüzler: {interface_info}")
                
                time.sleep(10)  # 10 saniyede bir kontrol et
                
            except Exception as e:
                self.log_message(f"Arayüz monitör hatası: {str(e)}")
                time.sleep(10)
    
    def update_graphs(self):
        """Grafikleri güncelle"""
        while self.monitoring:
            try:
                # Ping grafiği
                if self.ping_data:
                    self.ax1.clear()
                    self.ax1.set_title('Ping (ms)')
                    self.ax1.set_ylabel('Gecikme (ms)')
                    self.ax1.grid(True)
                    
                    valid_pings = [p for p in self.ping_data if p is not None]
                    if valid_pings:
                        x_values = range(len(list(self.ping_data)))
                        y_values = list(self.ping_data)
                        
                        # None değerleri için NaN kullan
                        y_values = [p if p is not None else np.nan for p in y_values]
                        
                        self.ax1.plot(x_values, y_values, 'b-', linewidth=2)
                        self.ax1.set_ylim(0, max(valid_pings) * 1.1 if valid_pings else 100)
                
                # Bant genişliği grafiği
                if self.bandwidth_data:
                    self.ax2.clear()
                    self.ax2.set_title('Bant Genişliği')
                    self.ax2.set_ylabel('Hız (MB/s)')
                    self.ax2.grid(True)
                    
                    x_values = range(len(self.bandwidth_data))
                    download_values = [d[0] for d in self.bandwidth_data]
                    upload_values = [d[1] for d in self.bandwidth_data]
                    
                    self.ax2.plot(x_values, download_values, 'g-', label='Download', linewidth=2)
                    self.ax2.plot(x_values, upload_values, 'r-', label='Upload', linewidth=2)
                    self.ax2.legend()
                
                # Paket kaybı grafiği
                if self.packet_loss_data:
                    self.ax3.clear()
                    self.ax3.set_title('Paket Kaybı')
                    self.ax3.set_ylabel('Kayıp (%)')
                    self.ax3.grid(True)
                    
                    x_values = range(len(self.packet_loss_data))
                    self.ax3.plot(x_values, list(self.packet_loss_data), 'r-', linewidth=2)
                    self.ax3.set_ylim(0, 100)
                
                # Ağ kullanımı grafiği
                try:
                    net_io = psutil.net_io_counters()
                    self.ax4.clear()
                    self.ax4.set_title('Toplam Ağ Trafiği')
                    self.ax4.set_ylabel('Bytes')
                    self.ax4.grid(True)
                    
                    categories = ['Gönderilen', 'Alınan']
                    values = [net_io.bytes_sent, net_io.bytes_recv]
                    colors = ['orange', 'green']
                    
                    bars = self.ax4.bar(categories, values, color=colors)
                    
                    # Değerleri MB cinsinden göster
                    for bar, value in zip(bars, values):
                        height = bar.get_height()
                        self.ax4.text(bar.get_x() + bar.get_width()/2., height,
                                    f'{value/(1024*1024):.1f} MB',
                                    ha='center', va='bottom')
                
                except:
                    pass
                
                self.canvas.draw()
                time.sleep(2)  # 2 saniyede bir güncelle
                
            except Exception as e:
                self.log_message(f"Grafik güncelleme hatası: {str(e)}")
                time.sleep(2)
    
    def log_message(self, message):
        """Log mesajı ekle"""
        timestamp = time.strftime("%H:%M:%S")
        log_entry = f"[{timestamp}] {message}\n"
        
        self.log_text.insert(tk.END, log_entry)
        self.log_text.see(tk.END)
        
        # Log uzunluğunu sınırla
        lines = self.log_text.get("1.0", tk.END).split('\n')
        if len(lines) > 100:  # Son 100 satırı tut
            self.log_text.delete("1.0", f"{len(lines)-100}.0")
    
    def cleanup(self):
        """Temizlik işlemleri"""
        self.monitoring = False 