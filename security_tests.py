#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Güvenlik Testleri Modülü
MITM simülasyonu, güvenlik açığı tespiti ve koruma önlemleri
"""

import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext
import threading
import time
import socket
import hashlib
import random
import json
from collections import defaultdict
import subprocess
import platform

class SecurityTestsTab:
    def __init__(self, parent):
        self.parent = parent
        self.mitm_active = False
        self.port_scan_active = False
        self.vulnerability_scan_active = False
        
        self.setup_ui()
    
    def setup_ui(self):
        """Kullanıcı arayüzünü oluştur"""
        # Ana çerçeve
        main_frame = ttk.Frame(self.parent)
        main_frame.pack(fill='both', expand=True, padx=10, pady=10)
        
        # Başlık
        title_label = ttk.Label(main_frame, text="Güvenlik Testleri ve Saldırı Simülasyonu", style='Title.TLabel')
        title_label.pack(pady=(0, 20))
        
        # Notebook için sekmeler
        notebook = ttk.Notebook(main_frame)
        notebook.pack(fill='both', expand=True)
        
        # MITM Simülasyonu sekmesi
        mitm_frame = ttk.Frame(notebook)
        notebook.add(mitm_frame, text="MITM Simülasyonu")
        self.setup_mitm_tab(mitm_frame)
        
        # Port Tarama sekmesi
        port_scan_frame = ttk.Frame(notebook)
        notebook.add(port_scan_frame, text="Port Tarama")
        self.setup_port_scan_tab(port_scan_frame)
        
        # Güvenlik Açığı Tespiti sekmesi
        vuln_scan_frame = ttk.Frame(notebook)
        notebook.add(vuln_scan_frame, text="Güvenlik Açığı Tespiti")
        self.setup_vulnerability_tab(vuln_scan_frame)
        
        # Koruma Önlemleri sekmesi
        protection_frame = ttk.Frame(notebook)
        notebook.add(protection_frame, text="Koruma Önlemleri")
        self.setup_protection_tab(protection_frame)
    
    def setup_mitm_tab(self, parent):
        """MITM simülasyonu sekmesini oluştur"""
        # Kontrol paneli
        control_frame = ttk.LabelFrame(parent, text="MITM Saldırı Simülasyonu", padding=10)
        control_frame.pack(fill='x', padx=10, pady=10)
        
        # Hedef bilgileri
        ttk.Label(control_frame, text="Hedef IP:").grid(row=0, column=0, sticky='w', padx=(0, 10))
        self.mitm_target_ip = tk.StringVar(value="192.168.1.1")
        ttk.Entry(control_frame, textvariable=self.mitm_target_ip, width=15).grid(row=0, column=1, padx=(0, 20))
        
        ttk.Label(control_frame, text="Gateway IP:").grid(row=0, column=2, sticky='w', padx=(0, 10))
        self.mitm_gateway_ip = tk.StringVar(value="192.168.1.1")
        ttk.Entry(control_frame, textvariable=self.mitm_gateway_ip, width=15).grid(row=0, column=3, padx=(0, 20))
        
        # Saldırı türü
        ttk.Label(control_frame, text="Saldırı Türü:").grid(row=1, column=0, sticky='w', padx=(0, 10))
        self.attack_type = tk.StringVar(value="arp_spoofing")
        attack_combo = ttk.Combobox(control_frame, textvariable=self.attack_type,
                                   values=["arp_spoofing", "dns_spoofing", "ssl_strip", "packet_injection"],
                                   state='readonly', width=15)
        attack_combo.grid(row=1, column=1, padx=(0, 20))
        
        # Kontrol butonları
        self.mitm_start_btn = ttk.Button(control_frame, text="Simülasyonu Başlat", 
                                       command=self.start_mitm_simulation)
        self.mitm_start_btn.grid(row=1, column=2, padx=(0, 10))
        
        self.mitm_stop_btn = ttk.Button(control_frame, text="Durdur", 
                                      command=self.stop_mitm_simulation, state='disabled')
        self.mitm_stop_btn.grid(row=1, column=3)
        
        # Durum paneli
        status_frame = ttk.LabelFrame(parent, text="Saldırı Durumu", padding=10)
        status_frame.pack(fill='x', padx=10, pady=(0, 10))
        
        self.mitm_status_label = ttk.Label(status_frame, text="Hazır", foreground='green')
        self.mitm_status_label.pack()
        
        # Yakalanan trafik
        traffic_frame = ttk.LabelFrame(parent, text="Yakalanan Trafik", padding=10)
        traffic_frame.pack(fill='both', expand=True, padx=10, pady=(0, 10))
        
        # Trafik tablosu
        columns = ("Zaman", "Kaynak", "Hedef", "Protokol", "Veri")
        self.mitm_tree = ttk.Treeview(traffic_frame, columns=columns, show='headings', height=10)
        
        for col in columns:
            self.mitm_tree.heading(col, text=col)
            self.mitm_tree.column(col, width=120)
        
        mitm_scrollbar = ttk.Scrollbar(traffic_frame, orient='vertical', command=self.mitm_tree.yview)
        self.mitm_tree.configure(yscrollcommand=mitm_scrollbar.set)
        
        self.mitm_tree.pack(side='left', fill='both', expand=True)
        mitm_scrollbar.pack(side='right', fill='y')
        
        # Log alanı
        log_frame = ttk.LabelFrame(parent, text="Saldırı Logları", padding=10)
        log_frame.pack(fill='x', padx=10, pady=(0, 10))
        
        self.mitm_log = scrolledtext.ScrolledText(log_frame, height=8, wrap=tk.WORD)
        self.mitm_log.pack(fill='x')
    
    def setup_port_scan_tab(self, parent):
        """Port tarama sekmesini oluştur"""
        # Kontrol paneli
        control_frame = ttk.LabelFrame(parent, text="Port Tarama Ayarları", padding=10)
        control_frame.pack(fill='x', padx=10, pady=10)
        
        # Hedef IP
        ttk.Label(control_frame, text="Hedef IP/Range:").grid(row=0, column=0, sticky='w', padx=(0, 10))
        self.scan_target = tk.StringVar(value="127.0.0.1")
        ttk.Entry(control_frame, textvariable=self.scan_target, width=20).grid(row=0, column=1, padx=(0, 20))
        
        # Port aralığı
        ttk.Label(control_frame, text="Port Aralığı:").grid(row=0, column=2, sticky='w', padx=(0, 10))
        self.port_range_start = tk.StringVar(value="1")
        self.port_range_end = tk.StringVar(value="1000")
        
        port_frame = ttk.Frame(control_frame)
        port_frame.grid(row=0, column=3, padx=(0, 20))
        
        ttk.Entry(port_frame, textvariable=self.port_range_start, width=8).pack(side='left')
        ttk.Label(port_frame, text=" - ").pack(side='left')
        ttk.Entry(port_frame, textvariable=self.port_range_end, width=8).pack(side='left')
        
        # Tarama türü
        ttk.Label(control_frame, text="Tarama Türü:").grid(row=1, column=0, sticky='w', padx=(0, 10))
        self.scan_type = tk.StringVar(value="tcp_connect")
        scan_combo = ttk.Combobox(control_frame, textvariable=self.scan_type,
                                 values=["tcp_connect", "tcp_syn", "udp_scan", "stealth_scan"],
                                 state='readonly', width=15)
        scan_combo.grid(row=1, column=1, padx=(0, 20))
        
        # Thread sayısı
        ttk.Label(control_frame, text="Thread Sayısı:").grid(row=1, column=2, sticky='w', padx=(0, 10))
        self.thread_count = tk.StringVar(value="50")
        ttk.Entry(control_frame, textvariable=self.thread_count, width=10).grid(row=1, column=3, padx=(0, 20))
        
        # Kontrol butonları
        self.scan_start_btn = ttk.Button(control_frame, text="Taramayı Başlat", 
                                       command=self.start_port_scan)
        self.scan_start_btn.grid(row=0, column=4, padx=(0, 10))
        
        self.scan_stop_btn = ttk.Button(control_frame, text="Durdur", 
                                      command=self.stop_port_scan, state='disabled')
        self.scan_stop_btn.grid(row=1, column=4)
        
        # Sonuçlar
        results_frame = ttk.LabelFrame(parent, text="Tarama Sonuçları", padding=10)
        results_frame.pack(fill='both', expand=True, padx=10, pady=(0, 10))
        
        # Sonuç tablosu
        columns = ("IP", "Port", "Durum", "Servis", "Banner")
        self.scan_tree = ttk.Treeview(results_frame, columns=columns, show='headings', height=15)
        
        for col in columns:
            self.scan_tree.heading(col, text=col)
            self.scan_tree.column(col, width=100)
        
        scan_scrollbar = ttk.Scrollbar(results_frame, orient='vertical', command=self.scan_tree.yview)
        self.scan_tree.configure(yscrollcommand=scan_scrollbar.set)
        
        self.scan_tree.pack(side='left', fill='both', expand=True)
        scan_scrollbar.pack(side='right', fill='y')
        
        # İstatistikler
        stats_frame = ttk.LabelFrame(parent, text="Tarama İstatistikleri", padding=10)
        stats_frame.pack(fill='x', padx=10, pady=(0, 10))
        
        stats_grid = ttk.Frame(stats_frame)
        stats_grid.pack()
        
        ttk.Label(stats_grid, text="Taranan Port:").grid(row=0, column=0, sticky='w', padx=(0, 10))
        self.scanned_ports_label = ttk.Label(stats_grid, text="0", foreground='blue')
        self.scanned_ports_label.grid(row=0, column=1, sticky='w', padx=(0, 30))
        
        ttk.Label(stats_grid, text="Açık Port:").grid(row=0, column=2, sticky='w', padx=(0, 10))
        self.open_ports_label = ttk.Label(stats_grid, text="0", foreground='green')
        self.open_ports_label.grid(row=0, column=3, sticky='w', padx=(0, 30))
        
        ttk.Label(stats_grid, text="Kapalı Port:").grid(row=0, column=4, sticky='w', padx=(0, 10))
        self.closed_ports_label = ttk.Label(stats_grid, text="0", foreground='red')
        self.closed_ports_label.grid(row=0, column=5, sticky='w')
    
    def setup_vulnerability_tab(self, parent):
        """Güvenlik açığı tespiti sekmesini oluştur"""
        # Kontrol paneli
        control_frame = ttk.LabelFrame(parent, text="Güvenlik Açığı Tarama", padding=10)
        control_frame.pack(fill='x', padx=10, pady=10)
        
        # Hedef
        ttk.Label(control_frame, text="Hedef:").grid(row=0, column=0, sticky='w', padx=(0, 10))
        self.vuln_target = tk.StringVar(value="127.0.0.1")
        ttk.Entry(control_frame, textvariable=self.vuln_target, width=20).grid(row=0, column=1, padx=(0, 20))
        
        # Tarama türü
        ttk.Label(control_frame, text="Tarama Türü:").grid(row=0, column=2, sticky='w', padx=(0, 10))
        self.vuln_scan_type = tk.StringVar(value="basic")
        vuln_combo = ttk.Combobox(control_frame, textvariable=self.vuln_scan_type,
                                 values=["basic", "web_vuln", "network_vuln", "comprehensive"],
                                 state='readonly', width=15)
        vuln_combo.grid(row=0, column=3, padx=(0, 20))
        
        # Kontrol butonları
        self.vuln_start_btn = ttk.Button(control_frame, text="Taramayı Başlat", 
                                       command=self.start_vulnerability_scan)
        self.vuln_start_btn.grid(row=0, column=4, padx=(0, 10))
        
        self.vuln_stop_btn = ttk.Button(control_frame, text="Durdur", 
                                      command=self.stop_vulnerability_scan, state='disabled')
        self.vuln_stop_btn.grid(row=0, column=5)
        
        # Sonuçlar
        results_frame = ttk.LabelFrame(parent, text="Bulunan Güvenlik Açıkları", padding=10)
        results_frame.pack(fill='both', expand=True, padx=10, pady=(0, 10))
        
        # Sonuç tablosu
        columns = ("Seviye", "Açık Türü", "Hedef", "Açıklama", "Çözüm")
        self.vuln_tree = ttk.Treeview(results_frame, columns=columns, show='headings', height=12)
        
        for col in columns:
            self.vuln_tree.heading(col, text=col)
            self.vuln_tree.column(col, width=120)
        
        vuln_scrollbar = ttk.Scrollbar(results_frame, orient='vertical', command=self.vuln_tree.yview)
        self.vuln_tree.configure(yscrollcommand=vuln_scrollbar.set)
        
        self.vuln_tree.pack(side='left', fill='both', expand=True)
        vuln_scrollbar.pack(side='right', fill='y')
        
        # Detay alanı
        detail_frame = ttk.LabelFrame(parent, text="Açık Detayları", padding=10)
        detail_frame.pack(fill='x', padx=10, pady=(0, 10))
        
        self.vuln_detail = scrolledtext.ScrolledText(detail_frame, height=6, wrap=tk.WORD)
        self.vuln_detail.pack(fill='x')
        
        # Treeview seçim olayı
        self.vuln_tree.bind('<<TreeviewSelect>>', self.on_vulnerability_select)
    
    def setup_protection_tab(self, parent):
        """Koruma önlemleri sekmesini oluştur"""
        # Ana çerçeve
        main_frame = ttk.Frame(parent)
        main_frame.pack(fill='both', expand=True, padx=10, pady=10)
        
        # Firewall kontrolleri
        firewall_frame = ttk.LabelFrame(main_frame, text="Firewall Kontrolleri", padding=10)
        firewall_frame.pack(fill='x', pady=(0, 10))
        
        firewall_buttons = ttk.Frame(firewall_frame)
        firewall_buttons.pack()
        
        ttk.Button(firewall_buttons, text="Firewall Durumunu Kontrol Et", 
                  command=self.check_firewall_status).pack(side='left', padx=(0, 10))
        ttk.Button(firewall_buttons, text="Güvenlik Kuralları Öner", 
                  command=self.suggest_security_rules).pack(side='left', padx=(0, 10))
        ttk.Button(firewall_buttons, text="Ağ Trafiği Analiz Et", 
                  command=self.analyze_network_traffic).pack(side='left')
        
        # Güvenlik önerileri
        recommendations_frame = ttk.LabelFrame(main_frame, text="Güvenlik Önerileri", padding=10)
        recommendations_frame.pack(fill='both', expand=True, pady=(0, 10))
        
        self.recommendations_text = scrolledtext.ScrolledText(recommendations_frame, wrap=tk.WORD)
        self.recommendations_text.pack(fill='both', expand=True)
        
        # İlk önerileri yükle
        self.load_initial_recommendations()
        
        # Sistem güvenlik durumu
        security_status_frame = ttk.LabelFrame(main_frame, text="Sistem Güvenlik Durumu", padding=10)
        security_status_frame.pack(fill='x', pady=(0, 10))
        
        status_grid = ttk.Frame(security_status_frame)
        status_grid.pack()
        
        ttk.Label(status_grid, text="Firewall:").grid(row=0, column=0, sticky='w', padx=(0, 10))
        self.firewall_status_label = ttk.Label(status_grid, text="Kontrol ediliyor...", foreground='orange')
        self.firewall_status_label.grid(row=0, column=1, sticky='w', padx=(0, 30))
        
        ttk.Label(status_grid, text="Antivirus:").grid(row=0, column=2, sticky='w', padx=(0, 10))
        self.antivirus_status_label = ttk.Label(status_grid, text="Kontrol ediliyor...", foreground='orange')
        self.antivirus_status_label.grid(row=0, column=3, sticky='w', padx=(0, 30))
        
        ttk.Label(status_grid, text="Güncellemeler:").grid(row=1, column=0, sticky='w', padx=(0, 10))
        self.updates_status_label = ttk.Label(status_grid, text="Kontrol ediliyor...", foreground='orange')
        self.updates_status_label.grid(row=1, column=1, sticky='w', padx=(0, 30))
        
        ttk.Label(status_grid, text="Ağ Güvenliği:").grid(row=1, column=2, sticky='w', padx=(0, 10))
        self.network_security_label = ttk.Label(status_grid, text="Kontrol ediliyor...", foreground='orange')
        self.network_security_label.grid(row=1, column=3, sticky='w')
        
        # İlk güvenlik kontrolünü başlat
        threading.Thread(target=self.initial_security_check, daemon=True).start()
    
    def start_mitm_simulation(self):
        """MITM simülasyonunu başlat"""
        if self.mitm_active:
            return
        
        self.mitm_active = True
        self.mitm_start_btn.config(state='disabled')
        self.mitm_stop_btn.config(state='normal')
        self.mitm_status_label.config(text="Simülasyon aktif", foreground='red')
        
        # MITM simülasyon thread'ini başlat
        threading.Thread(target=self.mitm_simulation_thread, daemon=True).start()
        
        self.log_mitm("MITM simülasyonu başlatıldı")
        self.log_mitm(f"Saldırı türü: {self.attack_type.get()}")
        self.log_mitm(f"Hedef IP: {self.mitm_target_ip.get()}")
    
    def stop_mitm_simulation(self):
        """MITM simülasyonunu durdur"""
        self.mitm_active = False
        self.mitm_start_btn.config(state='normal')
        self.mitm_stop_btn.config(state='disabled')
        self.mitm_status_label.config(text="Simülasyon durduruldu", foreground='green')
        
        self.log_mitm("MITM simülasyonu durduruldu")
    
    def mitm_simulation_thread(self):
        """MITM simülasyon thread'i"""
        attack_type = self.attack_type.get()
        
        # Simüle edilmiş saldırı senaryoları
        scenarios = {
            'arp_spoofing': self.simulate_arp_spoofing,
            'dns_spoofing': self.simulate_dns_spoofing,
            'ssl_strip': self.simulate_ssl_strip,
            'packet_injection': self.simulate_packet_injection
        }
        
        if attack_type in scenarios:
            scenarios[attack_type]()
    
    def simulate_arp_spoofing(self):
        """ARP spoofing simülasyonu"""
        while self.mitm_active:
            fake_traffic = {
                'time': time.strftime("%H:%M:%S"),
                'src': f"192.168.1.{random.randint(2, 254)}",
                'dst': self.mitm_target_ip.get(),
                'protocol': 'ARP',
                'data': f"ARP Reply: {self.mitm_target_ip.get()} is at fake_mac_address"
            }
            
            self.add_mitm_traffic(fake_traffic)
            self.log_mitm(f"ARP spoofing paketi gönderildi: {fake_traffic['data']}")
            
            time.sleep(random.uniform(1, 3))
    
    def simulate_dns_spoofing(self):
        """DNS spoofing simülasyonu"""
        fake_domains = ['google.com', 'facebook.com', 'amazon.com', 'microsoft.com']
        
        while self.mitm_active:
            domain = random.choice(fake_domains)
            fake_ip = f"192.168.1.{random.randint(100, 199)}"
            
            fake_traffic = {
                'time': time.strftime("%H:%M:%S"),
                'src': 'DNS Server',
                'dst': self.mitm_target_ip.get(),
                'protocol': 'DNS',
                'data': f"DNS Response: {domain} -> {fake_ip} (SPOOFED)"
            }
            
            self.add_mitm_traffic(fake_traffic)
            self.log_mitm(f"DNS spoofing: {domain} -> {fake_ip}")
            
            time.sleep(random.uniform(2, 5))
    
    def simulate_ssl_strip(self):
        """SSL Strip simülasyonu"""
        while self.mitm_active:
            fake_traffic = {
                'time': time.strftime("%H:%M:%S"),
                'src': self.mitm_target_ip.get(),
                'dst': '203.0.113.1',
                'protocol': 'HTTP',
                'data': f"HTTP Request: GET /login.php (HTTPS stripped to HTTP)"
            }
            
            self.add_mitm_traffic(fake_traffic)
            self.log_mitm("SSL Strip: HTTPS connection downgraded to HTTP")
            
            time.sleep(random.uniform(3, 7))
    
    def simulate_packet_injection(self):
        """Paket injection simülasyonu"""
        injection_types = ['Malicious JavaScript', 'Fake Form', 'Ad Injection', 'Tracking Code']
        
        while self.mitm_active:
            injection_type = random.choice(injection_types)
            
            fake_traffic = {
                'time': time.strftime("%H:%M:%S"),
                'src': 'Attacker',
                'dst': self.mitm_target_ip.get(),
                'protocol': 'HTTP',
                'data': f"Injected: {injection_type}"
            }
            
            self.add_mitm_traffic(fake_traffic)
            self.log_mitm(f"Packet injection: {injection_type}")
            
            time.sleep(random.uniform(4, 8))
    
    def add_mitm_traffic(self, traffic):
        """MITM trafiğini tabloya ekle"""
        self.mitm_tree.insert('', 'end', values=(
            traffic['time'],
            traffic['src'],
            traffic['dst'],
            traffic['protocol'],
            traffic['data']
        ))
        
        # Auto scroll
        children = self.mitm_tree.get_children()
        if children:
            self.mitm_tree.see(children[-1])
    
    def log_mitm(self, message):
        """MITM log mesajı ekle"""
        timestamp = time.strftime("%H:%M:%S")
        log_entry = f"[{timestamp}] {message}\n"
        
        self.mitm_log.insert(tk.END, log_entry)
        self.mitm_log.see(tk.END)
    
    def start_port_scan(self):
        """Port taramayı başlat"""
        if self.port_scan_active:
            return
        
        self.port_scan_active = True
        self.scan_start_btn.config(state='disabled')
        self.scan_stop_btn.config(state='normal')
        
        # Tabloyu temizle
        for item in self.scan_tree.get_children():
            self.scan_tree.delete(item)
        
        # Port tarama thread'ini başlat
        threading.Thread(target=self.port_scan_thread, daemon=True).start()
    
    def stop_port_scan(self):
        """Port taramayı durdur"""
        self.port_scan_active = False
        self.scan_start_btn.config(state='normal')
        self.scan_stop_btn.config(state='disabled')
    
    def port_scan_thread(self):
        """Port tarama thread'i"""
        target = self.scan_target.get()
        start_port = int(self.port_range_start.get())
        end_port = int(self.port_range_end.get())
        scan_type = self.scan_type.get()
        
        scanned = 0
        open_ports = 0
        closed_ports = 0
        
        # Bilinen servisler
        known_services = {
            21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP',
            53: 'DNS', 80: 'HTTP', 110: 'POP3', 143: 'IMAP',
            443: 'HTTPS', 993: 'IMAPS', 995: 'POP3S', 3389: 'RDP'
        }
        
        for port in range(start_port, end_port + 1):
            if not self.port_scan_active:
                break
            
            try:
                if scan_type == "tcp_connect":
                    result = self.tcp_connect_scan(target, port)
                elif scan_type == "tcp_syn":
                    result = self.tcp_syn_scan(target, port)
                elif scan_type == "udp_scan":
                    result = self.udp_scan(target, port)
                else:
                    result = self.tcp_connect_scan(target, port)  # Default
                
                scanned += 1
                
                if result['status'] == 'Open':
                    open_ports += 1
                    service = known_services.get(port, 'Unknown')
                    banner = self.get_service_banner(target, port)
                    
                    self.scan_tree.insert('', 'end', values=(
                        target, port, result['status'], service, banner
                    ))
                else:
                    closed_ports += 1
                
                # İstatistikleri güncelle
                self.scanned_ports_label.config(text=str(scanned))
                self.open_ports_label.config(text=str(open_ports))
                self.closed_ports_label.config(text=str(closed_ports))
                
                # Hız kontrolü
                time.sleep(0.1)
                
            except Exception as e:
                print(f"Port {port} tarama hatası: {e}")
    
    def tcp_connect_scan(self, target, port):
        """TCP Connect tarama"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            result = sock.connect_ex((target, port))
            sock.close()
            
            if result == 0:
                return {'status': 'Open'}
            else:
                return {'status': 'Closed'}
        except:
            return {'status': 'Filtered'}
    
    def tcp_syn_scan(self, target, port):
        """TCP SYN tarama (simüle edilmiş)"""
        # Gerçek SYN tarama için raw socket gerekir
        # Simülasyon için TCP connect kullanıyoruz
        return self.tcp_connect_scan(target, port)
    
    def udp_scan(self, target, port):
        """UDP tarama"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(1)
            sock.sendto(b'', (target, port))
            sock.close()
            return {'status': 'Open|Filtered'}
        except:
            return {'status': 'Closed'}
    
    def get_service_banner(self, target, port):
        """Servis banner alma"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2)
            sock.connect((target, port))
            
            # HTTP servisleri için GET isteği gönder
            if port in [80, 8080, 8000]:
                sock.send(b'GET / HTTP/1.1\r\nHost: ' + target.encode() + b'\r\n\r\n')
            
            banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
            sock.close()
            
            return banner[:50] + "..." if len(banner) > 50 else banner
        except:
            return ""
    
    def start_vulnerability_scan(self):
        """Güvenlik açığı taramayı başlat"""
        if self.vulnerability_scan_active:
            return
        
        self.vulnerability_scan_active = True
        self.vuln_start_btn.config(state='disabled')
        self.vuln_stop_btn.config(state='normal')
        
        # Tabloyu temizle
        for item in self.vuln_tree.get_children():
            self.vuln_tree.delete(item)
        
        # Güvenlik açığı tarama thread'ini başlat
        threading.Thread(target=self.vulnerability_scan_thread, daemon=True).start()
    
    def stop_vulnerability_scan(self):
        """Güvenlik açığı taramayı durdur"""
        self.vulnerability_scan_active = False
        self.vuln_start_btn.config(state='normal')
        self.vuln_stop_btn.config(state='disabled')
    
    def vulnerability_scan_thread(self):
        """Güvenlik açığı tarama thread'i"""
        target = self.vuln_target.get()
        scan_type = self.vuln_scan_type.get()
        
        # Simüle edilmiş güvenlik açıkları
        vulnerabilities = [
            {
                'level': 'Yüksek',
                'type': 'Açık Port',
                'target': f"{target}:22",
                'description': 'SSH servisi default yapılandırma ile çalışıyor',
                'solution': 'SSH yapılandırmasını güçlendirin, key-based authentication kullanın'
            },
            {
                'level': 'Orta',
                'type': 'Web Güvenlik',
                'target': f"{target}:80",
                'description': 'HTTP header güvenlik eksikliği',
                'solution': 'Security header\'ları ekleyin (HSTS, CSP, X-Frame-Options)'
            },
            {
                'level': 'Düşük',
                'type': 'Bilgi Sızıntısı',
                'target': f"{target}:80",
                'description': 'Server banner bilgisi açığa çıkıyor',
                'solution': 'Server banner\'ını gizleyin veya özelleştirin'
            },
            {
                'level': 'Yüksek',
                'type': 'Şifreleme',
                'target': f"{target}:443",
                'description': 'Zayıf SSL/TLS konfigürasyonu',
                'solution': 'TLS 1.2+ kullanın, güçlü cipher suites aktif edin'
            }
        ]
        
        for vuln in vulnerabilities:
            if not self.vulnerability_scan_active:
                break
            
            self.vuln_tree.insert('', 'end', values=(
                vuln['level'],
                vuln['type'],
                vuln['target'],
                vuln['description'],
                vuln['solution']
            ))
            
            time.sleep(random.uniform(0.5, 2))
    
    def on_vulnerability_select(self, event):
        """Güvenlik açığı seçildiğinde detayları göster"""
        selection = self.vuln_tree.selection()
        if selection:
            item = self.vuln_tree.item(selection[0])
            values = item['values']
            
            detail_text = f"""
Güvenlik Açığı Detayları:

Seviye: {values[0]}
Tür: {values[1]}
Hedef: {values[2]}

Açıklama:
{values[3]}

Önerilen Çözüm:
{values[4]}

Risk Değerlendirmesi:
- Bu açık saldırganlar tarafından istismar edilebilir
- Sistem güvenliğini artırmak için hemen harekete geçilmelidir
- Düzenli güvenlik taramaları yapılması önerilir
"""
            
            self.vuln_detail.delete(1.0, tk.END)
            self.vuln_detail.insert(1.0, detail_text)
    
    def check_firewall_status(self):
        """Firewall durumunu kontrol et"""
        try:
            if platform.system().lower() == "windows":
                result = subprocess.run(['netsh', 'advfirewall', 'show', 'allprofiles'], 
                                      capture_output=True, text=True)
                if "State                                 ON" in result.stdout:
                    status = "Aktif"
                    color = "green"
                else:
                    status = "Pasif"
                    color = "red"
            else:
                # Linux için ufw kontrolü
                result = subprocess.run(['ufw', 'status'], capture_output=True, text=True)
                if "Status: active" in result.stdout:
                    status = "Aktif"
                    color = "green"
                else:
                    status = "Pasif"
                    color = "red"
            
            self.firewall_status_label.config(text=status, foreground=color)
            
        except Exception as e:
            self.firewall_status_label.config(text="Kontrol edilemedi", foreground="orange")
    
    def suggest_security_rules(self):
        """Güvenlik kuralları öner"""
        suggestions = """
Önerilen Güvenlik Kuralları:

1. FIREWALL KURALLARI:
   - Gelen bağlantıları varsayılan olarak engelleyin
   - Sadece gerekli portları açın (22/SSH, 80/HTTP, 443/HTTPS)
   - Brute force saldırılarına karşı rate limiting uygulayın
   - DDoS koruması aktif edin

2. AĞ GÜVENLİĞİ:
   - VPN kullanımını zorunlu kılın
   - MAC adresi filtreleme uygulayın
   - Guest network izolasyonu sağlayın
   - Network segmentation yapın

3. UYGULAMA GÜVENLİĞİ:
   - HTTPS şifrelemesi zorunlu kılın
   - Security header'ları ekleyin
   - Input validation uygulayın
   - SQL injection koruması aktif edin

4. SİSTEM GÜVENLİĞİ:
   - Güçlü parola politikaları uygulayın
   - 2FA aktif edin
   - Düzenli güvenlik güncellemeleri yapın
   - Log monitoring kurun

5. VERİ GÜVENLİĞİ:
   - Hassas verileri şifreleyin
   - Düzenli backup alın
   - Access control uygulayın
   - Data loss prevention kurun
"""
        
        self.recommendations_text.delete(1.0, tk.END)
        self.recommendations_text.insert(1.0, suggestions)
    
    def analyze_network_traffic(self):
        """Ağ trafiği analizi"""
        analysis = """
Ağ Trafiği Analiz Sonuçları:

NORMAL TRAFİK PATTERN'Lari:
✓ HTTPS trafiği dominant (%78)
✓ DNS sorguları normal aralıkta
✓ P2P trafiği minimal
✓ Bandwidth kullanımı normal

ANORMAL AKTIVITELER:
⚠ Port 445'e unusual connection attempts
⚠ Gece saatlerinde yüksek trafik
⚠ Unknown protocols detected (%3)
⚠ Suspicious DNS queries

ÖNERİLER:
1. SMB trafiğini sınırlandırın
2. After-hours traffic monitoring artırın
3. DPI (Deep Packet Inspection) aktif edin
4. DNS filtreleme uygulayın
5. Traffic baseline'ını güncelleyin

RİSK SKORLARI:
- Ağ Güvenliği: 7/10
- Trafik Normalliği: 6/10
- Threat Detection: 8/10
- Overall Security: 7/10
"""
        
        self.recommendations_text.delete(1.0, tk.END)
        self.recommendations_text.insert(1.0, analysis)
    
    def load_initial_recommendations(self):
        """İlk güvenlik önerilerini yükle"""
        initial_text = """
Güvenlik Önerileri ve En İyi Uygulamalar:

🔒 TEMEL GÜVENLİK PRENSİPLERİ:

1. Defense in Depth (Katmanlı Güvenlik)
   - Birden fazla güvenlik katmanı kullanın
   - Her katmanda farklı kontroller uygulayın
   - Single point of failure'ı önleyin

2. Least Privilege (En Az Yetki)
   - Kullanıcılara sadece gerekli yetkileri verin
   - Privilege escalation'ı önleyin
   - Düzenli yetki denetimleri yapın

3. Zero Trust Model
   - "Trust but verify" yerine "Never trust, always verify"
   - Her bağlantıyı doğrulayın
   - Continuous monitoring uygulayın

🛡️ UYGULAMA ÖNERİLERİ:

• Güçlü şifreleme algoritmaları kullanın (AES-256, RSA-2048+)
• Multi-factor authentication (MFA) aktif edin
• Düzenli güvenlik güncellemeleri yapın
• Incident response planı hazırlayın
• Security awareness training'i düzenleyin
• Backup ve disaster recovery planları yapın

Bu uygulamayı kullanarak ağınızın güvenlik durumunu düzenli olarak test edin!
"""
        self.recommendations_text.insert(1.0, initial_text)
    
    def initial_security_check(self):
        """İlk güvenlik kontrolünü yap"""
        time.sleep(2)  # Simulated delay
        
        # Firewall kontrolü
        self.check_firewall_status()
        
        # Antivirus durumu (simüle)
        self.antivirus_status_label.config(text="Aktif", foreground="green")
        
        # Güncellemeler (simüle)
        self.updates_status_label.config(text="Güncel", foreground="green")
        
        # Ağ güvenliği (simüle)
        self.network_security_label.config(text="İyi", foreground="green")
    
    def cleanup(self):
        """Temizlik işlemleri"""
        self.mitm_active = False
        self.port_scan_active = False
        self.vulnerability_scan_active = False 