#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Güvenli Dosya Transferi Modülü
RSA + AES hibrit şifreleme, dijital imza ve büyük dosya desteği
"""

import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext
import threading
import socket
import os
import json
import hashlib
import base64
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import time

class FileTransferTab:
    def __init__(self, parent):
        self.parent = parent
        self.server_socket = None
        self.client_socket = None
        self.is_server_running = False
        self.transfer_in_progress = False
        
        # RSA anahtar çifti
        self.private_key = None
        self.public_key = None
        self.peer_public_key = None
        
        self.setup_ui()
        self.generate_keys()
    
    def setup_ui(self):
        """Kullanıcı arayüzünü oluştur"""
        # Ana çerçeve
        main_frame = ttk.Frame(self.parent)
        main_frame.pack(fill='both', expand=True, padx=10, pady=10)
        
        # Başlık
        title_label = ttk.Label(main_frame, text="Güvenli Dosya Transferi", style='Title.TLabel')
        title_label.pack(pady=(0, 20))
        
        # Sunucu/İstemci seçimi
        mode_frame = ttk.LabelFrame(main_frame, text="Mod Seçimi", padding=10)
        mode_frame.pack(fill='x', pady=(0, 10))
        
        self.mode_var = tk.StringVar(value="server")
        ttk.Radiobutton(mode_frame, text="Sunucu", variable=self.mode_var, 
                       value="server", command=self.on_mode_change).pack(side='left', padx=(0, 20))
        ttk.Radiobutton(mode_frame, text="İstemci", variable=self.mode_var, 
                       value="client", command=self.on_mode_change).pack(side='left')
        
        # Bağlantı ayarları
        connection_frame = ttk.LabelFrame(main_frame, text="Bağlantı Ayarları", padding=10)
        connection_frame.pack(fill='x', pady=(0, 10))
        
        # IP ve Port
        ttk.Label(connection_frame, text="IP Adresi:").grid(row=0, column=0, sticky='w', padx=(0, 10))
        self.ip_entry = ttk.Entry(connection_frame, width=15)
        self.ip_entry.insert(0, "127.0.0.1")
        self.ip_entry.grid(row=0, column=1, padx=(0, 20))
        
        ttk.Label(connection_frame, text="Port:").grid(row=0, column=2, sticky='w', padx=(0, 10))
        self.port_entry = ttk.Entry(connection_frame, width=10)
        self.port_entry.insert(0, "8888")
        self.port_entry.grid(row=0, column=3, padx=(0, 20))
        
        # Bağlantı kontrol butonları
        self.start_button = ttk.Button(connection_frame, text="Sunucuyu Başlat", 
                                     command=self.start_server)
        self.start_button.grid(row=0, column=4, padx=(0, 10))
        
        self.connect_button = ttk.Button(connection_frame, text="Bağlan", 
                                       command=self.connect_to_server, state='disabled')
        self.connect_button.grid(row=0, column=5)
        
        # Dosya seçimi
        file_frame = ttk.LabelFrame(main_frame, text="Dosya İşlemleri", padding=10)
        file_frame.pack(fill='x', pady=(0, 10))
        
        ttk.Label(file_frame, text="Seçilen Dosya:").grid(row=0, column=0, sticky='w', padx=(0, 10))
        self.file_path_var = tk.StringVar()
        file_entry = ttk.Entry(file_frame, textvariable=self.file_path_var, width=50, state='readonly')
        file_entry.grid(row=0, column=1, padx=(0, 10))
        
        ttk.Button(file_frame, text="Dosya Seç", command=self.select_file).grid(row=0, column=2, padx=(0, 10))
        ttk.Button(file_frame, text="Gönder", command=self.send_file).grid(row=0, column=3)
        
        # Transfer durumu
        status_frame = ttk.LabelFrame(main_frame, text="Transfer Durumu", padding=10)
        status_frame.pack(fill='x', pady=(0, 10))
        
        self.progress_var = tk.DoubleVar()
        self.progress_bar = ttk.Progressbar(status_frame, variable=self.progress_var, maximum=100)
        self.progress_bar.pack(fill='x', pady=(0, 10))
        
        self.status_label = ttk.Label(status_frame, text="Hazır")
        self.status_label.pack()
        
        # Güvenlik bilgileri
        security_frame = ttk.LabelFrame(main_frame, text="Güvenlik Bilgileri", padding=10)
        security_frame.pack(fill='both', expand=True)
        
        self.security_text = scrolledtext.ScrolledText(security_frame, height=15, wrap=tk.WORD)
        self.security_text.pack(fill='both', expand=True)
        
        # İlk mod ayarı
        self.on_mode_change()
    
    def generate_keys(self):
        """RSA anahtar çifti oluştur"""
        try:
            self.private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=2048
            )
            self.public_key = self.private_key.public_key()
            
            self.log_security("RSA anahtar çifti oluşturuldu (2048 bit)")
            
            # Public key'i PEM formatında al
            public_pem = self.public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ).decode('utf-8')
            
            self.log_security(f"Public Key:\n{public_pem}")
            
        except Exception as e:
            messagebox.showerror("Hata", f"Anahtar oluşturma hatası: {str(e)}")
    
    def on_mode_change(self):
        """Mod değiştiğinde UI'yi güncelle"""
        if self.mode_var.get() == "server":
            self.start_button.config(state='normal')
            self.connect_button.config(state='disabled')
            self.ip_entry.config(state='disabled')
        else:
            self.start_button.config(state='disabled')
            self.connect_button.config(state='normal')
            self.ip_entry.config(state='normal')
    
    def start_server(self):
        """Sunucuyu başlat"""
        if self.is_server_running:
            self.stop_server()
            return
        
        try:
            port = int(self.port_entry.get())
            self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.server_socket.bind(('', port))
            self.server_socket.listen(1)
            
            self.is_server_running = True
            self.start_button.config(text="Sunucuyu Durdur")
            self.log_security(f"Sunucu port {port}'da başlatıldı")
            
            # İstemci bekleme thread'i
            threading.Thread(target=self.wait_for_client, daemon=True).start()
            
        except Exception as e:
            messagebox.showerror("Hata", f"Sunucu başlatma hatası: {str(e)}")
    
    def stop_server(self):
        """Sunucuyu durdur"""
        self.is_server_running = False
        if self.server_socket:
            self.server_socket.close()
            self.server_socket = None
        
        self.start_button.config(text="Sunucuyu Başlat")
        self.log_security("Sunucu durduruldu")
    
    def wait_for_client(self):
        """İstemci bağlantısını bekle"""
        try:
            while self.is_server_running:
                try:
                    client_sock, addr = self.server_socket.accept()
                    self.log_security(f"İstemci bağlandı: {addr}")
                    self.handle_client(client_sock)
                except socket.error:
                    break
        except Exception as e:
            if self.is_server_running:
                self.log_security(f"Sunucu hatası: {str(e)}")
    
    def connect_to_server(self):
        """Sunucuya bağlan"""
        try:
            ip = self.ip_entry.get().strip()
            port_str = self.port_entry.get().strip()
            
            if not ip:
                messagebox.showwarning("Uyarı", "Lütfen geçerli bir IP adresi girin")
                return
            
            if not port_str:
                messagebox.showwarning("Uyarı", "Lütfen geçerli bir port numarası girin")
                return
            
            try:
                port = int(port_str)
                if port < 1 or port > 65535:
                    messagebox.showwarning("Uyarı", "Port numarası 1-65535 arasında olmalıdır")
                    return
            except ValueError:
                messagebox.showwarning("Uyarı", "Geçerli bir port numarası girin")
                return
            
            self.update_status("Bağlanıyor...")
            
            # Yeni socket oluştur
            if self.client_socket:
                try:
                    self.client_socket.close()
                except:
                    pass
            
            self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.client_socket.settimeout(10)  # 10 saniye timeout
            
            self.client_socket.connect((ip, port))
            
            self.log_security(f"Sunucuya bağlanıldı: {ip}:{port}")
            self.update_status("Anahtar değişimi yapılıyor...")
            
            # Public key değişimi
            threading.Thread(target=self._exchange_keys_thread, daemon=True).start()
            
        except socket.timeout:
            self.update_status("Bağlantı zaman aşımı")
            messagebox.showerror("Hata", "Bağlantı zaman aşımına uğradı")
            if self.client_socket:
                self.client_socket.close()
                self.client_socket = None
        except socket.gaierror:
            self.update_status("Geçersiz IP adresi")
            messagebox.showerror("Hata", "Geçersiz IP adresi")
        except ConnectionRefusedError:
            self.update_status("Bağlantı reddedildi")
            messagebox.showerror("Hata", "Bağlantı reddedildi. Sunucu çalışıyor mu?")
        except Exception as e:
            self.update_status(f"Bağlantı hatası: {str(e)}")
            messagebox.showerror("Hata", f"Bağlantı hatası: {str(e)}")
            if self.client_socket:
                self.client_socket.close()
                self.client_socket = None
    
    def _exchange_keys_thread(self):
        """Anahtar değişimi thread'i"""
        try:
            self.exchange_public_keys(self.client_socket)
            self.update_status("Bağlantı hazır - Dosya gönderebilirsiniz")
        except Exception as e:
            self.update_status(f"Anahtar değişim hatası: {str(e)}")
            self.log_security(f"Anahtar değişim hatası: {str(e)}")
            if self.client_socket:
                self.client_socket.close()
                self.client_socket = None

    def handle_client(self, client_sock):
        """İstemci isteklerini işle"""
        try:
            # Public key değişimi
            self.exchange_public_keys(client_sock)
            
            # Dosya alma işlemi
            self.receive_file(client_sock)
            
        except Exception as e:
            self.log_security(f"İstemci işleme hatası: {str(e)}")
        finally:
            client_sock.close()
    
    def exchange_public_keys(self, sock):
        """Public key değişimi"""
        try:
            if not sock:
                raise Exception("Socket bağlantısı yok")
            
            # Kendi public key'imizi gönder
            public_pem = self.public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
            
            # Veri boyutunu gönder
            key_length_bytes = len(public_pem).to_bytes(4, 'big')
            sock.send(key_length_bytes)
            
            # Public key'i gönder
            sock.send(public_pem)
            
            self.log_security("Public key gönderildi")
            
            # Karşı tarafın public key'ini al
            try:
                key_length_bytes = sock.recv(4)
                if len(key_length_bytes) != 4:
                    raise Exception("Anahtar uzunluk bilgisi alınamadı")
                
                key_length = int.from_bytes(key_length_bytes, 'big')
                
                if key_length <= 0 or key_length > 10000:  # Makul bir sınır
                    raise Exception(f"Geçersiz anahtar uzunluğu: {key_length}")
                
                peer_public_pem = b""
                while len(peer_public_pem) < key_length:
                    chunk = sock.recv(min(key_length - len(peer_public_pem), 4096))
                    if not chunk:
                        raise Exception("Anahtar verisi alınamadı")
                    peer_public_pem += chunk
                
                self.peer_public_key = serialization.load_pem_public_key(peer_public_pem)
                
                self.log_security("Karşı taraf public key'i alındı")
                self.log_security("Public key değişimi tamamlandı")
                
            except Exception as e:
                raise Exception(f"Karşı taraf anahtarı alma hatası: {str(e)}")
            
        except Exception as e:
            raise Exception(f"Key değişim hatası: {str(e)}")
    
    def select_file(self):
        """Dosya seç"""
        file_path = filedialog.askopenfilename(
            title="Gönderilecek dosyayı seçin",
            filetypes=[("Tüm dosyalar", "*.*")]
        )
        if file_path:
            self.file_path_var.set(file_path)
    
    def send_file(self):
        """Dosya gönder"""
        if not self.file_path_var.get():
            messagebox.showwarning("Uyarı", "Lütfen önce bir dosya seçin")
            return
        
        if not self.client_socket:
            messagebox.showwarning("Uyarı", "Önce sunucuya bağlanın")
            return
        
        if not hasattr(self, 'peer_public_key') or not self.peer_public_key:
            messagebox.showwarning("Uyarı", "Anahtar değişimi tamamlanmamış. Lütfen tekrar bağlanın.")
            return
        
        if self.transfer_in_progress:
            messagebox.showwarning("Uyarı", "Zaten bir dosya transferi devam ediyor")
            return
        
        threading.Thread(target=self._send_file_thread, daemon=True).start()
    
    def _send_file_thread(self):
        """Dosya gönderme thread'i"""
        try:
            file_path = self.file_path_var.get()
            file_size = os.path.getsize(file_path)
            file_name = os.path.basename(file_path)
            
            self.transfer_in_progress = True
            self.update_status("Dosya şifreleniyor...")
            
            # AES anahtarı oluştur
            aes_key = os.urandom(32)  # 256-bit AES
            iv = os.urandom(16)       # 128-bit IV
            
            # AES anahtarını RSA ile şifrele
            encrypted_aes_key = self.peer_public_key.encrypt(
                aes_key,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            
            # Dosyayı AES ile şifrele ve hash hesapla
            cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv))
            encryptor = cipher.encryptor()
            
            file_hash = hashlib.sha256()
            encrypted_chunks = []
            
            with open(file_path, 'rb') as f:
                while True:
                    chunk = f.read(8192)
                    if not chunk:
                        break
                    
                    file_hash.update(chunk)
                    
                    # PKCS7 padding
                    if len(chunk) % 16 != 0:
                        chunk += bytes([16 - len(chunk) % 16]) * (16 - len(chunk) % 16)
                    
                    encrypted_chunk = encryptor.update(chunk)
                    encrypted_chunks.append(encrypted_chunk)
            
            encrypted_chunks.append(encryptor.finalize())
            
            # Dijital imza oluştur
            signature = self.private_key.sign(
                file_hash.digest(),
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            
            # Transfer metadata'sı oluştur
            metadata = {
                'filename': file_name,
                'filesize': file_size,
                'encrypted_aes_key': base64.b64encode(encrypted_aes_key).decode('utf-8'),
                'iv': base64.b64encode(iv).decode('utf-8'),
                'signature': base64.b64encode(signature).decode('utf-8'),
                'file_hash': file_hash.hexdigest()
            }
            
            # Metadata'yı gönder
            metadata_json = json.dumps(metadata).encode('utf-8')
            self.client_socket.send(len(metadata_json).to_bytes(4, 'big'))
            self.client_socket.send(metadata_json)
            
            # Şifrelenmiş dosyayı gönder
            self.update_status("Dosya gönderiliyor...")
            total_size = sum(len(chunk) for chunk in encrypted_chunks)
            sent_size = 0
            
            for chunk in encrypted_chunks:
                self.client_socket.send(chunk)
                sent_size += len(chunk)
                progress = (sent_size / total_size) * 100
                self.parent.after(0, lambda p=progress: self.progress_var.set(p))
            
            self.update_status("Dosya başarıyla gönderildi")
            self.log_security(f"Dosya gönderildi: {file_name} ({file_size:,} bytes)")
            self.log_security(f"Kaynak dosya: {file_path}")
            self.log_security(f"SHA-256 Hash: {file_hash.hexdigest()}")
            
            # Başarı mesajı göster
            success_msg = f"Dosya başarıyla gönderildi!\n\n"
            success_msg += f"Dosya: {file_name}\n"
            success_msg += f"Boyut: {file_size:,} bytes\n"
            success_msg += f"Hash: {file_hash.hexdigest()[:16]}..."
            
            messagebox.showinfo("Gönderim Başarılı", success_msg)
            
        except Exception as e:
            self.update_status(f"Gönderme hatası: {str(e)}")
            self.log_security(f"Gönderme hatası: {str(e)}")
        finally:
            self.transfer_in_progress = False
            self.parent.after(0, lambda: self.progress_var.set(0))
    
    def receive_file(self, sock):
        """Dosya al"""
        try:
            self.update_status("Dosya alınıyor...")
            
            # Metadata al
            metadata_length = int.from_bytes(sock.recv(4), 'big')
            metadata_json = sock.recv(metadata_length)
            metadata = json.loads(metadata_json.decode('utf-8'))
            
            # Şifrelenmiş AES anahtarını çöz
            encrypted_aes_key = base64.b64decode(metadata['encrypted_aes_key'])
            aes_key = self.private_key.decrypt(
                encrypted_aes_key,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            
            iv = base64.b64decode(metadata['iv'])
            
            # Şifrelenmiş dosyayı al
            file_size = metadata['filesize']
            filename = metadata['filename']
            
            # Test klasörü oluştur
            test_dir = os.path.join(os.getcwd(), "result_test")
            if not os.path.exists(test_dir):
                os.makedirs(test_dir)
            
            # Dosya adını benzersiz yap (timestamp ekle)
            timestamp = time.strftime("%Y%m%d_%H%M%S")
            base_name, extension = os.path.splitext(filename)
            unique_filename = f"{base_name}_{timestamp}{extension}"
            
            # Otomatik kaydetme yolu
            save_path = os.path.join(test_dir, unique_filename)
            
            self.log_security(f"Dosya otomatik olarak kaydediliyor: {save_path}")
            
            # Dosyayı al ve şifresini çöz
            cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv))
            decryptor = cipher.decryptor()
            
            received_size = 0
            file_hash = hashlib.sha256()
            
            with open(save_path, 'wb') as f:
                while received_size < file_size:
                    chunk = sock.recv(8192)
                    if not chunk:
                        break
                    
                    decrypted_chunk = decryptor.update(chunk)
                    
                    # Son chunk için padding kaldır
                    if received_size + len(decrypted_chunk) >= file_size:
                        remaining = file_size - received_size
                        decrypted_chunk = decrypted_chunk[:remaining]
                    
                    f.write(decrypted_chunk)
                    file_hash.update(decrypted_chunk)
                    received_size += len(decrypted_chunk)
                    
                    progress = (received_size / file_size) * 100
                    self.parent.after(0, lambda p=progress: self.progress_var.set(p))
            
            decryptor.finalize()
            
            # Dijital imzayı doğrula
            signature = base64.b64decode(metadata['signature'])
            try:
                self.peer_public_key.verify(
                    signature,
                    file_hash.digest(),
                    padding.PSS(
                        mgf=padding.MGF1(hashes.SHA256()),
                        salt_length=padding.PSS.MAX_LENGTH
                    ),
                    hashes.SHA256()
                )
                signature_valid = True
            except:
                signature_valid = False
            
            # Hash kontrolü
            calculated_hash = file_hash.hexdigest()
            original_hash = metadata['file_hash']
            hash_valid = calculated_hash == original_hash
            
            self.update_status("Dosya başarıyla alındı")
            self.log_security(f"Dosya alındı: {filename} ({file_size} bytes)")
            self.log_security(f"Kaydedilen konum: {save_path}")
            self.log_security(f"SHA-256 Hash: {calculated_hash}")
            self.log_security(f"Hash Doğrulama: {'✓ Geçerli' if hash_valid else '✗ Geçersiz'}")
            self.log_security(f"Dijital İmza: {'✓ Geçerli' if signature_valid else '✗ Geçersiz'}")
            
            # Başarı mesajı göster
            success_msg = f"Dosya başarıyla alındı!\n\nKonum: {save_path}\n"
            success_msg += f"Boyut: {file_size:,} bytes\n"
            success_msg += f"Hash Doğrulama: {'✓ Geçerli' if hash_valid else '✗ Geçersiz'}\n"
            success_msg += f"Dijital İmza: {'✓ Geçerli' if signature_valid else '✗ Geçersiz'}"
            
            if hash_valid and signature_valid:
                messagebox.showinfo("Transfer Başarılı", success_msg)
            else:
                messagebox.showwarning("Güvenlik Uyarısı", 
                                     success_msg + "\n\n⚠️ Güvenlik doğrulaması başarısız!")
            
        except Exception as e:
            self.update_status(f"Alma hatası: {str(e)}")
            self.log_security(f"Alma hatası: {str(e)}")
    
    def update_status(self, message):
        """Durum güncelle"""
        try:
            # Thread-safe UI güncelleme
            self.parent.after(0, lambda: self.status_label.config(text=message))
        except:
            # UI mevcut değilse
            pass
    
    def log_security(self, message):
        """Güvenlik loglarını ekle"""
        timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
        log_message = f"[{timestamp}] {message}\n"
        
        try:
            # Thread-safe UI güncelleme
            self.parent.after(0, lambda: self._update_security_log(log_message))
        except:
            # UI mevcut değilse
            pass
    
    def _update_security_log(self, log_message):
        """Security log'u güncelle (UI thread'de çalışır)"""
        try:
            self.security_text.insert(tk.END, log_message)
            self.security_text.see(tk.END)
        except:
            pass
    
    def cleanup(self):
        """Temizlik işlemleri"""
        self.transfer_in_progress = False
        if self.server_socket:
            self.server_socket.close()
        if self.client_socket:
            self.client_socket.close() 