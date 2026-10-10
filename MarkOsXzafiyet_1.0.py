# -*- coding: utf-8 -*-
"""
MarkOs Sistem ve Web Zafiyet Analiz Motoru
[EĞİTİM VE SIZMA TESTİ LABORATUVARI İÇİN GELİŞTİRİLMİŞTİR]
"""

import os
import sys
import socket
import subprocess
import requests
import httpx
from colorama import Fore, Style, init

# Terminal renklerini tüm platformlarda (Windows, Linux) aktif ediyoruz
init(autoreset=True)

def markos_banner():
    """MarkOs Kurumsal Açılış Logosu"""
    banner = f"""
{Fore.CYAN}======================================================================
{Fore.GREEN} __  __             _    ____         __  __             _    _     
{Fore.GREEN}|  \/  |  __ _ _ __| | _/ ___|       |  \/  |  __ _ _ __| | _| |    
{Fore.GREEN}| |\/| | / _` | '__| |/ /\___ \ _____| |\/| | / _` | '__| |/ / |    
{Fore.GREEN}| |  | || (_| | |  |   <  ___) |_____| |  | || (_| | |  |   <|_|    
{Fore.GREEN}|_|  |_| \__,_6|_|  |_|\_\|____/       |_|  |_| \__,_|_|  |_|\_\|_6   
{Fore.CYAN}======================================================================
{Fore.YELLOW}          [+] MarkOs Bağımsız Siber Güvenlik Modülü v1.0
{Fore.YELLOW}          [+] Geliştirici: MarkOs Dağıtım Ekibi
{Fore.CYAN}======================================================================
"""
    print(banner)

def sistem_analiz_modulu():
    """1. Katman: Sistem Dosyaları ve Süreç (Process) Analizi"""
    print(f"\n{Fore.CYAN}[*] 1. KATMAN: SİSTEM VE SÜREÇ ANALİZİ BAŞLATILIYOR...")
    
    # Şüpheli uzantı kontrolü
    riskli_uzantilar = ['.exe', '.apk', '.bat', '.sh', '.py']
    bulunan_riskli = 0
    
    print(f"{Fore.YELLOW}[+] Mevcut dizindeki riskli uzantılı dosyalar taranıyor...")
    for kok_dizin, klasorler, dosyalar in os.walk("."):
        for dosya in dosyalar:
            uzanti = os.path.splitext(dosya)[1].lower()
            if uzanti in riskli_uzantilar:
                print(f"  {Fore.RED}[!] Şüpheli Uzantı Tespit Edildi: {dosya} -> Yol: {kok_dizin}")
                bulunan_riskli += 1
                
    if bulunan_riskli == 0:
        print(f"  {Fore.GREEN}[OK] Mevcut dizinde şüpheli uzantılı dosyaya rastlanmadı.")

    # Süreç (Process) İzleme Kontrolü
    print(f"\n{Fore.YELLOW}[+] Arka planda çalışan aktif süreçler kontrol ediliyor...")
    try:
        if sys.platform.startswith('win'):
            # Windows için çalışan süreçleri listeleme
            sonuc = subprocess.check_output("tasklist", shell=True).decode('utf-8', errors='ignore')
            print(f"  {Fore.GREEN}[OK] Windows süreç listesi başarıyla çekildi (İlk 10 satır):")
            print("\n".join(sonuc.splitlines()[:10]))
        else:
            # Linux veya diğer Unix sistemler için süreç listeleme
            sonuc = subprocess.check_output("ps aux", shell=True).decode('utf-8', errors='ignore')
            print(f"  {Fore.GREEN}[OK] Sistem süreç listesi başarıyla çekildi (İlk 10 satır):")
            print("\n".join(sonuc.splitlines()[:10]))
    except Exception as e:
        print(f"  {Fore.RED}[❌] Süreç listesi alınırken bir hata oluştu: {e}")

def ag_ve_port_tarayici():
    """2. Katman: Yerel Ağ ve Port Keşif Modülü"""
    print(f"\n{Fore.CYAN}[*] 2. KATMAN: AĞ VE AÇIK PORT TARAMASI BAŞLATILIYOR...")
    
    # Test edilecek kritik portlar (Docker 2375, SSH 22, HTTP 80, HTTPS 443)
    kritik_portlar = [22, 80, 443, 2375]
    hedef_host = "127.0.0.1" # Yerel test için localhost
    
    print(f"{Fore.YELLOW}[+] {hedef_host} adresi üzerindeki kritik servis portları taranıyor...")
    
    for port in kritik_portlar:
        soket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        soket.settimeout(1.0) # 1 saniye zaman aşımı
        sonuc = soket.connect_ex((hedef_host, port))
        
        if sonuc == 0:
            if port == 2375:
                print(f"  {Fore.RED}[🚨 TEHLİKE] Port {port} (Docker Remote API) AÇIK! Yetkisiz sızma riski yüksek.")
            else:
                print(f"  {Fore.GREEN}[+] Port {port} AÇIK ve yanıt veriyor.")
        else:
            print(f"  {Fore.WHITE}[-] Port {port} kapalı.")
        soket.close()

def asenkron_web_zafiyet_tarayici():
    """3. Katman: Asenkron HTTPX ve Requests ile Web Zafiyet/Sürüm Analizi"""
    print(f"\n{Fore.CYAN}[*] 3. KATMAN: WEB ZAFİYET VE BANNER ANALİZİ BAŞLATILIYOR...")
    
    # Test amaçlı yasal bir hedef veya yerel lab adresi belirlenmelidir
    hedef_url = "https://httpbin.org"
    print(f"{Fore.YELLOW}[+] {hedef_url} adresi üzerinden asenkron web testleri yürütülüyor...")
    
    # 1. Aşama: Requests ile hızlı bağlantı testi
    try:
        r_test = requests.get(hedef_url, timeout=5)
        print(f"  {Fore.GREEN}[OK] Requests Bağlantı Durumu: {r_test.status_code}")
    except requests.exceptions.RequestException as e:
        print(f"  {Fore.RED}[❌] Requests bağlantı hatası: {e}")
        return

    # 2. Aşama: HTTPX ile Asenkron istek simülasyonu ve Sunucu Bilgisi (Banner) Yakalama
    try:
        with httpx.Client() as istemci:
            yanit = istemci.get(hedef_url)
            print(f"  {Fore.GREEN}[OK] HTTPX Asenkron İstek Başarılı. Sürüm: {yanit.http_version}")
            
            # Sunucu yazılım bilgisini (Banner) kontrol ediyoruz
            sunucu_bilgisi = yanit.headers.get("Server", "Bilinmiyor")
            print(f"  {Fore.YELLOW}[i] Hedef Sunucu Yazılımı (Banner): {sunucu_bilgisi}")
            
            # Basit bir SQL Injection / XSS koruma filtresi analizi (Zafiyet tarama mantığı)
            if "X-XSS-Protection" in yanit.headers:
                print(f"  {Fore.GREEN}[+] Güvenlik Filtresi: XSS Koruması aktif.")
            else:
                print(f"  {Fore.RED}[!] Güvenlik Filtresi Eksik: XSS koruma başlığı bulunamadı.")
                
    except Exception as e:
        print(f"  {Fore.RED}[❌] HTTPX tarama hatası: {e}")

def ana_menu():
    """MarkOs Ana Kontrol Menüsü"""
    while True:
        markos_banner()
        print(f"{Fore.WHITE}1 -> Tam Sistem ve Süreç Analizi Yap")
        print(f"{Fore.WHITE}2 -> Yerel Ağ ve Kritik Port Taraması Yap")
        print(f"{Fore.WHITE}3 -> Asenkron Web Zafiyet ve Banner Taraması Yap")
        print(f"{Fore.WHITE}4 -> Tüm Katmanları Sırayla Çalıştır (Full Scan)")
        print(f"{Fore.RED}5 -> Programdan Çıkış Yap")
        
        secim = input(f"\n{Fore.CYAN}MarkOs > Seçiminiz nedir şef? ")
        
        if secim == "1":
            sistem_analiz_modulu()
        elif secim == "2":
            ag_ve_port_tarayici()
        elif secim == "3":
            asenkron_web_zafiyet_tarayici()
        elif secim == "4":
            sistem_analiz_modulu()
            ag_ve_port_tarayici()
            asenkron_web_zafiyet_tarayici()
        elif secim == "5":
            print(f"\n{Fore.GREEN}[+] MarkOs Motoru kapatılıyor. Güvenli günler şef! Hadi baybay...")
            break
        else:
            print(f"\n{Fore.RED}[❌] Geçersiz seçim! Lütfen menüdeki rakamlardan birini girin.")
            
        input(f"\n{Fore.YELLOW}Devam etmek için ENTER tuşuna basın...")
        # Terminal ekranını temizleme (İşletim sistemine göre)
        os.system('cls' if os.name == 'nt' else 'clear')

if __name__ == "__main__":
    ana_menu()
