import os
import sys
import time
import socket
import ssl
import sqlite3
import threading
import subprocess
import itertools
from datetime import datetime
import requests
import httpx
from bs4 import BeautifulSoup
import psutil
import phonenumbers
from colorama import Fore, Style, init

init(autoreset=True)

class MarkOsDatabaseAndIntelCore:
    """
    ===================================================================
    MARKOS NATIONAL ENTERPRISE INTEL & DB AUDITOR PLATFORM v7.5
    ===================================================================
    Mimar: memetcanwq31-ship-it (BTK Akademi Projesi)
    Kütüphaneler: httpx + sqlite3 + subprocess + psutil + phonenumbers
    ===================================================================
    """

    def __init__(self):
        self.version = "7.5.0-Enterprise"
        self.owner = "memetcanwq31"
        self.target_domain = ""
        self.target_ip = ""
        self.db_name = "markos_intel_vault.db"
        self.lock = threading.Lock()
        self.intel_ports = [21, 22, 23, 25, 53, 80, 110, 139, 443, 445, 1433, 3306, 3389, 8080, 8443]
        self.is_running = True
        self.scan_results = {
            "security_headers": [],
            "open_ports": [],
            "false_positive_logs": []
        }
        self.setup_local_vault()

    def clear_screen(self):
        os.system('cls' if os.name == 'nt' else 'clear')

    def show_banner(self):
        self.clear_screen()
        print(f"""{Fore.GREEN}
███╗   ███╗ █████╗ ██████╗ ██╗  ██╗ ██████╗ ███████╗
████╗ ████║██╔══██╗██╔══██╗██║ ██╔╝██╔═══██╗██╔════╝
██╔████╔██║███████║██████╔╝█████╔╝ ██║   ██║███████╗
██║╚██╔╝██║██╔══██║██╔══██╗██╔═██╗ ██║   ██║╚════██║
██║ ╚═╝ ██║██║  ██║██║  ██╗╚██████╔╝███████║
╚═╝     ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝ ╚══════╝
 ──────────────────────────────────────────────────────────
   [📡] MARKOS ULUSAL VERİTABANI VE HİBRİT İSTİHBARAT ÜSSÜ
   [⚙️ ] MİMARİ: psutil + phonenumbers + httpx + sqlite3
   [📌] Sürüm: {self.version} | Mimar: {self.owner}
 ──────────────────────────────────────────────────────────{Style.RESET_ALL}""")

    def animate_loading(self, text, duration=1.2):
        spinner = itertools.cycle(['|', '/', '-', '\\'])
        stop_time = time.time() + duration
        sys.stdout.write(f"{Fore.YELLOW}[*] {text} ")
        while time.time() < stop_time:
            sys.stdout.write(next(spinner))
            sys.stdout.flush()
            time.sleep(0.1)
            sys.stdout.write('\b')
        sys.stdout.write(f"\r{Fore.GREEN}[+] {text} Tamamlandı!\n")

    def setup_local_vault(self):
        try:
            conn = sqlite3.connect(self.db_name)
            cursor = conn.cursor()
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS intel_logs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    domain TEXT,
                    ip TEXT,
                    detected_db TEXT,
                    security_score TEXT,
                    scan_date TEXT
                )
            ''')
            conn.commit()
            conn.close()
        except Exception as e:
            print(f"{Fore.RED}[!] Yerel veritabanı kurulum hatası: {e}")

    def set_target(self):
        self.show_banner()
        print(f"\n{Fore.CYAN}── [İSTİHBARAT HEDEF YAPILANDIRMASI] ──────────────────────")
        domain = input(f"{Fore.GREEN}[?] Analiz Edilecek Domain (Örn: example.com): {Style.RESET_ALL}").strip()
        if not domain:
            print(f"{Fore.RED}[!] Alan adı boş bırakılamaz!")
            time.sleep(1.2)
            return False
        if "://" in domain:
            domain = domain.split("://")[-1]
        if "/" in domain:
            domain = domain.split("/")[0]
        self.target_domain = domain
        try:
            self.target_ip = socket.gethostbyname(self.target_domain)
            print(f"{Fore.GREEN}[+] Hedef IP Adresi Çözümlendi: {Fore.YELLOW}{self.target_ip}")
            time.sleep(1.2)
            return True
        except socket.gaierror:
            print(f"{Fore.RED}[!] Kritik Hata: DNS Çözümleme Başarısız!")
            self.target_domain = ""
            return False

    # ===================================================================
    # KISIM 2: DONANIM MONİTÖRÜ, GSM OSINT, FORM ANALİZİ, PORT TARAMASI
    # ===================================================================

    def run_adli_donanim_monitoru(self):
        self.show_banner()
        print(f"\n{Fore.CYAN}── Modül C: Adli Sistem ve Donanım Analizörü ────────────────")
        self.animate_loading("İşlemci ve bellek yükü hesaplanıyor", 1.0)

        cpu_usage = psutil.cpu_percent(interval=1)
        ram_info = psutil.virtual_memory()
        disk_info = psutil.disk_usage('/' if os.name != 'nt' else 'C:\\')

        print(f"\n{Fore.GREEN}[+] ANLIK DONANIM ADLİ BİLİŞİM RAPORU:")
        print(f"  {Fore.BLUE}• CPU Kullanımı       : {Fore.WHITE}%{cpu_usage}")
        print(f"  {Fore.BLUE}• CPU Çekirdek Sayısı : {Fore.WHITE}{psutil.cpu_count(logical=True)}")
        print(f"  {Fore.BLUE}• RAM Toplam          : {Fore.WHITE}{round(ram_info.total / (1024**3), 2)} GB")
        print(f"  {Fore.BLUE}• RAM Kullanılan      : {Fore.WHITE}{round(ram_info.used / (1024**3), 2)} GB")
        print(f"  {Fore.BLUE}• RAM Boşta           : {Fore.WHITE}{round(ram_info.available / (1024**3), 2)} GB")
        print(f"  {Fore.BLUE}• Disk Kullanılan     : {Fore.WHITE}{round(disk_info.used / (1024**3), 2)} GB / {round(disk_info.total / (1024**3), 2)} GB")

        input(f"\n{Fore.GREEN}Devam etmek için Enter'a basın...")

    def run_gsm_osint_validator(self):
        self.show_banner()
        print(f"\n{Fore.CYAN}── Modül D: GSM Telekom Format İstihbarat Motoru ────────────")
        numara = input(f"{Fore.GREEN}[?] Doğrulanacak Numara (Örn: +905xxxxxxxxx): {Style.RESET_ALL}").strip()

        if not numara:
            print(f"{Fore.RED}[!] Numara alanı boş bırakılamaz!")
            time.sleep(1.2)
            return

        try:
            self.animate_loading("ITU uluslararası format denetleniyor", 1.0)
            parsed_number = phonenumbers.parse(numara, None)
            is_valid = phonenumbers.is_valid_number(parsed_number)
            operator = phonenumbers.carrier.name_for_number(parsed_number, "tr")
            region = phonenumbers.region_code_for_number(parsed_number)
            timezone = phonenumbers.timezone.time_zones_for_number(parsed_number)

            print(f"\n{Fore.GREEN}[+] GSM OSINT VE DOĞRULAMA SONUÇLARI:")
            print(f"  {Fore.BLUE}• Girilen Girdi        : {Fore.WHITE}{numara}")
            print(f"  {Fore.BLUE}• Ülke Kodu (E.164)    : {Fore.WHITE}+{parsed_number.country_code}")
            print(f"  {Fore.BLUE}• Ulusal Format No     : {Fore.WHITE}{parsed_number.national_number}")
            print(f"  {Fore.BLUE}• Bölge Kodu           : {Fore.WHITE}{region}")
            print(f"  {Fore.BLUE}• Tahmini Operatör     : {Fore.WHITE}{operator or 'Bilinmiyor'}")
            print(f"  {Fore.BLUE}• Saat Dilimi          : {Fore.WHITE}{', '.join(timezone) or 'Bilinmiyor'}")
            print(f"  {Fore.BLUE}• Format Kontrolü      : " + (
                f"{Fore.GREEN}GEÇERLİ NUMARA FORMATI" if is_valid
                else f"{Fore.RED}GEÇERSİZ NUMARA FORMATİ!"))
        except Exception as e:
            print(f"{Fore.RED}[!] Format Çözümleme Hatası: {e}. Numaranın başına '+' ekleyin.")

        input(f"\n{Fore.GREEN}Devam etmek için Enter'a basın...")

    def run_web_crawler_simulation(self):
        if not self.target_domain:
            print(f"{Fore.RED}[!] Hedef tanımlanmamış!")
            time.sleep(1.5)
            return

        self.show_banner()
        print(f"\n{Fore.CYAN}── Modül E: Form Yapılandırma ve CSRF Koruma Analizi ────────")
        self.animate_loading("Kaynak kod güvenlik süzgecinden geçiriliyor", 1.2)

        url = f"https://{self.target_domain}"
        try:
            headers = {"User-Agent": f"MarkOs-Crawler/{self.version}"}
            res = requests.get(url, timeout=7, headers=headers)
            soup = BeautifulSoup(res.text, 'html.parser')
            forms = soup.find_all('form')

            print(f"\n{Fore.GREEN}[+] Analiz Sonuçları:")
            print(f"  {Fore.BLUE}• Tespit Edilen Form Sayısı: {Fore.WHITE}{len(forms)}")

            for idx, form in enumerate(forms, 1):
                action = form.get('action', 'Mevcut Sayfa')
                method = form.get('method', 'get').upper()
                print(f"    {Fore.YELLOW}[ Form {idx} ] Yönlendirme: {action} | Metot: {method}")

                inputs = form.find_all('input')
                has_token = any(
                    'token' in str(inp.get('name', '')).lower()
                    or 'csrf' in str(inp.get('name', '')).lower()
                    for inp in inputs
                )

                if has_token:
                    print(f"      {Fore.GREEN}[+] CSRF Güvenlik Token'ı Tespit Edildi. (Güvenli)")
                else:
                    print(f"      {Fore.RED}[!] Risk: CSRF Token'ı bulunamadı! (Potansiyel CSRF Riski)")

        except Exception as e:
            print(f"{Fore.RED}[!] Kaynak kod analizi hatası: {e}")

        input(f"\n{Fore.GREEN}Devam etmek için Enter'a basın...")

    def socket_port_worker(self, port):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1.5)
            result = sock.connect_ex((self.target_ip, port))
            if result == 0:
                with self.lock:
                    try:
                        service_name = socket.getservbyport(port)
                    except OSError:
                        service_name = "Bilinmeyen Servis"
                    print(f"  {Fore.GREEN}[+] Port {port:<6} DURUM: AÇIK | Servis: {service_name}")
                    self.scan_results["open_ports"].append(port)
            sock.close()
        except OSError:
            pass

    def run_port_scanner(self):
        if not self.target_ip:
            print(f"{Fore.RED}[!] Kritik Hata: Önce hedef IP tanımlamalısınız!")
            time.sleep(1.5)
            return

        self.show_banner()
        print(f"\n{Fore.CYAN}── Modül F: Çoklu İş Parçacıklı Port Denetimi ───────────────")
        print(f"{Fore.YELLOW}[*] {self.target_ip} üzerinde {len(self.intel_ports)} kritik port denetleniyor...\n")

        threads = [threading.Thread(target=self.socket_port_worker, args=(port,)) for port in self.intel_ports]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        if not self.scan_results["open_ports"]:
            print(f"{Fore.CYAN}[i] Sonuç: Kritik portlar kapalı veya güvenlik duvarı tarafından korunuyor.")

        input(f"\n{Fore.GREEN}Devam etmek için Enter'a basın...")

    # ===================================================================
    # KISIM 3: GÜVENLİK BAŞLIKLARI, DB PARMAK İZİ, FALSE POSITIVE RADAR
    # ===================================================================

    def run_header_audit(self):
        if not self.target_domain:
            print(f"{Fore.RED}[!] Hedef tanımlanmamış!")
            time.sleep(1.5)
            return

        self.show_banner()
        print(f"\n{Fore.CYAN}── Modül G: HTTP/HTTPS Güvenlik Başlıkları Denetimi ──────────")
        self.animate_loading("Sunucu güvenlik kalkanları analiz ediliyor", 1.2)

        url = f"https://{self.target_domain}"
        try:
            headers = {"User-Agent": f"MarkOs-Istihbarat-Engine/{self.version}"}
            res = requests.get(url, timeout=7, headers=headers)
            server_headers = res.headers

            print(f"\n{Fore.GREEN}=== KRİTİK GÜVENLİK BAŞLIKLARI VE KALKAN DURUMU ===")

            checks = {
                "Strict-Transport-Security": ("ŞİFRELEME", "HSTS", "MitM / Trafik Dinleme Riski"),
                "X-Frame-Options": ("DEFANS", "X-Frame-Options", "Clickjacking Riski"),
                "Content-Security-Policy": ("DEFANS", "CSP", "XSS / Kod Enjeksiyonu Riski"),
                "X-Content-Type-Options": ("DEFANS", "X-Content-Type-Options", "MIME Sniffing Riski"),
            }

            for header, (cat, label, risk) in checks.items():
                if header in server_headers:
                    print(f"{Fore.GREEN}[+] [{cat}] {label} AKTİF! -> {server_headers[header]}")
                    self.scan_results["security_headers"].append(f"{label}: Aktif")
                else:
                    print(f"{Fore.RED}[!] [ZAFİYET] {label} EKSİK! ({risk})")
                    self.scan_results["security_headers"].append(f"{label}: EKSİK!")

            server_signature = server_headers.get("Server", "Gizli / WAF Arkasında")
            print(f"\n{Fore.CYAN}[i] Sunucu Banner İmzası: {Fore.WHITE}{server_signature}")

        except Exception as e:
            print(f"{Fore.RED}[!] Web sunucusuna bağlanılamadı: {e}")

        input(f"\n{Fore.GREEN}Devam etmek için Enter'a basın...")

    def run_db_type_fingerprinting(self):
        if not self.target_domain:
            print(f"{Fore.RED}[!] Kritik Hata: Önce hedef tanımlamalısınız!")
            time.sleep(1.5)
            return

        self.show_banner()
        print(f"\n{Fore.CYAN}── Modül H: Veritabanı Mimari Analizörü ─────────────────────")
        self.animate_loading("Veritabanı hata mesajı filtreleri çözümleniyor", 1.5)

        detected_db = "Bilinmiyor / Korunuyor"
        url = f"https://{self.target_domain}/?id=1'"

        try:
            with httpx.Client(timeout=7.0, follow_redirects=True) as client:
                res = client.get(url, headers={"User-Agent": f"MarkOs-DB-Auditor/{self.version}"})
                response_text = res.text.lower()

            print(f"\n{Fore.GREEN}[*] Veritabanı İmzası Tarama Raporu:")

            if "mysql" in response_text or "you have an error in your sql syntax" in response_text:
                detected_db = "MySQL"
                print(f"  {Fore.RED}[!] TESPİT: {Fore.YELLOW}MySQL{Fore.RED} mimarisi algılandı! (Ham Hata İfşası)")
            elif "postgresql" in response_text or "invalid input syntax for" in response_text:
                detected_db = "PostgreSQL"
                print(f"  {Fore.RED}[!] TESPİT: {Fore.YELLOW}PostgreSQL{Fore.RED} mimarisi algılandı!")
            elif "ora-00933" in response_text or "ora-01756" in response_text:
                detected_db = "Oracle Database"
                print(f"  {Fore.RED}[!] TESPİT: {Fore.YELLOW}Oracle DB{Fore.RED} mimarisi algılandı!")
            elif "sqlite" in response_text or "no such table" in response_text:
                detected_db = "SQLite"
                print(f"  {Fore.RED}[!] TESPİT: {Fore.YELLOW}SQLite{Fore.RED} mimarisi algılandı!")
            elif "microsoft sql" in response_text or "sql server" in response_text:
                detected_db = "MSSQL"
                print(f"  {Fore.RED}[!] TESPİT: {Fore.YELLOW}Microsoft SQL Server{Fore.RED} mimarisi algılandı!")
            else:
                print(f"  {Fore.GREEN}[+] Durum: Sunucu veritabanı hata mesajlarını sızdırmıyor. (Güvenli)")

            self.save_to_local_vault(detected_db)

        except Exception as e:
            print(f"{Fore.RED}[!] Veritabanı analiz motoru bağlanamadı: {e}")

        input(f"\n{Fore.GREEN}Devam etmek için Enter'a basın...")

    def run_false_positive_radar(self):
        if not self.target_domain:
            print(f"{Fore.RED}[!] Hedef tanımlanmamış!")
            time.sleep(1.5)
            return

        self.show_banner()
        print(f"\n{Fore.CYAN}── Modül I: Yalancı Pozitif İstihbarat Radarı ───────────────")
        self.animate_loading("Hata yakalama şablonları çözümleniyor", 1.2)

        fake_files = [".env_backup_test", "root_ssh_key_fake.id_rsa", "config_secret_test.bak"]
        print(f"\n{Fore.GREEN}[*] WAF Hata Davranış Analizi Başlatıldı:")

        for file in fake_files:
            url = f"https://{self.target_domain}/{file}"
            try:
                res = requests.get(url, timeout=6, allow_redirects=False,
                                   headers={"User-Agent": f"MarkOs-Radar/{self.version}"})
                if res.status_code == 200 or res.status_code in (301, 302, 403):
                    print(f"  {Fore.YELLOW}[!] Bulgulandı: /{file} -> {res.status_code} yanıtı. (Özel 404/Yönlendirme Aktif)")
                    self.scan_results["false_positive_logs"].append(f"{file} -> Sunucu Yanıltma Filtresi Aktif")
                else:
                    print(f"  {Fore.GREEN}[+] Güvenli: /{file} -> standart {res.status_code} yanıtı.")
            except Exception as e:
                print(f"  {Fore.RED}[!] Bağlantı kısıtlaması: {e}")

        print(f"\n{Fore.CYAN}[i] Analist Notu: Bu radar, sahte zafiyet raporlarını ayıklamak için geliştirilmiştir.")
        input(f"\n{Fore.GREEN}Devam etmek için Enter'a basın...")

    # ===================================================================
    # KISIM 4: SQLITE VAULT, SUBPROCESS MOTORU, RAPOR, ANA MENÜ
    # ===================================================================

    def save_to_local_vault(self, detected_db):
        try:
            conn = sqlite3.connect(self.db_name)
            cursor = conn.cursor()
            scan_date = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            cursor.execute('''
                INSERT INTO intel_logs (domain, ip, detected_db, security_score, scan_date)
                VALUES (?, ?, ?, ?, ?)
            ''', (self.target_domain, self.target_ip, detected_db, "Analiz Başarılı", scan_date))
            conn.commit()
            conn.close()
            print(f"\n{Fore.GREEN}[+] BAŞARILI: Bulgular yerel {Fore.YELLOW}{self.db_name}{Fore.GREEN} veritabanına kaydedildi!")
        except Exception as e:
            print(f"{Fore.RED}[!] sqlite3 yazım hatası: {e}")

    def run_subprocess_ping_check(self):
        if not self.target_domain:
            print(f"{Fore.RED}[!] Kritik Hata: Önce hedef tanımlamalısınız!")
            time.sleep(1.5)
            return

        self.show_banner()
        print(f"\n{Fore.CYAN}── Modül J: Subprocess Ağ Doğrulaması ───────────────────────")
        self.animate_loading("İşletim sistemi kabuk katmanı tetikleniyor", 1.0)

        param = "-n" if os.name == "nt" else "-c"
        command = ["ping", param, "3", self.target_domain]

        try:
            print(f"\n{Fore.GREEN}[*] Komut çalıştırılıyor: {' '.join(command)}")
            result = subprocess.run(command, stdout=subprocess.PIPE,
                                    stderr=subprocess.PIPE, text=True, timeout=15)
            if result.returncode == 0:
                print(f"{Fore.GREEN}[+] Altyapı Kararlı: Sunucu ICMP isteklerine yanıt veriyor.")
                print(f"{Fore.WHITE}{result.stdout[:300]}")
            else:
                print(f"{Fore.YELLOW}[!] Sunucu ICMP isteklerini drop ediyor (Güvenlik Duvarı Aktif olabilir).")
        except Exception as e:
            print(f"{Fore.RED}[!] Subprocess motoru hatası: {e}")

        input(f"\n{Fore.GREEN}Devam etmek için Enter'a basın...")

    def show_local_vault_logs(self):
        self.show_banner()
        print(f"\n{Fore.CYAN}── Modül K: SQLite Veritabanı Kayıt Defteri ─────────────────")

        try:
            conn = sqlite3.connect(self.db_name)
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM intel_logs ORDER BY id DESC LIMIT 5")
            logs = cursor.fetchall()
            conn.close()

            if not logs:
                print(f"\n{Fore.CYAN}[i] Veritabanında henüz kayıtlı bulgu logu yok.")
            else:
                print(f"\n{Fore.GREEN}=== SON 5 İSTİHBARAT LOGU ===")
                for log in logs:
                    print(f"\n{Fore.YELLOW}[ Log ID: {log[0]} ]")
                    print(f"{Fore.CYAN}  • Hedef Domain : {Fore.WHITE}{log[1]}")
                    print(f"{Fore.CYAN}  • Çözümlenen IP: {Fore.WHITE}{log[2]}")
                    print(f"{Fore.CYAN}  • Algılanan DB : {Fore.GREEN}{log[3]}")
                    print(f"{Fore.CYAN}  • Tarama Tarihi: {Fore.WHITE}{log[5]}")
        except Exception as e:
            print(f"{Fore.RED}[!] sqlite3 okuma hatası: {e}")

        input(f"\n{Fore.GREEN}Devam etmek için Enter'a basın...")

    def generate_enterprise_report(self):
        if not self.target_domain:
            print(f"{Fore.RED}[!] Rapor üretilecek veri yok!")
            time.sleep(1.5)
            return

        self.show_banner()
        print(f"\n{Fore.CYAN}── Rapor Oluşturma ve Dışa Aktarma Sihirbazı ────────────────")
        self.animate_loading("Veriler kurumsal şablona işleniyor", 1.5)

        filename_base = f"markos_report_{self.target_domain.replace('.', '_')}"
        txt_name = f"{filename_base}.txt"
        html_name = f"{filename_base}.html"
        scan_date = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        with open(txt_name, "w", encoding="utf-8") as f:
            f.write("===================================================================\n")
            f.write("      MARKOS NATIONAL ENTERPRISE INTEL & DB AUDITOR REPORT v7.5\n")
            f.write("===================================================================\n")
            f.write(f"Hedef Domain      : {self.target_domain}\n")
            f.write(f"Sunucu IP         : {self.target_ip}\n")
            f.write(f"Analiz Zamanı     : {scan_date}\n")
            f.write("-------------------------------------------------------------------\n")
            f.write(f"Açık Portlar      : {', '.join(map(str, self.scan_results['open_ports'])) if self.scan_results['open_ports'] else 'Bulunamadı'}\n")
            f.write(f"Güvenlik Başlıkları: {', '.join(self.scan_results['security_headers']) if self.scan_results['security_headers'] else 'Analiz yapılmadı'}\n")
            f.write("===================================================================\n")

        html_content = f"""
        <!DOCTYPE html>
        <html lang="tr">
        <head>
            <meta charset="UTF-8">
            <title>MarkOs Raporu - {self.target_domain}</title>
            <style>
                body {{ font-family: 'Segoe UI', Tahoma, sans-serif; margin: 40px; background-color: #0f172a; color: #e2e8f0; }}
                .container {{ max-width: 900px; margin: auto; background: #1e293b; padding: 30px; border-radius: 12px; box-shadow: 0 4px 6px rgba(0,0,0,0.3); }}
                .header {{ border-bottom: 3px solid #10b981; padding-bottom: 20px; text-align: center; }}
                h1 {{ color: #10b981; margin: 0; font-size: 28px; }}
                h2 {{ color: #38bdf8; border-bottom: 1px solid #475569; padding-bottom: 8px; margin-top: 30px; }}
                .meta-table {{ width: 100%; border-collapse: collapse; margin-top: 15px; }}
                .meta-table td {{ padding: 10px; border: 1px solid #475569; }}
                .meta-table td.title {{ font-weight: bold; color: #94a3b8; width: 30%; }}
                .footer {{ text-align: center; margin-top: 40px; font-size: 12px; color: #64748b; }}
            </style>
        </head>
        <body>
            <div class="container">
                <div class="header">
                    <h1>MarkOs Siber Tehdit ve Zafiyet Analiz Raporu</h1>
                    <p>Kurumsal Altyapı Defans Denetim Modülü v7.5</p>
                </div>
                <h2>1. Hedef ve Sunucu Profil Bilgileri</h2>
                <table class="meta-table">
                    <tr><td class="title">Hedef Alan Adı</td><td>{self.target_domain}</td></tr>
                    <tr><td class="title">Sunucu IP</td><td>{self.target_ip}</td></tr>
                    <tr><td class="title">Tarama Zamanı</td><td>{scan_date}</td></tr>
                    <tr><td class="title">Açık Portlar</td><td>{', '.join(map(str, self.scan_results['open_ports'])) or 'Bulunamadı'}</td></tr>
                    <tr><td class="title">Güvenlik Başlıkları</td><td>{'<br>'.join(self.scan_results['security_headers']) or 'Analiz yapılmadı'}</td></tr>
                </table>
                <div class="footer">
                    <p>Bu rapor <strong>MarkOs National Enterprise Platform v7.5</strong> tarafından otomatik üretilmiştir.</p>
                    <p>&copy; 2026 memetcanwq31-ship-it. Tüm Hakları Saklıdır.</p>
                </div>
            </div>
        </body>
        </html>
        """
        with open(html_name, "w", encoding="utf-8") as f:
            f.write(html_content)

        print(f"\n{Fore.GREEN}[+] BAŞARILI: Kurumsal Raporlar Dışa Aktarıldı!\n  • {txt_name}\n  • {html_name}")
        input(f"\n{Fore.GREEN}Ana menüye dönmek için Enter'a basın...")

    def start_framework_engine(self):
        while self.is_running:
            self.show_banner()
            print(f"\n{Fore.WHITE} HEDEF YAPILANDIRMASI")
            if self.target_domain:
                print(f"    {Fore.YELLOW}[Mevcut Hedef: {self.target_domain} | IP: {self.target_ip}]")
            else:
                print(f"    {Fore.RED}[Şu An Tanımlı Hedef Yok!]")

            print(f"\n{Fore.CYAN}── SEÇİLEBİLİR SİBER İSTİHBARAT VE DB MOTORLARI ────────────")
            print(f"  {Fore.GREEN}[1]{Fore.WHITE}  Analiz Hedefi Tanımla ve IP Çözümle")
            print(f"  {Fore.GREEN}[2]{Fore.WHITE}  Adli Sistem Donanım Analizörü (psutil)")
            print(f"  {Fore.GREEN}[3]{Fore.WHITE}  GSM Telekom Format İstihbaratı (phonenumbers)")
            print(f"  {Fore.GREEN}[4]{Fore.WHITE}  Form Güvenliği ve CSRF Koruma Analizörü (bs4)")
            print(f"  {Fore.GREEN}[5]{Fore.WHITE}  Çoklu İş Parçacıklı Port Taraması (threading)")
            print(f"  {Fore.GREEN}[6]{Fore.WHITE}  HTTP Güvenlik Kalkanları ve HSTS Denetimi")
            print(f"  {Fore.GREEN}[7]{Fore.WHITE}  Veritabanı Mimari Analizörü (httpx)")
            print(f"  {Fore.GREEN}[8]{Fore.WHITE}  Yalancı Pozitif İstihbarat Radarı")
            print(f"  {Fore.GREEN}[9]{Fore.WHITE}  Subprocess Ağ Doğrulaması (subprocess)")
            print(f"  {Fore.GREEN}[10]{Fore.WHITE} SQLite Veritabanı Kayıt Defteri (sqlite3)")
            print(f"  {Fore.GREEN}[11]{Fore.WHITE} Kurumsal Rapor Oluştur (HTML/TXT)")
            print(f"  {Fore.RED}[0]  Framework Motorunu Kapat / Çıkış (Exit)")
            print(f"{Fore.GREEN}──────────────────────────────────────────────────────────")

            secim = input(f"{Fore.GREEN}MarkOs_Intel > Seçiminiz: {Style.RESET_ALL}").strip()

            if secim == "1":
                self.set_target()
                input(f"\n{Fore.GREEN}Devam etmek için Enter'a basın...")
            elif secim == "2":
                self.run_adli_donanim_monitoru()
            elif secim == "3":
                self.run_gsm_osint_validator()
            elif secim == "4":
                self.run_web_crawler_simulation()
            elif secim == "5":
                self.run_port_scanner()
            elif secim == "6":
                self.run_header_audit()
            elif secim == "7":
                self.run_db_type_fingerprinting()
            elif secim == "8":
                self.run_false_positive_radar()
            elif secim == "9":
                self.run_subprocess_ping_check()
            elif secim == "10":
                self.show_local_vault_logs()
            elif secim == "11":
                self.generate_enterprise_report()
            elif secim == "0":
                print(f"\n{Fore.RED}[!] MarkOs İstihbarat Çekirdeği kapatıldı. Harika mesai kankam!")
                self.is_running = False
            else:
                print(f"\n{Fore.RED}[!] Geçersiz numara! Lütfen listeden bir sayı seçin.")
                time.sleep(1.2)


if __name__ == "__main__":
    markos_engine = MarkOsDatabaseAndIntelCore()
    markos_engine.start_framework_engine()
