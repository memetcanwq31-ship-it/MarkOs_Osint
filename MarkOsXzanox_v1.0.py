import os
import sys
import socket
import ssl
import requests
import re
import time
from urllib.parse import urlparse, urlencode
from colorama import Fore, Style, init

init(autoreset=True)

def clear_screen():
    os.system('cls' if os.name == 'nt' else 'clear')

def show_banner():
    clear_screen()
    banner_text = f"""
{Fore.GREEN}███╗   ███╗ █████╗ ██████╗ ██╗  ██╗ ██████╗ ███████╗    ██╗  ██╗    ███████╗ █████╗ ███╗   ██╗ ██████╗ ██╗  ██╗
{Fore.GREEN}████╗ ████║██╔══██╗██╔══██╗██║ ██╔╝██╔═══██╗██╔════╝    ╚██╗██╔╝    ╚══███╔╝██╔══██╗████╗  ██║██╔═══██╗╚██╗██╔╝
{Fore.GREEN}██╔████╔██║███████║██████╔╝█████╔╝ ██║   ██║███████╗     ╚███╔╝       ███╔╝ ███████║██╔██╗ ██║██║   ██║ ╚███╔╝
{Fore.GREEN}██║╚██╔╝██║██╔══██║██╔══██╗██╔═██╗ ██║   ██║╚════██║     ██╔██╗      ███╔╝  ██╔══██║██║╚██╗██║██║   ██║ ██╔██╗
{Fore.GREEN}██║ ╚═╝ ██║██║  ██║██║  ██║██║  ██╗╚██████╔╝███████║    ██╔╝ ██╗    ███████╗██║  ██║██║ ╚████║╚██████╔╝██╔╝ ██╗
{Fore.GREEN}╚═╝     ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝ ╚══════╝    ╚═╝  ╚═╝    ╚══════╝╚═╝  ╚═╝╚═╝  ╚═══╝ ╚═════╝ ╚═╝  ╚═╝
{Fore.GREEN}=======================================================================================================
{Fore.GREEN}[+] Owner: memetcanwq31 | [+] Repo: MarkOs_osint | [+] Tool: Active Pentest Engine v1.1 [6 Tools]
{Fore.GREEN}=======================================================================================================
"""
    print(banner_text)

def show_menu():
    print(f"{Fore.GREEN} [1] SQL Entegrasyon & Guvenlik Testi")
    print(f"{Fore.GREEN} [2] Web Site Tam Analiz (Guvenlik Basliklari & Sunucu Tespiti)")
    print(f"{Fore.GREEN} [3] Web Site Admin Paneli Arama Tarama")
    print(f"{Fore.GREEN} [4] Robots.txt ve Sitemap.xml Analizoru")
    print(f"{Fore.GREEN} [5] Acik Port Taramasi ve Servis Analizi")
    print(f"{Fore.GREEN} [6] Kapsamli Zafiyet Tarama Araci")
    print(f"{Fore.RED} [0] Exit (Cikis)")
    print(Style.RESET_ALL)

def format_url(url):
    if not url.startswith("http"):
        url = "https://" + url
    return url.rstrip('/')

HEADERS = {"User-Agent": "MarkOs-Scanner"}

# ==================== MODUL 1: SQL TESTI ====================

def sql_integration_test():
    print(f"\n{Fore.GREEN}=== [1] SQL ENTEGRASYON & GUVENLIK TESTI ===")
    url = input(f"{Fore.GREEN}Test edilecek URL (Orn: https://example.com/page.php?id=1): {Style.RESET_ALL}").strip()
    if not url:
        return
    url = format_url(url)

    payloads = ["'", "\"", "' OR '1'='1", "\" OR \"1\"=\"1", "1' ORDER BY 10-- -"]
    sql_errors = {
        "MySQL": ["you have an error in your sql syntax", "warning: mysql_", "unterminated quoted string"],
        "PostgreSQL": ["postgresql query failed", "pg_query", "severity: error"],
        "MSSQL": ["[microsoft][odbc sql server driver]", "ole db provider for sql server", "unclosed quotation mark"],
        "Oracle": ["ora-01756", "ora-00933", "oracle error"],
        "SQLite": ["sqlite3::query failed", "unrecognized token"],
    }

    print(f"{Fore.GREEN}[*] Parametrelere SQL payloadlari enjekte ediliyor...\n")
    vuln_found = False

    for payload in payloads:
        test_url = f"{url}{payload}" if "?" in url else f"{url}?id={payload}"
        try:
            res = requests.get(test_url, timeout=6, headers=HEADERS)
            for db_name, errors in sql_errors.items():
                for error in errors:
                    if error.lower() in res.text.lower():
                        print(f"{Fore.YELLOW}[!] ZAFIYET TESPIT EDILDI! -> {db_name} SQL Hatasi Dondu.")
                        print(f"{Fore.GREEN}    Tetikleyici URL: {test_url}")
                        print(f"{Fore.GREEN}    Eslesen Desen: {error}")
                        vuln_found = True
                        break
        except requests.exceptions.RequestException as e:
            print(f"{Fore.RED}[!] Baglanti hatasi ({payload}): {e}")

    if not vuln_found:
        print(f"{Fore.GREEN}[+] Temiz! Temel SQL enjeksiyon testlerini basariyla gecti.")

# ==================== MODUL 2: TAM ANALIZ ====================

def website_full_analysis():
    print(f"\n{Fore.GREEN}=== [2] WEB SITE TAM ANALIZ ===")
    url = input(f"{Fore.GREEN}Hedef Domain veya URL: {Style.RESET_ALL}").strip()
    if not url:
        return
    url = format_url(url)

    try:
        print(f"{Fore.GREEN}[*] {url} sunucu ve guvenlik yapisi inceleniyor...\n")
        res = requests.get(url, timeout=6, headers=HEADERS)
        headers = res.headers

        print(f"{Fore.GREEN}[+] Status Kodu: {res.status_code}")
        print(f"{Fore.GREEN}[+] Kullanilan Sunucu Yazilimi: {headers.get('Server', 'Bilinmiyor')}")
        print(f"{Fore.GREEN}[+] Teknoloji Altyapisi (X-Powered-By): {headers.get('X-Powered-By', 'Bilinmiyor')}\n")

        critical_headers = {
            "X-Frame-Options": "Clickjacking",
            "Content-Security-Policy": "XSS / Kod Enjeksiyonu",
            "X-Content-Type-Options": "MIME Sniffing",
            "Strict-Transport-Security": "Man-in-the-Middle (SSL Zorlamasi)",
            "Referrer-Policy": "Bilgi Sizmasi (Referrer)",
            "Permissions-Policy": "Hassas Browser API Erisimi",
        }

        for h, desc in critical_headers.items():
            if h in headers:
                print(f"{Fore.GREEN}[+] Guvenli: {h} basligi aktif. ({headers[h]})")
            else:
                print(f"{Fore.YELLOW}[!] EKSIK/ZAFIYET: {h} basligi tanimlanmamis! (Risk: {desc})")
    except requests.exceptions.RequestException as e:
        print(f"{Fore.RED}[!] Hata: {e}")

# ==================== MODUL 3: ADMIN PANEL TARAMASI ====================

def admin_panel_scanner():
    print(f"\n{Fore.GREEN}=== [3] WEB SITE ADMIN PANELI ARAMA TARAMA ===")
    url = input(f"{Fore.GREEN}Hedef URL (Orn: example.com): {Style.RESET_ALL}").strip()
    if not url:
        return
    url = format_url(url)

    admin_paths = [
        "/admin", "/login", "/wp-login.php", "/admin.php", "/dashboard",
        "/administrator", "/user/login", "/cpanel", "/panel", "/admin_login",
        "/admin/login", "/adminpanel", "/manager", "/cms", "/backend",
        "/admin/admin.php", "/phpmyadmin", "/wp-admin", "/signin",
    ]

    print(f"{Fore.GREEN}[*] Admin paneli tarama algoritmasi baslatildi...\n")
    found_count = 0

    for path in admin_paths:
        target_path = f"{url}{path}"
        try:
            res = requests.get(target_path, timeout=4, allow_redirects=False, headers=HEADERS)
            if res.status_code in (200, 301, 302, 401, 403):
                print(f"{Fore.YELLOW}[+] POTANSIYEL PANEL BULUNDU: {target_path} (Status: {res.status_code})")
                found_count += 1
        except requests.exceptions.RequestException:
            pass

    print(f"\n{Fore.GREEN}[*] Tarama bitti. Toplam {found_count} olasi giris noktasi listelendi.")

# ==================== MODUL 4: ROBOTS/SITEMAP ====================

def robots_sitemap_analyzer():
    print(f"\n{Fore.GREEN}=== [4] ROBOTS.TXT VE SITEMAP.XML ANALIZORU ===")
    url = input(f"{Fore.GREEN}Hedef URL: {Style.RESET_ALL}").strip()
    if not url:
        return
    url = format_url(url)

    robots_url = f"{url}/robots.txt"
    print(f"\n{Fore.GREEN}[*] {robots_url} taraniyor...")
    try:
        res_robots = requests.get(robots_url, timeout=5, headers=HEADERS)
        if res_robots.status_code == 200 and "user-agent" in res_robots.text.lower():
            print(f"{Fore.GREEN}[+] Robots.txt dosyasi AKTIF! Icerik analiz ediliyor:")
            lines = res_robots.text.split("\n")
            disallow_count = 0
            for line in lines[:15]:
                if line.strip().lower().startswith("disallow"):
                    print(f"{Fore.YELLOW}    [!] Gizlenen Dizin: {line.strip()}")
                    disallow_count += 1
            if len(lines) > 15:
                print(f"{Fore.GREEN}    ... ve dahasi var.")
            print(f"{Fore.GREEN}[+] Toplam {disallow_count} gizli dizin/ayar bulundu (ilk 15 satir).")
        else:
            print(f"{Fore.RED}[-] Robots.txt bulunamadi veya erisilemez durumda (Status: {res_robots.status_code})")
    except requests.exceptions.RequestException as e:
        print(f"{Fore.RED}[!] Robots.txt taranirken hata olustu: {e}")

    sitemap_url = f"{url}/sitemap.xml"
    print(f"\n{Fore.GREEN}[*] {sitemap_url} taraniyor...")
    try:
        res_site = requests.get(sitemap_url, timeout=5, headers=HEADERS)
        if res_site.status_code == 200 and "<urlset" in res_site.text.lower():
            urls = re.findall(r"<loc>(.*?)</loc>", res_site.text)
            print(f"{Fore.GREEN}[+] Sitemap.xml AKTIF! Sistem haritasi cozuldu.")
            print(f"{Fore.GREEN}[+] Haritada toplam {len(urls)} adet indekslenmis sayfa linki bulundu.")
            for u in urls[:5]:
                print(f"{Fore.GREEN}    - {u}")
        else:
            print(f"{Fore.RED}[-] Sitemap.xml bulunamadi (Status: {res_site.status_code})")
    except requests.exceptions.RequestException as e:
        print(f"{Fore.RED}[!] Sitemap.xml taranirken hata olustu: {e}")

# ==================== MODUL 5: PORT TARAMASI ====================

def port_scanner():
    print(f"\n{Fore.GREEN}=== [5] ACIK PORT TARAMASI VE SERVIS ANALIZI ===")
    target = input(f"{Fore.GREEN}Hedef IP veya Alan Adi (Domain): {Style.RESET_ALL}").strip()
    if not target:
        return

    try:
        target_ip = socket.gethostbyname(target)
        print(f"{Fore.GREEN}[*] Cozumlenen IP: {target_ip}")
        print(f"{Fore.GREEN}[*] Kritik servis portlari taraniyor...\n")

        critical_ports = {
            21: "FTP (Dosya Transferi)",
            22: "SSH (Guvenli Baglanti)",
            23: "Telnet (Sifresiz Baglanti)",
            25: "SMTP (E-Posta Servisi)",
            53: "DNS",
            80: "HTTP (Web Sunucu)",
            110: "POP3",
            143: "IMAP",
            443: "HTTPS (Guvenli Web)",
            445: "SMB (Dosya Paylasimi / EternalBlue Riski)",
            3306: "MySQL (Veritabani)",
            3389: "RDP (Uzak Masaustu)",
            8080: "HTTP-Proxy / Alternatif Web",
        }

        open_ports = 0
        for port, service in critical_ports.items():
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(1.0)
            result = s.connect_ex((target_ip, port))
            if result == 0:
                print(f"{Fore.YELLOW}[+] Port {port} ACIK! -> Servis: {service}")
                open_ports += 1
            s.close()

        print(f"\n{Fore.GREEN}[*] Ag analizi tamamlandi. Toplam {open_ports} acik port bulundu.")

    except socket.gaierror:
        print(f"{Fore.RED}[!] Hata: Domain cozumlenemedi. Internet baglantini veya adresi kontrol et.")
    except Exception as e:
        print(f"{Fore.RED}[!] Beklenmedik Tarama Hatasi: {e}")

# ==================== MODUL 6: ZAFIYET TARAMA (YENI) ====================

def vulnerability_scanner():
    print(f"\n{Fore.GREEN}=== [6] KAPSAMLI ZAFIYET TARAMA ARACI ===")
    url = input(f"{Fore.GREEN}Hedef URL: {Style.RESET_ALL}").strip()
    if not url:
        return
    url = format_url(url)
    parsed = urlparse(url)
    findings = 0

    print(f"{Fore.GREEN}[*] {url} uzerinde kapsamli zafiyet taramasi basliyor...\n")

    # --- 6.1 SSL/TLS Kontrolu ---
    print(f"{Fore.GREEN}[*] [6.1] SSL/TLS Yapilandirmasi Kontrol Ediliyor...")
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((parsed.hostname, 443), timeout=5) as sock:
            with ctx.wrap_socket(sock, server_hostname=parsed.hostname) as ssock:
                cert = ssock.getpeercert()
                proto = ssock.version()
                print(f"{Fore.GREEN}[+] SSL Aktif - Protokol: {proto}")
                not_after = cert.get('notAfter')
                print(f"{Fore.GREEN}[+] Sertifika Gecerlilik Bitisi: {not_after}")
    except ssl.SSLError as e:
        print(f"{Fore.YELLOW}[!] SSL Sorunu: {e}")
        findings += 1
    except Exception:
        print(f"{Fore.RED}[-] 443 portu uzerinden SSL baglantisi kurulamadi (HTTP-only sunucu olabilir).")
        findings += 1

    # --- 6.2 Reflected XSS Kontrolu ---
    print(f"\n{Fore.GREEN}[*] [6.2] Reflected XSS Testi Baslatiliyor...")
    xss_payload = "<script>markos</script>"
    try:
        test_url = f"{url}?q={xss_payload}" if "?" not in url else f"{url}&q={xss_payload}"
        res = requests.get(test_url, timeout=6, headers=HEADERS)
        if xss_payload in res.text:
            print(f"{Fore.YELLOW}[!] POTANSIYEL REFLECTED XSS: Payload yanitta yansimadi ama kod olarak dondu!")
            print(f"{Fore.GREEN}    Test URL: {test_url}")
            findings += 1
        else:
            print(f"{Fore.GREEN}[+] Reflected XSS bulunamadi (q parametresi).")
    except requests.exceptions.RequestException as e:
        print(f"{Fore.RED}[!] XSS testi baglanti hatasi: {e}")

    # --- 6.3 Acik Dizin Listeleme Kontrolu ---
    print(f"\n{Fore.GREEN}[*] [6.3] Dizin Listeleme (Directory Listing) Kontrolu...")
    listing_paths = ["/uploads/", "/backup/", "/images/", "/files/", "/.git/", "/tmp/", "/config/"]
    for path in listing_paths:
        try:
            res = requests.get(f"{url}{path}", timeout=4, headers=HEADERS)
            if res.status_code == 200 and ("Index of /" in res.text or "Directory listing for" in res.text):
                print(f"{Fore.YELLOW}[!] ACIK DIZIN LISTELEME: {url}{path}")
                findings += 1
        except requests.exceptions.RequestException:
            pass
    print(f"{Fore.GREEN}[*] Dizin listeleme taramasi tamamlandi.")

    # --- 6.4 Acik Redirect Kontrolu ---
    print(f"\n{Fore.GREEN}[*] [6.4] Acik Redirect (Open Redirect) Testi...")
    try:
        redirect_test_url = f"{url}?redirect=https://example.com&url=https://example.com&next=https://example.com"
        res = requests.get(redirect_test_url, timeout=6, headers=HEADERS, allow_redirects=False)
        location = res.headers.get("Location", "")
        if res.status_code in (301, 302, 303, 307) and "example.com" in location:
            print(f"{Fore.YELLOW}[!] POTANSIYEL ACIK REDIRECT: {location}")
            findings += 1
        else:
            print(f"{Fore.GREEN}[+] Acik redirect bulunamadi.")
    except requests.exceptions.RequestException as e:
        print(f"{Fore.RED}[!] Redirect testi hatasi: {e}")

    # --- 6.5 Cookie Guvenlik Bayraklari ---
    print(f"\n{Fore.GREEN}[*] [6.5] Cookie Guvenlik Bayraklari Kontrolu...")
    try:
        res = requests.get(url, timeout=6, headers=HEADERS)
        cookies = res.headers.get("Set-Cookie", "")
        if cookies:
            if "httponly" not in cookies.lower():
                print(f"{Fore.YELLOW}[!] Cookie'de HttpOnly bayragi yok (XSS ile cookie calinabilir).")
                findings += 1
            if "secure" not in cookies.lower():
                print(f"{Fore.YELLOW}[!] Cookie'de Secure bayragi yok (HTTP uzerinden tasiniyor olabilir).")
                findings += 1
            if "samesite" not in cookies.lower():
                print(f"{Fore.YELLOW}[!] Cookie'de SameSite bayragi yok (CSRF riski).")
                findings += 1
        else:
            print(f"{Fore.GREEN}[+] Sunucu cookie setlemiyor.")
    except requests.exceptions.RequestException as e:
        print(f"{Fore.RED}[!] Cookie testi hatasi: {e}")

    # --- 6.6 Hassas Dosyalar ---
    print(f"\n{Fore.GREEN}[*] [6.6] Hassas Dosya / Bilgi Sizmasi Kontrolu...")
    sensitive_paths = [
        "/.env", "/.git/config", "/composer.json", "/package.json",
        "/phpinfo.php", "/info.php", "/server-status", "/backup.sql",
        "/wp-config.php.bak", "/.DS_Store", "/id_rsa",
    ]
    for path in sensitive_paths:
        try:
            res = requests.get(f"{url}{path}", timeout=4, headers=HEADERS)
            if res.status_code == 200 and len(res.text) > 0:
                print(f"{Fore.YELLOW}[!] HASSAS DOSYA ERISILEBILIYOR: {url}{path} (Boyut: {len(res.text)} byte)")
                findings += 1
        except requests.exceptions.RequestException:
            pass
    print(f"{Fore.GREEN}[*] Hassas dosya taramasi tamamlandi.")

    # --- Ozet ---
    print(f"\n{Fore.GREEN}===============================================")
    if findings > 0:
        print(f"{Fore.YELLOW}[!] Tarama bitti. Toplam {findings} olasi zafiyet/bulgul tespit edildi.")
    else:
        print(f"{Fore.GREEN}[+] Tarama bitti. Kritik zafiyet bulunamadi.")
    print(f"{Fore.GREEN}===============================================")

# ==================== ANA MENU ====================

def main():
    while True:
        show_banner()
        show_menu()
        secim = input(f"{Fore.GREEN}MarkOs > Seciminiz: {Style.RESET_ALL}").strip()

        if secim == "1":
            sql_integration_test()
        elif secim == "2":
            website_full_analysis()
        elif secim == "3":
            admin_panel_scanner()
        elif secim == "4":
            robots_sitemap_analyzer()
        elif secim == "5":
            port_scanner()
        elif secim == "6":
            vulnerability_scanner()
        elif secim == "0":
            print(f"\n{Fore.RED}[!] Programdan cikiliyor. MarkOs X Zanox v1.1 basariyla kapatildi!")
            sys.exit(0)
        else:
            print(f"\n{Fore.RED}[!] Gecersiz secim yaptin kankam!")
            time.sleep(1)
            continue

        input(f"\n{Fore.GREEN}Menuye donmek icin Enter'a basin...")

if __name__ == "__main__":
    main()
