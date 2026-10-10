import os
import sys
import socket
import requests
import re
import time
import ssl
import json
import urllib.parse
import concurrent.futures
from colorama import Fore, Style, init

# httpx opsiyonel - yoksa requests ile devam eder
try:
    import httpx
    HAS_HTTPX = True
except ImportError:
    HAS_HTTPX = False

init(autoreset=True)

HEADERS = {"User-Agent": "MarkOs-Scanner/2.0"}
TIMEOUT = 6

def clear_screen():
    os.system('cls' if os.name == 'nt' else 'clear')

def show_banner():
    clear_screen()
    print(f"""{Fore.GREEN}
███╗   ███╗ █████╗ ██████╗ ██╗  ██╗ ██████╗ ███████╗    ██╗  ██╗    ███████╗ █████╗ ███╗   ██╗ ██████╗ ██╗  ██╗
████╗ ████║██╔══██╗██╔══██╗██║ ██╔╝██╔═══██╗██╔════╝    ╚██╗██╔╝    ╚══███╔╝██╔══██╗████╗  ██║██╔═══██╗╚██╗██╔╝
██╔████╔██║███████║██████╔╝█████╔╝ ██║   ██║███████╗     ╚███╔╝       ███╔╝ ███████║██╔██╗ ██║██║   ██║ ╚███╔╝
██║╚██╔╝██║██╔══██║██╔══██╗██╔═██╗ ██║   ██║╚════██║     ██╔██╗      ███╔╝  ██╔══██║██║╚██╗██║██║   ██║ ██╔██╗
██║ ╚═╝ ██║██║  ██║██║  ██║██║  ██╗╚██████╔╝███████║    ██╔╝ ██╗    ███████╗██║  ██║██║ ╚████║╚██████╔╝██╔╝ ██╗
╚═╝     ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝ ╚══════╝    ╚═╝  ╚═╝    ╚══════╝╚═╝  ╚═╝╚═╝  ╚═══╝ ╚═════╝ ╚═╝  ╚═╝
=======================================================================================================
{Fore.CYAN}[+] Owner: memetcanwq31 | [+] Repo: MarkOs_osint | [+] Tool: Vulnerability Suite v2.0 [15 FULL TOOLS]
{Fore.GREEN}======================================================================================================={Style.RESET_ALL}""")

def show_menu():
    print(f"""
{Fore.GREEN} ──────────────── ZAFİYET & OSINT SÜİTİ v2.0 ────────────────
{Fore.CYAN} [1]{Fore.GREEN}  SQL Enjeksiyon & Hata Tabanlı Zafiyet Testi
{Fore.CYAN} [2]{Fore.GREEN}  Web Güvenlik Başlıkları (Header) Analizi
{Fore.CYAN} [3]{Fore.GREEN}  Admin Panel / Gizli Dizin Taraması
{Fore.CYAN} [4]{Fore.GREEN}  Robots.txt & Sitemap.xml Bilgi İfşası Kontrolü
{Fore.CYAN} [5]{Fore.GREEN}  Açık Port & Servis Zafiyet Analizi
{Fore.CYAN} [6]{Fore.GREEN}  Subdomain Keşif Motoru (Multithread)
{Fore.CYAN} [7]{Fore.GREEN}  SSL/TLS Sertifika Güvenlik Denetleyicisi
{Fore.CYAN} [8]{Fore.GREEN}  DNS Kayıt Sorgulayıcı (A, MX, NS, TXT, CNAME)
{Fore.CYAN} [9]{Fore.GREEN}  Whois / RDAP Domain Yaşı & Kayıt Analizi
{Fore.CYAN} [10]{Fore.GREEN} Kaynak Kod Link/URL Ayıklayıcı (Scraper)
{Fore.CYAN} [11]{Fore.GREEN} IP Coğrafi Konum & ISP Tespit Edici
{Fore.CYAN} [12]{Fore.GREEN} Sunucu Yanıt (Stres/Dayanıklılık) Ölçer
{Fore.CYAN} [13]{Fore.GREEN} CMS Sürüm Dedektörü (WordPress, Joomla, Drupal)
{Fore.CYAN} [14]{Fore.GREEN} HTTP Metodları İzin Denetimi (OPTIONS, PUT, TRACE)
{Fore.CYAN} [15]{Fore.GREEN} SPF/DKIM/DMARC E-Posta Güvenlik Analizi
{Fore.RED} [0]  Exit (Çıkış)
{Style.RESET_ALL}""")

def format_url(url):
    if not url.startswith("http"):
        url = "https://" + url
    return url.rstrip('/')

def get_domain(url):
    return urllib.parse.urlparse(format_url(url)).netloc

def pause():
    input(f"\n{Fore.GREEN}Menüye dönmek için Enter'a basın...{Style.RESET_ALL}")

# ==================== MODÜL 1: SQL TESTİ ====================

def tool_1():
    print(f"\n{Fore.GREEN}=== [1] SQL ENJEKSİYON & HATA TESTİ ===")
    url = input(f"{Fore.CYAN}Test URL (Örn: https://site.com/sayfa.php?id=1): {Style.RESET_ALL}").strip()
    if not url: return
    url = format_url(url)
    payloads = ["'", "\"", "' OR '1'='1", "\" OR \"1\"=\"1", "1' ORDER BY 10-- -", "1 UNION SELECT NULL-- -"]
    sql_errors = {
        "MySQL": ["you have an error in your sql syntax", "warning: mysql_", "mysqli"],
        "PostgreSQL": ["postgresql query failed", "pg_query", "unterminated"],
        "MSSQL": ["[microsoft][odbc sql server driver]", "unclosed quotation mark"],
        "Oracle": ["ora-01756", "ora-00933"],
        "SQLite": ["sqlite3::query failed", "unrecognized token"],
    }
    vuln = False
    print(f"{Fore.GREEN}[*] Payload'lar enjekte ediliyor...\n")
    for p in payloads:
        t_url = f"{url}{p}" if "?" in url else f"{url}?id={urllib.parse.quote(p)}"
        try:
            res = requests.get(t_url, timeout=TIMEOUT, headers=HEADERS)
            for db, errs in sql_errors.items():
                for err in errs:
                    if err.lower() in res.text.lower():
                        print(f"{Fore.YELLOW}[!] ZAFİYET: {db} hatası döndü!")
                        print(f"{Fore.CYAN}    Payload : {p}")
                        print(f"{Fore.CYAN}    URL     : {t_url}")
                        vuln = True
                        break
        except requests.exceptions.RequestException:
            pass
    if not vuln:
        print(f"{Fore.GREEN}[+] Temiz: Temel SQL hata işaretçilerine rastlanmadı.")

# ==================== MODÜL 2: HEADER ANALİZİ ====================

def tool_2():
    print(f"\n{Fore.GREEN}=== [2] GÜVENLİK BAŞLIKLARI ANALİZİ ===")
    url = input(f"{Fore.CYAN}Hedef URL: {Style.RESET_ALL}").strip()
    if not url: return
    try:
        res = requests.get(format_url(url), timeout=TIMEOUT, headers=HEADERS)
        h = res.headers
        print(f"\n{Fore.CYAN}[*] Status: {res.status_code}")
        print(f"{Fore.GREEN}[+] Sunucu        : {h.get('Server', 'Gizli')}")
        print(f"{Fore.GREEN}[+] X-Powered-By  : {h.get('X-Powered-By', 'Gizli')}\n")
        checks = {
            "X-Frame-Options": "Clickjacking",
            "Content-Security-Policy": "XSS / Kod Enjeksiyonu",
            "X-Content-Type-Options": "MIME Sniffing",
            "Strict-Transport-Security": "MITM / HSTS Eksikliği",
            "Referrer-Policy": "Referrer Bilgi Sızması",
        }
        risk = 0
        for head, desc in checks.items():
            if head in h:
                print(f"{Fore.GREEN}[+] AKTİF   : {head}")
            else:
                print(f"{Fore.YELLOW}[!] EKSİK  : {head} (Risk: {desc})")
                risk += 1
        print(f"\n{Fore.GREEN}[*] Sonuç: {5 - risk}/5 başlık aktif, {risk} eksik.")
    except requests.exceptions.RequestException as e:
        print(f"{Fore.RED}[!] Hata: {e}")

# ==================== MODÜL 3: ADMIN PANEL TARAMASI ====================

def tool_3():
    print(f"\n{Fore.GREEN}=== [3] ADMİN PANELİ TARAMASI ===")
    url = input(f"{Fore.CYAN}Hedef URL: {Style.RESET_ALL}").strip()
    if not url: return
    url = format_url(url)
    paths = [
        "/admin", "/login", "/wp-login.php", "/wp-admin", "/admin.php",
        "/dashboard", "/administrator", "/cpanel", "/panel", "/user/login",
        "/phpmyadmin", "/admin/login", "/backend", "/manager", "/cms",
    ]
    found = 0
    print(f"{Fore.GREEN}[*] {len(paths)} yol taranıyor...\n")
    for p in paths:
        try:
            res = requests.get(f"{url}{p}", timeout=3, allow_redirects=False, headers=HEADERS)
            if res.status_code in (200, 301, 302, 401, 403):
                print(f"{Fore.YELLOW}[+] BULUNDU: {url}{p} (Kod: {res.status_code})")
                found += 1
        except requests.exceptions.RequestException:
            pass
    print(f"\n{Fore.GREEN}[*] Tarama bitti. {found} olası giriş noktası bulundu.")

# ==================== MODÜL 4: ROBOTS/SITEMAP ====================

def tool_4():
    print(f"\n{Fore.GREEN}=== [4] ROBOTS.TXT & SITEMAP.XML ANALİZİ ===")
    url = input(f"{Fore.CYAN}Hedef URL: {Style.RESET_ALL}").strip()
    if not url: return
    url = format_url(url)
    try:
        r = requests.get(f"{url}/robots.txt", timeout=4, headers=HEADERS)
        if r.status_code == 200 and "user-agent" in r.text.lower():
            print(f"{Fore.GREEN}[+] Robots.txt Aktif:")
            count = 0
            for line in r.text.split("\n"):
                if line.strip().lower().startswith("disallow"):
                    print(f"{Fore.YELLOW}    {line.strip()}")
                    count += 1
            print(f"{Fore.GREEN}[+] Toplam {count} gizli dizin bildirimi.")
        else:
            print(f"{Fore.RED}[-] Robots.txt bulunamadı (Kod: {r.status_code})")
    except requests.exceptions.RequestException:
        print(f"{Fore.RED}[-] Robots.txt erişilemedi.")
    try:
        s = requests.get(f"{url}/sitemap.xml", timeout=4, headers=HEADERS)
        if s.status_code == 200 and "<urlset" in s.text.lower():
            links = re.findall(r"<loc>(.*?)</loc>", s.text)
            print(f"{Fore.GREEN}[+] Sitemap.xml Aktif. Toplam Link: {len(links)}")
            for u in links[:5]:
                print(f"{Fore.CYAN}    - {u}")
        else:
            print(f"{Fore.RED}[-] Sitemap.xml bulunamadı (Kod: {s.status_code})")
    except requests.exceptions.RequestException:
        print(f"{Fore.RED}[-] Sitemap.xml erişilemedi.")

# ==================== MODÜL 5: PORT TARAMASI ====================

def tool_5():
    print(f"\n{Fore.GREEN}=== [5] PORT & SERVİS ANALİZİ ===")
    target = input(f"{Fore.CYAN}Hedef IP veya Domain: {Style.RESET_ALL}").strip()
    if not target: return
    try:
        ip = socket.gethostbyname(target)
        print(f"{Fore.GREEN}[*] Hedef IP: {ip}\n")
        ports = {
            21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
            80: "HTTP", 110: "POP3", 143: "IMAP", 443: "HTTPS",
            445: "SMB (EternalBlue Riski)", 3306: "MySQL", 3389: "RDP", 8080: "HTTP-Alt",
        }
        open_count = 0
        for port, name in ports.items():
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(0.8)
            if s.connect_ex((ip, port)) == 0:
                print(f"{Fore.YELLOW}[+] Port {port:<6} AÇIK  ->  {name}")
                open_count += 1
            s.close()
        print(f"\n{Fore.GREEN}[*] Tarama bitti. {open_count} açık port bulundu.")
    except socket.gaierror:
        print(f"{Fore.RED}[!] Domain çözümlenemedi.")
    except Exception as e:
        print(f"{Fore.RED}[!] Hata: {e}")

# ==================== MODÜL 6: SUBDOMAIN KEŞFİ ====================

def tool_6():
    print(f"\n{Fore.GREEN}=== [6] SUBDOMAIN KEŞİF MOTORU ===")
    domain = input(f"{Fore.CYAN}Ana Domain (Örn: google.com): {Style.RESET_ALL}").strip()
    if not domain: return
    subs = [
        "www", "mail", "ftp", "admin", "blog", "cpanel", "api", "dev", "staging",
        "secure", "ns1", "ns2", "vpn", "remote", "portal", "shop", "app", "cdn",
        "test", "beta", "git", "jira", "webmail", "smtp", "db", "cloud",
    ]
    found = []
    print(f"{Fore.GREEN}[*] {len(subs)} alt domain test ediliyor...\n")

    def check(sub):
        for scheme in ("https",):
            target = f"{scheme}://{sub}.{domain}"
            try:
                res = requests.get(target, timeout=3, headers=HEADERS, allow_redirects=True)
                return (target, res.status_code)
            except requests.exceptions.RequestException:
                continue
        # HTTPS yoksa DNS kaydı var mı diye bak
        try:
            socket.gethostbyname(f"{sub}.{domain}")
            return (f"{sub}.{domain}", "DNS-Only")
        except socket.gaierror:
            return None

    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as ex:
        for result in ex.map(check, subs):
            if result:
                target, code = result
                print(f"{Fore.YELLOW}[+] AKTİF: {target} (Durum: {code})")
                found.append(target)

    print(f"\n{Fore.GREEN}[*] Keşif bitti. {len(found)} aktif subdomain bulundu.")

# ==================== MODÜL 7: SSL DENETLEYİCİ ====================

def tool_7():
    print(f"\n{Fore.GREEN}=== [7] SSL/TLS SERTİFİKA DENETLEYİCİSİ ===")
    domain = get_domain(input(f"{Fore.CYAN}Hedef Domain: {Style.RESET_ALL}").strip())
    if not domain: return
    ctx = ssl.create_default_context()
    try:
        with socket.create_connection((domain, 443), timeout=5) as sock:
            with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                print(f"{Fore.GREEN}[+] TLS Sürümü        : {ssock.version()}")
                print(f"{Fore.GREEN}[+] Şifreleme         : {ssock.cipher()[0]} ({ssock.cipher()[2]} bit)")
                print(f"{Fore.GREEN}[+] Sertifikai Tarafı : {dict(x[0] for x in cert['subject']).get('organizationName', 'Bilinmiyor')}")
                print(f"{Fore.GREEN}[+] Geçerlilik Bitiş  : {cert.get('notAfter', 'Bilinmiyor')}")
                if ssock.version() in ("TLSv1", "TLSv1.1"):
                    print(f"{Fore.YELLOW}[!] ESKİ TLS SÜRÜMÜ! TLS 1.2+ kullanılmalı.")
    except ssl.SSLCertVerificationError:
        print(f"{Fore.YELLOW}[!] Sertifika doğrulaması BAŞARISIZ (kendinden imzalı / süresi dolmuş olabilir).")
    except Exception as e:
        print(f"{Fore.YELLOW}[!] SSL hatası: {e}")

# ==================== MODÜL 8: DNS SORGULAYICI ====================

def tool_8():
    print(f"\n{Fore.GREEN}=== [8] DNS KAYIT SORGULAYICI ===")
    domain = get_domain(input(f"{Fore.CYAN}Hedef Domain: {Style.RESET_ALL}").strip())
    if not domain: return
    print(f"{Fore.GREEN}[*] Cloudflare DNS (DoH) üzerinden sorgulanıyor...\n")
    for t in ["A", "AAAA", "MX", "NS", "TXT", "CNAME"]:
        try:
            res = requests.get(
                "https://cloudflare-dns.com/dns-query",
                params={"name": domain, "type": t},
                headers={"Accept": "application/dns-json"},
                timeout=5,
            )
            data = res.json()
            if "Answer" in data:
                for ans in data["Answer"]:
                    print(f"{Fore.GREEN}[+] {t:<6}: {ans['data']}")
            else:
                print(f"{Fore.YELLOW}[*] {t:<6}: Kayıt yok")
        except Exception:
            print(f"{Fore.RED}[!] {t:<6}: Sorgu hatası")

# ==================== MODÜL 9: WHOIS/RDAP ====================

def tool_9():
    print(f"\n{Fore.GREEN}=== [9] WHOIS / RDAP ANALİZİ ===")
    domain = get_domain(input(f"{Fore.CYAN}Hedef Domain: {Style.RESET_ALL}").strip())
    if not domain: return
    try:
        res = requests.get(f"https://rdap.org/domain/{domain}", timeout=6)
        if res.status_code == 200:
            data = res.json()
            print(f"{Fore.GREEN}[+] Kayıt Kuruluşu: {data.get('port43', 'Bilinmiyor')}")
            for event in data.get('events', []):
                print(f"{Fore.GREEN}[+] {event.get('action', '?')}: {event.get('eventDate', '?')}")
            for ent in data.get('entities', []):
                roles = ", ".join(ent.get('roles', []))
                if roles:
                    print(f"{Fore.CYAN}[*] Varlık Rolü: {roles}")
        else:
            print(f"{Fore.RED}[-] RDAP verisi çekilemedi (Kod: {res.status_code})")
    except Exception as e:
        print(f"{Fore.RED}[!] Hata: {e}")

# ==================== MODÜL 10: LINK SCRAPER ====================

def tool_10():
    print(f"\n{Fore.GREEN}=== [10] KAYNAK KOD LINK AYIKLAYICI ===")
    url = input(f"{Fore.CYAN}Hedef URL: {Style.RESET_ALL}").strip()
    if not url: return
    try:
        res = requests.get(format_url(url), timeout=6, headers=HEADERS)
        links = re.findall(r'href=["\'](.*?)["\']', res.text)
        srcs = re.findall(r'src=["\'](.*?)["\']', res.text)
        forms = re.findall(r'<form[^>]*action=["\'](.*?)["\']', res.text)
        emails = re.findall(r'[\w.+-]+@[\w-]+\.[\w.]+', res.text)
        comments = re.findall(r'<!--(.*?)-->', res.text, re.S)
        print(f"\n{Fore.GREEN}[+] Bulunan Linkler ({len(links)}):")
        for l in sorted(set(links))[:20]:
            print(f"{Fore.CYAN}    - {l}")
        print(f"{Fore.GREEN}[+] Kaynak Dosyalar ({len(srcs)}):")
        for s in sorted(set(srcs))[:10]:
            print(f"{Fore.CYAN}    - {s}")
        if forms:
            print(f"{Fore.YELLOW}[!] Form Action'ları ({len(forms)}): {set(forms)}")
        if emails:
            print(f"{Fore.YELLOW}[!] Kaynakta E-Posta: {set(emails)}")
        if comments:
            print(f"{Fore.YELLOW}[!] HTML Yorumları ({len(comments)}):")
            for c in comments[:5]:
                print(f"{Fore.CYAN}    - {c.strip()[:100]}")
    except requests.exceptions.RequestException as e:
        print(f"{Fore.RED}[!] Hata: {e}")

# ==================== MODÜL 11: IP GEO/ISP ====================

def tool_11():
    print(f"\n{Fore.GREEN}=== [11] IP KONUM & ISP TESPİTİ ===")
    target = input(f"{Fore.CYAN}Domain veya IP: {Style.RESET_ALL}").strip()
    if not target: return
    try:
        ip = socket.gethostbyname(target) if not target.replace('.', '').isdigit() else target
        res = requests.get(f"http://ip-api.com/json/{ip}", timeout=6).json()
        if res.get("status") == "success":
            print(f"{Fore.GREEN}[+] IP          : {ip}")
            print(f"{Fore.GREEN}[+] Ülke        : {res.get('country')} ({res.get('countryCode')})")
            print(f"{Fore.GREEN}[+] Şehir       : {res.get('city')}")
            print(f"{Fore.GREEN}[+] ISP         : {res.get('isp')}")
            print(f"{Fore.GREEN}[+] Organizasyon: {res.get('org')}")
            print(f"{Fore.GREEN}[+] ASN         : {res.get('as')}")
            print(f"{Fore.GREEN}[+] Koordinat   : {res.get('lat')}, {res.get('lon')}")
        else:
            print(f"{Fore.RED}[-] Konum verisi alınamadı.")
    except Exception as e:
        print(f"{Fore.RED}[!] Hata: {e}")

# ==================== MODÜL 12: YANIT/STRES ÖLÇER ====================

def tool_12():
    print(f"\n{Fore.GREEN}=== [12] SUNUCU YANIT & DAYANIKLILIK ÖLÇER ===")
    url = input(f"{Fore.CYAN}Hedef URL: {Style.RESET_ALL}").strip()
    if not url: return
    url = format_url(url)
    n = 10
    print(f"{Fore.GREEN}[*] {n} ardışık istek gönderiliyor...\n")
    times = []
    for i in range(n):
        try:
            start = time.time()
            res = requests.get(url, timeout=8, headers=HEADERS)
            elapsed = (time.time() - start) * 1000
            times.append(elapsed)
            print(f"{Fore.CYAN}    İstek {i+1:<3}: {elapsed:.0f} ms  (Kod: {res.status_code}, Boyut: {len(res.content)} B)")
            time.sleep(0.3)
        except requests.exceptions.RequestException as e:
            print(f"{Fore.RED}    İstek {i+1:<3}: BAŞARISIZ ({e})")
    if times:
        avg = sum(times) / len(times)
        print(f"\n{Fore.GREEN}[+] Ortalama Yanıt : {avg:.0f} ms")
        print(f"{Fore.GREEN}[+] En Hızlı       : {min(times):.0f} ms")
        print(f"{Fore.GREEN}[+] En Yavaş       : {max(times):.0f} ms")
        if avg > 1500:
            print(f"{Fore.YELLOW}[!] Ortalama yanıt yüksek — performans/WAF gecikmesi olabilir.")

# ==================== MODÜL 13: CMS DETEKTÖRÜ ====================

def tool_13():
    print(f"\n{Fore.GREEN}=== [13] CMS SÜRÜM DETEKTÖRÜ ===")
    url = input(f"{Fore.CYAN}Hedef URL: {Style.RESET_ALL}").strip()
    if not url: return
    url = format_url(url)
    signatures = [
        ("/wp-login.php", "WordPress", r'wp-content|wp-includes'),
        ("/wp-content/", "WordPress", r'wp-content'),
        ("/administrator/", "Joomla", r'Joomla!'),
        ("/misc/drupal.js", "Drupal", r'Drupal'),
        ("/sites/default/files", "Drupal", r'sites/default'),
        ("/readme.html", "WordPress", r'WordPress'),
        ("/CHANGELOG.txt", "Drupal", r'Drupal'),
    ]
    detected = set()
    try:
        res = requests.get(url, timeout=6, headers=HEADERS)
        body = res.text.lower()
        for path, cms, pattern in signatures:
            try:
                r = requests.get(f"{url}{path}", timeout=4, headers=HEADERS)
                if r.status_code == 200 and re.search(pattern, r.text, re.I):
                    if cms not in detected:
                        print(f"{Fore.YELLOW}[+] CMS TESPİT EDİLDİ: {cms} (Kanıt: {path})")
                        detected.add(cms)
            except requests.exceptions.RequestException:
                pass
        # Generator meta tag
        gen = re.search(r'<meta name="generator" content="([^"]+)"', res.text, re.I)
        if gen:
            print(f"{Fore.GREEN}[+] Generator Meta   : {gen.group(1)}")
        if not detected and not gen:
            print(f"{Fore.GREEN}[-] Bilinen CMS imzası bulunamadı (özel yazılım olabilir).")
        # WordPress sürüm detayı
        try:
            r = requests.get(f"{url}/feed/", timeout=4, headers=HEADERS)
            m = re.search(r'<generator>(.*?)</generator>', r.text)
            if m and "wordpress" in m.group(1).lower():
                print(f"{Fore.YELLOW}[+] WordPress Sürümü: {m.group(1).strip()}")
        except requests.exceptions.RequestException:
            pass
    except requests.exceptions.RequestException as e:
        print(f"{Fore.RED}[!] Hata: {e}")

# ==================== MODÜL 14: HTTP METOT DENETİMİ ====================

def tool_14():
    print(f"\n{Fore.GREEN}=== [14] HTTP METOT İZİN DENETİMİ ===")
    url = input(f"{Fore.CYAN}Hedef URL: {Style.RESET_ALL}").strip()
    if not url: return
    url = format_url(url)
    try:
        res = requests.options(url, timeout=5, headers=HEADERS)
        allow = res.headers.get("Allow", res.headers.get("Public", ""))
        if allow:
            print(f"{Fore.GREEN}[+] İzin Verilen Metotlar: {allow}")
        else:
            print(f"{Fore.YELLOW}[*] OPTIONS başlığı döndürmedi, metotlar tek tek test ediliyor...")
        dangerous = ["PUT", "DELETE", "TRACE", "PATCH", "CONNECT"]
        for method in dangerous:
            try:
                r = requests.request(method, url, timeout=5, headers=HEADERS)
                if r.status_code not in (405, 501):
                    print(f"{Fore.YELLOW}[!] {method:<7} KABUL EDİLDİ (Kod: {r.status_code}) — potansiyel risk!")
                else:
                    print(f"{Fore.GREEN}[+] {method:<7} engelli (Kod: {r.status_code})")
            except requests.exceptions.RequestException:
                print(f"{Fore.RED}[-] {method:<7} test edilemedi")
    except requests.exceptions.RequestException as e:
        print(f"{Fore.RED}[!] Hata: {e}")

# ==================== MODÜL 15: SPF/DKIM/DMARC ====================

def tool_15():
    print(f"\n{Fore.GREEN}=== [15] E-POSTA GÜVENLİK ANALİZİ (SPF/DKIM/DMARC) ===")
    domain = get_domain(input(f"{Fore.CYAN}Hedef Domain: {Style.RESET_ALL}").strip())
    if not domain: return

    def txt_query(name):
        try:
            res = requests.get(
                "https://cloudflare-dns.com/dns-query",
                params={"name": name, "type": "TXT"},
                headers={"Accept": "application/dns-json"},
                timeout=5,
            )
            answers = res.json().get("Answer", [])
            return [a["data"] for a in answers]
        except Exception:
            return []

    # SPF
    spf = txt_query(domain)
    spf_rec = [r for r in spf if r.startswith('"v=spf1') or 'v=spf1' in r]
    if spf_rec:
        print(f"{Fore.GREEN}[+] SPF Kaydı       : {spf_rec[0].strip('\"')}")
        if '~all' in spf_rec[0] or '-all' in spf_rec[0]:
            print(f"{Fore.GREEN}    [-] Sıkı policy aktif (good).")
        elif '?all' in spf_rec[0]:
            print(f"{Fore.YELLOW}    [!] Zayıf policy (?all) — spoofing riski!")
    else:
        print(f"{Fore.RED}[-] SPF kaydı YOK — e-posta spoofing riski yüksek!")

    # DMARC
    dmarc = txt_query(f"_dmarc.{domain}")
    if dmarc:
        print(f"{Fore.GREEN}[+] DMARC Kaydı     : {dmarc[0].strip('\"')}")
    else:
        print(f"{Fore.YELLOW}[!] DMARC kaydı YOK.")

    # DKIM (yaygın selectorlar)
    print(f"{Fore.CYAN}[*] DKIM selectorları test ediliyor (default, google, mail, k1)...")
    dkim_found = False
    for sel in ["default", "google", "mail", "k1", "selector1", "s1"]:
        dkim = txt_query(f"{sel}._domainkey.{domain}")
        if dkim:
            print(f"{Fore.GREEN}[+] DKIM bulundu (selector: {sel})")
            dkim_found = True
    if not dkim_found:
        print(f"{Fore.YELLOW}[!] Yaygın selectorlarda DKIM bulunamadı (varsa özel selector kullanılıyor).")

# ==================== ANA PROGRAM ====================

TOOLS = {
    "1": tool_1, "2": tool_2, "3": tool_3, "4": tool_4, "5": tool_5,
    "6": tool_6, "7": tool_7, "8": tool_8, "9": tool_9, "10": tool_10,
    "11": tool_11, "12": tool_12, "13": tool_13, "14": tool_14, "15": tool_15,
}

def main():
    while True:
        show_banner()
        show_menu()
        secim = input(f"{Fore.CYAN}MarkOs > Seçiminiz: {Style.RESET_ALL}").strip()

        if secim == "0":
            print(f"\n{Fore.RED}[!] Kapatılıyor. MarkOs X Zanox v2.0 — 15 Araçlık Motor Sonlandırıldı!")
            sys.exit(0)
        elif secim in TOOLS:
            TOOLS[secim]()
            pause()
        else:
            print(f"\n{Fore.RED}[!] Geçersiz seçim kankam!")
            time.sleep(1)

if __name__ == "__main__":
    main()
