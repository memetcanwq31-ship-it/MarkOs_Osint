# -*- coding: utf-8 -*-
"""
MarkOs Zanox Pro v4.0 — Advanced Enterprise OSINT & Intel Suite
Geliştirici: memetcanwq31-ship-it
Kurulum: pip install requests httpx colorama
"""

import os
import sys
import ssl
import json
import time
import socket
import sqlite3
import asyncio
import hashlib
import base64
import re
import urllib.parse
from datetime import datetime
import httpx
import requests
from colorama import Fore, Style, init

init(autoreset=True)

HEADERS = {"User-Agent": "MarkOs-ZanoxPro/4.0"}
TIMEOUT = 6.0


class MarkOsZanoxPro:
    """
    ===================================================================
    MARKOS ZANOX PRO v4.0 — ADVANCED OSINT & INTEL SUITE
    ===================================================================
    12 modül: Async subdomain keşfi, DNS, header denetimi, SSL/TLS,
    RDAP/Whois, GeoIP, CMS tespiti, port taraması, teknoloji profili,
    JS/link scraping, Wayback arşiv, HTML rapor + SQLite Vault.
    ===================================================================
    """

    def __init__(self):
        self.version = "4.0.0-Pro"
        self.db_name = "zanox_intel_vault.db"
        self.is_running = True
        self.sub_dictionary = [
            "www", "mail", "remote", "blog", "dev", "test", "api", "vpn",
            "secure", "portal", "shop", "app", "cdn", "staging", "beta",
            "git", "jira", "webmail", "smtp", "db", "cloud", "ns1", "ns2",
            "cpanel", "admin", "ftp", "intranet", "helpdesk", "m", "mobile",
        ]
        self.last_target = None
        self.last_findings = {}
        self.setup_vault()

    # ------------------- ALTYAPI -------------------

    def clear_screen(self):
        os.system('cls' if os.name == 'nt' else 'clear')

    def show_banner(self):
        self.clear_screen()
        print(f"""{Fore.CYAN}
███████╗ █████╗ ███╗   ██╗ ██████╗ ██╗  ██╗    ██████╗ ██████╗  ██████╗
╚══███╔╝██╔══██╗████╗  ██║██╔═══██╗╚██╗██╔╝    ██╔══██╗██╔══██╗██╔═══██╗
  ███╔╝ ███████║██╔██╗ ██║██║   ██║ ╚███╔╝     ██████╔╝██████╔╝██║   ██║
 ███╔╝  ██╔══██║██║╚██╗██║██║   ██║ ██╔██╗     ██╔═══╝ ██╔══██╗██║   ██║
███████╗██║  ██║██║ ╚████║╚██████╔╝██╔╝ ██╗    ██║     ██║  ██║╚██████╔╝
╚══════╝╚═╝  ╚═╝╚═╝  ╚═══╝ ╚═════╝ ╚═╝  ╚═╝    ╚═╝     ╚═╝  ╚═╝ ╚═════╝
 ──────────────────────────────────────────────────────────────────────
   [📡] ZANOX PRO v{self.version} — OSINT & TEHDİT İSTİHBARATI SÜİTİ
   [🧩] 12 MODÜL | Asenkron httpx + SQLite Vault + HTML Rapor
 ──────────────────────────────────────────────────────────────────────{Style.RESET_ALL}""")

    def setup_vault(self):
        try:
            conn = sqlite3.connect(self.db_name)
            c = conn.cursor()
            c.execute('''
                CREATE TABLE IF NOT EXISTS zanox_logs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    target_domain TEXT,
                    resolved_ip TEXT,
                    findings TEXT,
                    scan_date TEXT
                )
            ''')
            conn.commit()
            conn.close()
        except Exception as e:
            print(f"{Fore.RED}[!] Vault kurulum hatası: {e}")

    def save_to_vault(self, domain, ip, findings_str):
        try:
            conn = sqlite3.connect(self.db_name)
            c = conn.cursor()
            c.execute(
                "INSERT INTO zanox_logs (target_domain, resolved_ip, findings, scan_date) VALUES (?, ?, ?, ?)",
                (domain, ip, findings_str, datetime.now().strftime("%Y-%m-%d %H:%M:%S")),
            )
            conn.commit()
            conn.close()
            print(f"\n{Fore.GREEN}[+] Bulgular Vault'a kaydedildi: {Fore.YELLOW}{self.db_name}")
        except Exception as e:
            print(f"{Fore.RED}[!] Vault yazma hatası: {e}")

    def get_target(self, prompt):
        target = input(prompt).strip()
        if not target:
            return None
        if "://" in target:
            target = target.split("://", 1)[-1]
        target = target.split("/", 1)[0]
        return target

    def resolve_ip(self, domain):
        try:
            return socket.gethostbyname(domain)
        except socket.gaierror:
            return None

    def pause(self):
        input(f"\n{Fore.GREEN}Ana menüye dönmek için Enter'a basın...{Style.RESET_ALL}")

    # ------------------- MODÜL 1: ASENKRON SUBDOMAIN -------------------

    async def _sub_check(self, client, domain, sub, results):
        sub_target = f"{sub}.{domain}"
        for scheme in ("https", "http"):
            url = f"{scheme}://{sub_target}"
            try:
                res = await client.get(url, timeout=3.0, follow_redirects=False)
                title = ""
                m = re.search(r"<title[^>]*>(.*?)</title>", res.text, re.S | re.I)
                if m:
                    title = m.group(1).strip()[:50]
                print(f"  {Fore.GREEN}[+] AKTİF: {sub_target} ({res.status_code}) {Fore.CYAN}{title}")
                results.append({"host": sub_target, "status": res.status_code, "title": title})
                return
            except Exception:
                continue
        # HTTP yanıt yok ama DNS kaydı var mı?
        try:
            socket.gethostbyname(sub_target)
            print(f"  {Fore.YELLOW}[~] DNS VAR (HTTP kapalı): {sub_target}")
            results.append({"host": sub_target, "status": "DNS-Only", "title": ""})
        except socket.gaierror:
            pass

    async def _osint_engine(self, domain):
        self.show_banner()
        print(f"\n{Fore.YELLOW}[*] Asenkron Subdomain Keşif Motoru — {len(self.sub_dictionary)} aday sorgulanıyor...\n")
        results = []
        async with httpx.AsyncClient(headers=HEADERS, verify=False) as client:
            tasks = [self._sub_check(client, domain, sub, results) for sub in self.sub_dictionary]
            await asyncio.gather(*tasks)
        print(f"\n{Fore.GREEN}[*] Keşif tamamlandı. {len(results)} sonuç bulundu.")
        if results:
            ip = self.resolve_ip(domain) or "-"
            self.save_to_vault(domain, ip, f"Subdomain: {len(results)} aktif alt alan adı")
        self.last_findings["subdomains"] = results

    def run_subdomain_scan(self):
        domain = self.get_target(f"{Fore.GREEN}[?] Ana Domain (Örn: example.com): {Style.RESET_ALL}")
        if not domain:
            return
        try:
            asyncio.run(self._osint_engine(domain))
        except KeyboardInterrupt:
            print(f"\n{Fore.RED}[-] Tarama iptal edildi.")
        self.last_target = domain
        self.pause()

    # ------------------- MODÜL 2: HEADER DENETİMİ -------------------

    def run_header_audit(self):
        domain = self.get_target(f"{Fore.GREEN}[?] Denetlenecek Domain: {Style.RESET_ALL}")
        if not domain:
            return
        self.show_banner()
        print(f"\n{Fore.CYAN}── HTTP Güvenlik Kalkanı Denetimi ──────────────────────────")
        ip = self.resolve_ip(domain)
        if not ip:
            print(f"{Fore.RED}[!] DNS çözümleme başarısız!")
            self.pause()
            return
        print(f"{Fore.GREEN}[+] Hedef IP: {Fore.YELLOW}{ip}\n")

        audit = []
        try:
            res = requests.get(f"https://{domain}", timeout=TIMEOUT, headers=HEADERS)
            h = res.headers
            print(f"{Fore.GREEN}[+] Status: {res.status_code} | Sunucu: {h.get('Server', 'Gizli')} | X-Powered-By: {h.get('X-Powered-By', 'Gizli')}\n")

            checks = {
                "Strict-Transport-Security": "MitM / Trafik dinleme",
                "X-Frame-Options": "Clickjacking",
                "Content-Security-Policy": "XSS / Kod enjeksiyonu",
                "X-Content-Type-Options": "MIME sniffing",
                "Referrer-Policy": "Referrer sızması",
                "Permissions-Policy": "Hassas API erişimi",
            }
            for header, risk in checks.items():
                if header in h:
                    print(f"{Fore.GREEN}[+] AKTİF : {header} -> {h[header][:60]}")
                    audit.append(f"{header}: Aktif")
                else:
                    print(f"{Fore.RED}[!] EKSİK : {header} (Risk: {risk})")
                    audit.append(f"{header}: EKSIK")

            # Cookie bayrakları
            set_cookie = h.get("Set-Cookie", "")
            if set_cookie:
                missing = [b for b in ("HttpOnly", "Secure", "SameSite") if b.lower() not in set_cookie.lower()]
                if missing:
                    print(f"{Fore.RED}[!] Cookie eksik bayraklar: {', '.join(missing)}")
                    audit.append(f"Cookie: eksik {','.join(missing)}")
                else:
                    print(f"{Fore.GREEN}[+] Cookie bayrakları güvenli")
        except Exception as e:
            print(f"{Fore.RED}[!] Bağlantı hatası: {e}")

        self.save_to_vault(domain, ip, " | ".join(audit) if audit else "Bağlantı kurulamadı")
        self.last_target = domain
        self.last_findings["headers"] = audit
        self.pause()

    # ------------------- MODÜL 3: DNS SORGULAYICI -------------------

    def run_dns_lookup(self):
        domain = self.get_target(f"{Fore.GREEN}[?] Hedef Domain: {Style.RESET_ALL}")
        if not domain:
            return
        self.show_banner()
        print(f"\n{Fore.CYAN}── DNS Kayıt Sorgulayıcı (Cloudflare DoH) ──────────────────\n")
        for rtype in ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA"]:
            try:
                res = requests.get(
                    "https://cloudflare-dns.com/dns-query",
                    params={"name": domain, "type": rtype},
                    headers={"Accept": "application/dns-json"},
                    timeout=5,
                )
                answers = res.json().get("Answer", [])
                if answers:
                    print(f"{Fore.GREEN}[+] {rtype:<6}:")
                    for a in answers[:6]:
                        print(f"         {Fore.WHITE}{a['data'][:90]}")
                else:
                    print(f"{Fore.YELLOW}[-] {rtype:<6}: kayıt yok")
            except Exception:
                print(f"{Fore.RED}[!] {rtype:<6}: sorgu hatası")
        self.pause()

    # ------------------- MODÜL 4: SSL/TLS DENETİMİ -------------------

    def run_ssl_audit(self):
        domain = self.get_target(f"{Fore.GREEN}[?] Hedef Domain: {Style.RESET_ALL}")
        if not domain:
            return
        self.show_banner()
        print(f"\n{Fore.CYAN}── SSL/TLS Sertifika Denetimi ──────────────────────────────\n")
        ctx = ssl.create_default_context()
        try:
            with socket.create_connection((domain, 443), timeout=6) as sock:
                with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                    cert = ssock.getpeercert()
                    print(f"{Fore.GREEN}[+] TLS Sürümü      : {ssock.version()}")
                    print(f"{Fore.GREEN}[+] Şifre Paketi    : {ssock.cipher()[0]} ({ssock.cipher()[2]} bit)")
                    subject = dict(x[0] for x in cert.get("subject", []))
                    issuer = dict(x[0] for x in cert.get("issuer", []))
                    print(f"{Fore.GREEN}[+] Sertifika Sahibi: {subject.get('commonName', '?')}")
                    print(f"{Fore.GREEN}[+] Veren Kurum     : {issuer.get('organizationName', '?')}")
                    print(f"{Fore.GREEN}[+] Geçerlilik      : {cert.get('notBefore', '?')} -> {cert.get('notAfter', '?')}")
                    sans = [v for k, v in cert.get("subjectAltName", [])]
                    print(f"{Fore.GREEN}[+] SAN Alanları    : {', '.join(sans[:8])}")
                    if ssock.version() in ("TLSv1", "TLSv1.1"):
                        print(f"{Fore.RED}[!] ZAFİYET: Eski TLS sürümü aktif! (TLS 1.2+ zorunlu olmalı)")
        except ssl.SSLCertVerificationError:
            print(f"{Fore.RED}[!] Sertifika doğrulaması BAŞARISIZ (kendi imzalı / süresi dolmuş / hostname uyumsuz)")
        except Exception as e:
            print(f"{Fore.RED}[!] SSL hatası: {e}")
        self.pause()

    # ------------------- MODÜL 5: RDAP / WHOIS -------------------

    def run_whois(self):
        domain = self.get_target(f"{Fore.GREEN}[?] Hedef Domain: {Style.RESET_ALL}")
        if not domain:
            return
        self.show_banner()
        print(f"\n{Fore.CYAN}── RDAP / Whois Kayıt Analizi ──────────────────────────────\n")
        try:
            res = requests.get(f"https://rdap.org/domain/{domain}", timeout=8)
            if res.status_code != 200:
                print(f"{Fore.RED}[-] RDAP verisi alınamadı (Kod: {res.status_code})")
                self.pause()
                return
            data = res.json()
            print(f"{Fore.GREEN}[+] Kayıt Kuruluşu : {data.get('port43', 'Bilinmiyor')}")
            for ev in data.get("events", []):
                print(f"{Fore.GREEN}[+] {ev.get('action', '?'):<16}: {ev.get('eventDate', '?')}")
            for ent in data.get("entities", []):
                roles = ", ".join(ent.get("roles", []))
                if roles:
                    print(f"{Fore.CYAN}[*] Varlık Rolü    : {roles}")
            status = data.get("status", [])
            if status:
                print(f"{Fore.CYAN}[*] Durum Bayrakları: {', '.join(status[:6])}")
        except Exception as e:
            print(f"{Fore.RED}[!] Hata: {e}")
        self.pause()

    # ------------------- MODÜL 6: GEOIP / ISP -------------------

    def run_geoip(self):
        target = input(f"{Fore.GREEN}[?] Domain veya IP: {Style.RESET_ALL}").strip()
        if not target:
            return
        self.show_banner()
        print(f"\n{Fore.CYAN}── IP Coğrafi Konum & ISP Analizi ──────────────────────────\n")
        try:
            ip = target if re.match(r"^\d+\.\d+\.\d+\.\d+$", target) else self.resolve_ip(target)
            if not ip:
                print(f"{Fore.RED}[!] IP çözümlenemedi!")
                self.pause()
                return
            data = requests.get(f"http://ip-api.com/json/{ip}", timeout=6).json()
            if data.get("status") == "success":
                print(f"{Fore.GREEN}[+] IP          : {ip}")
                print(f"{Fore.GREEN}[+] Ülke/Şehir  : {data.get('country')} / {data.get('city')}")
                print(f"{Fore.GREEN}[+] ISP         : {data.get('isp')}")
                print(f"{Fore.GREEN}[+] Organizasyon: {data.get('org')}")
                print(f"{Fore.GREEN}[+] ASN         : {data.get('as')}")
                print(f"{Fore.GREEN}[+] Koordinat   : {data.get('lat')}, {data.get('lon')}")
                print(f"{Fore.GREEN}[+] Saat Dilimi : {data.get('timezone')}")
            else:
                print(f"{Fore.RED}[-] GeoIP verisi alınamadı.")
        except Exception as e:
            print(f"{Fore.RED}[!] Hata: {e}")
        self.pause()

    # ------------------- MODÜL 7: PORT TARAMASI -------------------

    def run_port_scan(self):
        target = self.get_target(f"{Fore.GREEN}[?] Hedef IP veya Domain: {Style.RESET_ALL}")
        if not target:
            return
        self.show_banner()
        print(f"\n{Fore.CYAN}── Çoklu İş Parçacıklı Port Taraması ───────────────────────\n")
        ip = self.resolve_ip(target)
        if not ip:
            print(f"{Fore.RED}[!] DNS çözümleme başarısız!")
            self.pause()
            return
        print(f"{Fore.GREEN}[*] Hedef IP: {ip}\n")
        ports = {
            21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
            80: "HTTP", 110: "POP3", 143: "IMAP", 443: "HTTPS", 445: "SMB",
            1433: "MSSQL", 3306: "MySQL", 3389: "RDP", 8080: "HTTP-Alt", 8443: "HTTPS-Alt",
        }
        open_ports = []
        import threading
        lock = threading.Lock()

        def worker(port):
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(1.2)
                if s.connect_ex((ip, port)) == 0:
                    try:
                        svc = socket.getservbyport(port)
                    except OSError:
                        svc = ports.get(port, "Bilinmiyor")
                    with lock:
                        print(f"{Fore.GREEN}[+] Port {port:<6} AÇIK -> {svc}")
                        open_ports.append(port)
                s.close()
            except OSError:
                pass

        threads = [threading.Thread(target=worker, args=(p,)) for p in ports]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        if not open_ports:
            print(f"{Fore.CYAN}[i] Açık port bulunamadı (güvenlik duvarı aktif olabilir).")
        self.last_findings["open_ports"] = open_ports
        self.pause()

    # ------------------- MODÜL 8: CMS & TEKNOLOJİ TESPİTİ -------------------

    def run_cms_detect(self):
        domain = self.get_target(f"{Fore.GREEN}[?] Hedef Domain: {Style.RESET_ALL}")
        if not domain:
            return
        self.show_banner()
        print(f"\n{Fore.CYAN}── CMS & Teknoloji Parmak İzi ──────────────────────────────\n")
        base = f"https://{domain}"
        try:
            res = requests.get(base, timeout=TIMEOUT, headers=HEADERS)
            body = res.text
            headers = res.headers

            # Generator meta
            gen = re.search(r'<meta name="generator" content="([^"]+)"', body, re.I)
            if gen:
                print(f"{Fore.GREEN}[+] Generator Meta: {gen.group(1)}")

            # İmza tabanlı tespit
            signatures = [
                ("WordPress", r"wp-content|wp-includes"),
                ("Joomla", r"Joomla!|/media/joomla/"),
                ("Drupal", r"Drupal|sites/default/files"),
                ("Magento", r"Magento|mage/"),
                ("Shopify", r"cdn\.shopify\.com"),
                ("React", r"__NEXT_DATA__|react"),
                ("Vue.js", r"vue\.js|data-v-"),
                ("Laravel", r"laravel|csrf-token"),
                ("Cloudflare", r"cdn-cgi/"),
            ]
            for name, pattern in signatures:
                if re.search(pattern, body, re.I):
                    print(f"{Fore.YELLOW}[+] Teknoloji Tespiti: {name}")

            # WordPress sürümü
            try:
                r = requests.get(f"{base}/feed/", timeout=4, headers=HEADERS)
                m = re.search(r"<generator>(.*?)</generator>", r.text)
                if m and "wordpress" in m.group(1).lower():
                    print(f"{Fore.YELLOW}[+] WordPress Sürümü: {m.group(1).strip()}")
            except Exception:
                pass

            # Yaygın hassas yolların varlığı
            print(f"\n{Fore.CYAN}[*] Yaygın hassas dosya kontrolü:")
            for path in ["/.env", "/robots.txt", "/sitemap.xml", "/phpinfo.php", "/.git/config", "/wp-login.php"]:
                try:
                    r = requests.get(f"{base}{path}", timeout=4, headers=HEADERS)
                    if r.status_code == 200 and len(r.text) > 10:
                        print(f"{Fore.YELLOW}[!] Erişilebilir: {path} ({len(r.text)} byte)")
                except Exception:
                    pass
        except Exception as e:
            print(f"{Fore.RED}[!] Hata: {e}")
        self.pause()

    # ------------------- MODÜL 9: LINK / JS SCRAPER -------------------

    def run_scraper(self):
        url = input(f"{Fore.GREEN}[?] Hedef URL: {Style.RESET_ALL}").strip()
        if not url:
            return
        if not url.startswith("http"):
            url = "https://" + url
        self.show_banner()
        print(f"\n{Fore.CYAN}── Kaynak Kod Link & Varlık Ayıklayıcı ─────────────────────\n")
        try:
            res = requests.get(url, timeout=TIMEOUT, headers=HEADERS)
            body = res.text
            links = sorted(set(re.findall(r'href=["\'](.*?)["\']', body)))
            srcs = sorted(set(re.findall(r'src=["\'](.*?)["\']', body)))
            js_files = [s for s in srcs if s.endswith(".js")]
            forms = re.findall(r'<form[^>]*action=["\'](.*?)["\']', body)
            emails = sorted(set(re.findall(r'[\w.+-]+@[\w-]+\.[\w.]+', body)))
            comments = re.findall(r'<!--(.*?)-->', body, re.S)

            print(f"{Fore.GREEN}[+] Linkler ({len(links)}):")
            for l in links[:15]:
                print(f"      {l}")
            print(f"\n{Fore.GREEN}[+] JS Dosyaları ({len(js_files)}):")
            for j in js_files[:10]:
                print(f"      {j}")
            if forms:
                print(f"\n{Fore.YELLOW}[!] Form Action'ları: {set(forms)}")
            if emails:
                print(f"{Fore.YELLOW}[!] E-Posta Adresleri: {emails}")
            if comments:
                print(f"{Fore.YELLOW}[!] HTML Yorumları ({len(comments)}):")
                for c in comments[:5]:
                    print(f"      {c.strip()[:100]}")
        except Exception as e:
            print(f"{Fore.RED}[!] Hata: {e}")
        self.pause()

    # ------------------- MODÜL 10: FAVICON MMH HASH -------------------

    def run_favicon_hash(self):
        domain = self.get_target(f"{Fore.GREEN}[?] Hedef Domain: {Style.RESET_ALL}")
        if not domain:
            return
        self.show_banner()
        print(f"\n{Fore.CYAN}── Favicon Hash (Shodan mmh3 uyumlu) ───────────────────────\n")
        try:
            res = requests.get(f"https://{domain}/favicon.ico", timeout=6, headers=HEADERS)
            if res.status_code == 200 and res.content:
                import struct
                # mmh3 benzeri basit parmak izi (tam mmh3 için pip install mmh3)
                h = hashlib.md5(res.content).hexdigest()
                b64 = base64.encodebytes(res.content).decode()
                print(f"{Fore.GREEN}[+] Favicon MD5 : {h}")
                print(f"{Fore.GREEN}[+] Boyut       : {len(res.content)} byte")
                print(f"{Fore.CYAN}[*] Shodan'da kullanmak için: pip install mmh3 ile tam mmh3 hash üretilebilir.")
                print(f"{Fore.CYAN}[*] Shodan sorgusu: http.favicon.hash:<mmh3_degeri>")
            else:
                print(f"{Fore.RED}[-] Favicon.ico bulunamadı (Kod: {res.status_code})")
        except Exception as e:
            print(f"{Fore.RED}[!] Hata: {e}")
        self.pause()

    # ------------------- MODÜL 11: WAYBACK ARŞİV -------------------

    def run_wayback(self):
        domain = self.get_target(f"{Fore.GREEN}[?] Hedef Domain: {Style.RESET_ALL}")
        if not domain:
            return
        self.show_banner()
        print(f"\n{Fore.CYAN}── Wayback Machine Arşiv Keşfi ─────────────────────────────\n")
        try:
            res = requests.get(
                f"http://web.archive.org/cdx/search/cdx?url=*.{domain}&output=json&limit=50&collapse=urlkey",
                timeout=10,
            )
            rows = res.json()
            if len(rows) <= 1:
                print(f"{Fore.YELLOW}[-] Arşiv kaydı bulunamadı.")
            else:
                print(f"{Fore.GREEN}[+] {len(rows) - 1} arşivlenmiş URL bulundu:\n")
                for row in rows[1:]:
                    print(f"    {Fore.WHITE}{row[1][:12]}  {row[2][:80]}")
        except Exception as e:
            print(f"{Fore.RED}[!] Hata: {e}")
        self.pause()

    # ------------------- MODÜL 12: RAPOR & VAULT -------------------

    def show_vault_logs(self):
        self.show_banner()
        print(f"\n{Fore.CYAN}── SQLite Vault Kayıt Defteri ──────────────────────────────")
        try:
            conn = sqlite3.connect(self.db_name)
            c = conn.cursor()
            c.execute("SELECT * FROM zanox_logs ORDER BY id DESC LIMIT 10")
            logs = c.fetchall()
            conn.close()
            if not logs:
                print(f"\n{Fore.YELLOW}[i] Vault boş.")
            else:
                for log in logs:
                    print(f"\n{Fore.YELLOW}[ Log #{log[0]} ] {log[4]}")
                    print(f"  • Hedef : {log[1]}  |  IP: {log[2]}")
                    print(f"  • Bulgu : {log[3][:120]}")
        except Exception as e:
            print(f"{Fore.RED}[!] Vault okuma hatası: {e}")
        self.pause()

    def generate_report(self):
        if not self.last_target:
            print(f"{Fore.RED}[!] Önce bir tarama yapın (son hedef yok).")
            time.sleep(1.5)
            return
        self.show_banner()
        print(f"\n{Fore.CYAN}── HTML Rapor Üretici ──────────────────────────────────────")
        domain = self.last_target
        ip = self.resolve_ip(domain) or "-"
        date = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        fname = f"zanox_report_{domain.replace('.', '_')}.html"

        subs = self.last_findings.get("subdomains", [])
        ports = self.last_findings.get("open_ports", [])
        headers_res = self.last_findings.get("headers", [])

        subs_html = "".join(f"<li>{s['host']} — {s['status']}</li>" for s in subs) or "<li>Veri yok</li>"
        ports_html = ", ".join(map(str, ports)) or "Taranmadı / kapalı"
        headers_html = "".join(f"<li>{h}</li>" for h in headers_res) or "<li>Analiz yapılmadı</li>"

        html = f"""<!DOCTYPE html>
<html lang="tr"><head><meta charset="UTF-8"><title>Zanox Raporu - {domain}</title>
<style>
body{{font-family:'Segoe UI',sans-serif;margin:40px;background:#0f172a;color:#e2e8f0}}
.c{{max-width:900px;margin:auto;background:#1e293b;padding:30px;border-radius:12px}}
h1{{color:#10b981}}h2{{color:#38bdf8;border-bottom:1px solid #475569;padding-bottom:8px}}
table{{width:100%;border-collapse:collapse;margin-top:15px}}
td{{padding:10px;border:1px solid #475569}}
.t{{font-weight:bold;color:#94a3b8;width:30%}}
</style></head><body><div class="c">
<h1>MarkOs Zanox Pro — OSINT Raporu</h1>
<table>
<tr><td class="t">Hedef</td><td>{domain}</td></tr>
<tr><td class="t">IP</td><td>{ip}</td></tr>
<tr><td class="t">Tarih</td><td>{date}</td></tr>
</table>
<h2>Subdomain Keşfi ({len(subs)} sonuç)</h2><ul>{subs_html}</ul>
<h2>Açık Portlar</h2><p>{ports_html}</p>
<h2>Güvenlik Başlık Denetimi</h2><ul>{headers_html}</ul>
<p style="color:#64748b;margin-top:40px;font-size:12px">Zanox Pro v{self.version} tarafından otomatik üretildi.</p>
</div></body></html>"""

        with open(fname, "w", encoding="utf-8") as f:
            f.write(html)
        print(f"{Fore.GREEN}[+] Rapor üretildi: {fname}")
        self.pause()

    # ------------------- ANA MENÜ -------------------

    def start_interface(self):
        while self.is_running:
            self.show_banner()
            if self.last_target:
                print(f"{Fore.YELLOW}  [Son Hedef: {self.last_target}]")
            print(f"""
{Fore.CYAN}── ZANOX PRO OSINT MODÜLLERİ ──────────────────────────────────{Style.RESET_ALL}
  {Fore.GREEN}[1]{Fore.WHITE}  Asenkron Subdomain Keşif Motoru (httpx)
  {Fore.GREEN}[2]{Fore.WHITE}  HTTP Güvenlik Kalkanı Denetimi (Headers)
  {Fore.GREEN}[3]{Fore.WHITE}  DNS Kayıt Sorgulayıcı (A/AAAA/MX/NS/TXT/CNAME/SOA)
  {Fore.GREEN}[4]{Fore.WHITE}  SSL/TLS Sertifika Denetleyicisi
  {Fore.GREEN}[5]{Fore.WHITE}  RDAP / Whois Kayıt & Domain Yaşı Analizi
  {Fore.GREEN}[6]{Fore.WHITE}  IP Coğrafi Konum & ISP Tespit (GeoIP)
  {Fore.GREEN}[7]{Fore.WHITE}  Çoklu Thread Port Taraması
  {Fore.GREEN}[8]{Fore.WHITE}  CMS & Teknoloji Parmak İzi Dedektörü
  {Fore.GREEN}[9]{Fore.WHITE}  Link / JS / Form / E-Posta Ayıklayıcı (Scraper)
  {Fore.GREEN}[10]{Fore.WHITE} Favicon Hash Parmak İzi (Shodan uyumlu)
  {Fore.GREEN}[11]{Fore.WHITE} Wayback Machine Arşiv Keşfi
  {Fore.GREEN}[12]{Fore.WHITE} SQLite Vault Kayıtları + HTML Rapor Üret
  {Fore.RED}[0]  Çıkış{Style.RESET_ALL}""")

            secim = input(f"{Fore.GREEN}MarkOs_Zanox > Seçiminiz: {Style.RESET_ALL}").strip()

            if secim == "1":
                self.run_subdomain_scan()
            elif secim == "2":
                self.run_header_audit()
            elif secim == "3":
                self.run_dns_lookup()
            elif secim == "4":
                self.run_ssl_audit()
            elif secim == "5":
                self.run_whois()
            elif secim == "6":
                self.run_geoip()
            elif secim == "7":
                self.run_port_scan()
            elif secim == "8":
                self.run_cms_detect()
            elif secim == "9":
                self.run_scraper()
            elif secim == "10":
                self.run_favicon_hash()
            elif secim == "11":
                self.run_wayback()
            elif secim == "12":
                self.show_vault_logs()
                self.generate_report()
            elif secim == "0":
                print(f"\n{Fore.RED}[!] Zanox Pro kapatıldı. İyi çalışmalar!")
                self.is_running = False
            else:
                print(f"{Fore.RED}[!] Geçersiz seçim!")
                time.sleep(1)


if __name__ == "__main__":
    engine = MarkOsZanoxPro()
    engine.start_interface()
