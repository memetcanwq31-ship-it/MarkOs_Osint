#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
=============================================================================
        MarkOs Tehdit İstihbaratı & Zafiyet Analiz Platformu v2.3
                web_zafiyetTaramaXnative_v2.3.py
=============================================================================
Geliştirici: Mehmet Kayar (memetcanwq31-ship-it)
Kurulum    : pip install httpx colorama
Kullanım   : python3 web_zafiyetTaramaXnative_v2.3.py
=============================================================================
"""

import os
import sys
import socket
import re
import time
import json
import shutil
import asyncio
import platform
import warnings
from datetime import datetime
from urllib.parse import urlparse, urljoin

try:
    import httpx
except ImportError:
    print("[!] httpx eksik. Kurulum: pip install httpx")
    sys.exit(1)

try:
    from colorama import Fore, Style, init
except ImportError:
    print("[!] colorama eksik. Kurulum: pip install colorama")
    sys.exit(1)

warnings.filterwarnings("ignore")
init(autoreset=True)

BANNER = r"""
=============================================================================
   ____                                   _ _         _                
  |  _ \ ___  ___ _ __   ___  _ __ ___  __| (_)___  __| | _____      __
  | |_) / _ \/ __| '_ \ / _ \| '__/ _ \/ _` | / __|/ _` |/ _ \ \ /\ / /
  |  _ <  __/\__ \ | | | (_) | | |  __/ (_| | \__ \ (_| | (_) \ V  V / 
  |_| \_\___||___/_| |_|\___/|_|  \___|\__,_|_|___/\__,_|\___/ \_/\_/  
                W E B   A N A L I Z Y E R   v 2 . 3
      MarkOs Tehdit Istihbarati & Zafiyet Analiz Platformu
=============================================================================
"""


def draw_line(color=Fore.CYAN, char="="):
    try:
        columns, _ = shutil.get_terminal_size()
        print(color + char * columns)
    except Exception:
        print(color + char * 66)


def clear_screen():
    os.system("cls" if os.name == "nt" else "clear")


def ts():
    return time.strftime("%H:%M:%S")


class MarkOsProCoreScanner:
    def __init__(self, target_url, max_pages=40):
        if not target_url.startswith(("http://", "https://")):
            target_url = "http://" + target_url
        self.target_url = target_url.rstrip("/")
        self.parsed = urlparse(self.target_url)
        self.domain = self.parsed.netloc
        self.ip_address = None
        self.max_pages = max_pages

        self.visited_urls = set()
        self.urls_to_visit = {self.target_url}
        self.vulnerabilities = []
        self.discovered_forms = []
        self.discovered_api_endpoints = []
        self.discovered_subdomains = set()
        self.technologies = set()
        self.discovered_waf = "Tespit Edilemedi (Veya Bulunmuyor)"
        self.open_ports = []
        self.dead_links = []

        self.report_dir = "markos_private_reports"
        os.makedirs(self.report_dir, exist_ok=True)

    # ---------- 1. DNS + Recon ----------
    def run_raw_socket_recon(self):
        print(Fore.YELLOW + f"\n[*] [{ts()}] Ham Socket bağlantıları kuruluyor...")
        clean_domain = self.domain.split(":")[0]
        try:
            self.ip_address = socket.gethostbyname(clean_domain)
            print(Fore.GREEN + f" [+] DNS çözümleme: {clean_domain} -> [{self.ip_address}]")
            return True
        except socket.gaierror:
            print(Fore.RED + " [-] Hata: Domain IP adresine çözülemedi.")
            self.ip_address = None
            return False

    # ---------- 2. Port Tarama ----------
    def run_port_scan(self):
        if not self.ip_address:
            if not self.run_raw_socket_recon():
                return
        critical_ports = [21, 22, 23, 25, 53, 80, 110, 443, 445,
                          1433, 3306, 3389, 5432, 6379, 8080, 8443]
        print(Fore.YELLOW + f"[*] [{ts()}] {len(critical_ports)} kritik port taranıyor...")
        for port in critical_ports:
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.settimeout(0.8)
                    if s.connect_ex((self.ip_address, port)) == 0:
                        print(Fore.RED + Style.BRIGHT + f"  [!] AÇIK PORT: {port}")
                        self.open_ports.append(port)
            except OSError:
                continue
        if not self.open_ports:
            print(Fore.GREEN + "  [+] Açık port bulunamadı.")

    # ---------- 3. Subdomain Keşfi ----------
    def run_subdomain_scan(self):
        common = ["www", "mail", "ftp", "admin", "portal", "api", "dev",
                  "test", "staging", "vpn", "remote", "shop", "blog",
                  "cdn", "ns1", "ns2", "smtp", "webmail", "cpanel"]
        base = self.domain.split(":")[0]
        parts = base.split(".")
        root = ".".join(parts[-2:]) if len(parts) >= 2 else base

        print(Fore.YELLOW + f"[*] [{ts()}] Subdomain keşfi başlatıldı ({len(common)} aday)...")
        for sub in common:
            host = f"{sub}.{root}"
            try:
                socket.gethostbyname(host)
                print(Fore.GREEN + f"  [+] Bulundu: {host}")
                self.discovered_subdomains.add(host)
            except socket.gaierror:
                continue

    # ---------- 4. WAF Analizi ----------
    def detect_waf_presence(self, headers, html):
        waf_signatures = {
            "Cloudflare": ["cloudflare", "__cfduid", "cf-ray"],
            "ModSecurity": ["mod_security", "modsecurity"],
            "Sucuri": ["sucuri", "x-sucuri-id"],
            "Imperva / Incapsula": ["incapsula", "visid_incap", "incap_ses"],
            "F5 BIG-IP ASM": ["x-cnection", "bigipserver", "ts01"],
        }
        header_str = "".join(f"{k}: {v}".lower() for k, v in headers.items()).lower()
        html_lower = html.lower()
        for waf_name, sigs in waf_signatures.items():
            if any(sig in header_str or sig in html_lower for sig in sigs):
                self.discovered_waf = waf_name
                print(Fore.LIGHTMAGENTA_EX + Style.BRIGHT + f" [!] WAF tespit edildi: [{waf_name}]")
                return

    # ---------- 5. Teknoloji Tespiti ----------
    def detect_technologies(self, headers, html):
        t_map = {
            "WordPress": ["wp-content", "wp-includes"],
            "Drupal": ["drupal", "sites/default"],
            "Joomla": ["joomla", "/media/jui/"],
            "jQuery": ["jquery"],
            "Bootstrap": ["bootstrap"],
            "React": ["__next", "react"],
            "Laravel": ["laravel_session", "csrf-token"],
            "PHP": ["php", ".php"],
            "ASP.NET": ["asp.net", "aspnet", "__viewstate"],
            "Google Analytics": ["gtag", "google-analytics"],
        }
        low = html.lower()
        for tech, sigs in t_map.items():
            if any(sig in low for sig in sigs):
                self.technologies.add(tech)
        server = headers.get("server", "")
        if server:
            self.technologies.add(f"Server: {server}")

    # ---------- 6. Güvenlik Başlık Analizi ----------
    def evaluate_security_headers(self, url, headers):
        required = {
            "Strict-Transport-Security": "HSTS başlığı eksik",
            "Content-Security-Policy": "CSP başlığı eksik",
            "X-Content-Type-Options": "X-Content-Type-Options eksik (MIME sniffing riski)",
            "X-Frame-Options": "X-Frame-Options eksik (Clickjacking riski)",
            "Referrer-Policy": "Referrer-Policy eksik",
        }
        header_names = [k.lower() for k in headers.keys()]
        for header, desc in required.items():
            if header.lower() not in header_names:
                self.vulnerabilities.append({"tip": "Eksik Güvenlik Başlığı", "url": url, "detay": desc})

    # ---------- 7. Altyapı Dosyaları (robots/sitemap) ----------
    async def analyze_infrastructure_files(self, client):
        print(Fore.YELLOW + f"[*] [{ts()}] Rota ve harita dosyaları süzülüyor...")
        try:
            resp = await client.get(f"{self.target_url}/robots.txt")
            if resp.status_code == 200:
                print(Fore.GREEN + "  [+] robots.txt çözümlendi.")
                for path in re.findall(r"(?:Disallow|Allow):\s*(.*)", resp.text, re.IGNORECASE):
                    path = path.strip().split("#")[0].strip()
                    if path and path != "/" and "*" not in path:
                        self.urls_to_visit.add(urljoin(self.target_url, path))
        except Exception:
            pass
        try:
            resp = await client.get(f"{self.target_url}/sitemap.xml")
            if resp.status_code == 200:
                found = re.findall(r"<loc>(.*?)</loc>", resp.text, re.IGNORECASE)
                print(Fore.GREEN + f"  [+] sitemap.xml tarandı: {len(found)} rota.")
                for u in found:
                    u = u.strip().split("#")[0]
                    if urlparse(u).netloc == self.domain:
                        self.urls_to_visit.add(u)
        except Exception:
            pass

    # ---------- 8. Zafiyet Analizi ----------
    def evaluate_web_vulnerabilities(self, url, html, headers):
        server = headers.get("server", "")
        x_powered = headers.get("x-powered-by", "")
        if server:
            self.vulnerabilities.append({"tip": "Sunucu Bilgi İfşası", "url": url, "detay": f"Sunucu: {server}"})
        if x_powered:
            self.vulnerabilities.append({"tip": "Teknoloji Sızıntısı", "url": url, "detay": f"Altyapı: {x_powered}"})

        api_patterns = [r'["\'](/api/v[0-9]/.*?)["\']', r'["\'](/v1/.*?)["\']', r'https?://[^\s"\']+/api/[^\s"\']+']
        for pattern in api_patterns:
            for api in re.findall(pattern, html, re.IGNORECASE):
                full_api = urljoin(url, api) if api.startswith("/") else api
                if full_api not in self.discovered_api_endpoints and self.domain in full_api:
                    self.discovered_api_endpoints.append(full_api)
                    print(Fore.LIGHTCYAN_EX + f"  [~] API ucu: {full_api}")

        for comment in re.findall(r"<!--.*?-->", html, re.DOTALL):
            if any(k in comment.lower() for k in ["admin", "password", "key", "config", "test", "sql", "token"]):
                self.vulnerabilities.append({"tip": "Şüpheli Kaynak Kod Yorumu", "url": url, "detay": comment.strip()[:100]})

        sql_errors = ["sql syntax", "mysql_fetch", "ora-", "postgresql", "microsoft ole db", "unclosed quotation"]
        if any(err in html.lower() for err in sql_errors):
            self.vulnerabilities.append({"tip": "Potansiyel SQL Hata Yapısı", "url": url, "detay": "SQL hata izi bulundu!"})

        self.evaluate_security_headers(url, headers)

    # ---------- 9. Form Analizi ----------
    def evaluate_forms(self, url, html):
        for form in re.findall(r"<form\b.*?>", html, re.IGNORECASE | re.DOTALL):
            is_post = bool(re.search(r'method\s*=\s*["\']post["\']', form, re.IGNORECASE))
            action = re.search(r'action\s*=\s*["\'](.*?)["\']', form, re.IGNORECASE)
            action_url = action.group(1) if action else "Mevcut URL"
            form_data = f"Kaynak: {url} -> Hedef: {action_url} | Yöntem: {'POST' if is_post else 'GET'}"
            if form_data not in self.discovered_forms:
                self.discovered_forms.append(form_data)
                print(Fore.LIGHTYELLOW_EX + f"  [~] Form: {form_data}")
            if url.startswith("http://") and is_post:
                self.vulnerabilities.append({"tip": "Güvensiz Form İletimi", "url": url,
                                             "detay": f"Action: {action_url} (HTTP üzerinden POST)"})

    # ---------- 10. Asenkron Sayfa İşleme ----------
    async def process_async_page(self, client, url):
        if url in self.visited_urls:
            return
        self.visited_urls.add(url)
        try:
            resp = await client.get(url, headers={"User-Agent": "MarkOs_WebAnalizyer/2.3"}, follow_redirects=True)
            html = resp.text
            if self.discovered_waf.startswith("Tespit"):
                self.detect_waf_presence(resp.headers, html)
            self.detect_technologies(resp.headers, html)
            self.evaluate_web_vulnerabilities(url, html, resp.headers)
            self.evaluate_forms(url, html)

            for link in re.findall(r'href\s*=\s*["\'](.*?)["\']', html, re.IGNORECASE):
                full = urljoin(url, link)
                if urlparse(full).netloc == self.domain and full.startswith("http"):
                    clean = full.split("#")[0].rstrip("/")
                    if clean and clean not in self.visited_urls:
                        self.urls_to_visit.add(clean)
        except httpx.HTTPStatusError:
            self.dead_links.append(url)
        except Exception:
            pass

    # ---------- 11. Yaygın Yol Keşfi ----------
    async def discover_common_paths(self, client):
        common_paths = ["/admin", "/login", "/wp-admin", "/administrator",
                        "/dashboard", "/backup", "/.git/HEAD", "/.env",
                        "/phpmyadmin", "/config.php", "/db.sql", "/debug"]
        print(Fore.YELLOW + f"[*] [{ts()}] Yaygın hassas yollar kontrol ediliyor...")
        found = []
        for path in common_paths:
            url = urljoin(self.target_url, path)
            try:
                resp = await client.get(url)
                if resp.status_code == 200:
                    found.append((url, resp.status_code))
                    print(Fore.RED + Style.BRIGHT + f"  [!] Erişilebilir hassas yol: {url} (200)")
                    self.vulnerabilities.append({"tip": "Hassas Yol İfşası", "url": url,
                                                 "detay": f"HTTP {resp.status_code} ile erişilebilir"})
            except Exception:
                continue
        return found

    # ---------- 12. Orkestrasyon ----------
    async def coordinate_scanner(self):
        print(Fore.YELLOW + f"[*] [{ts()}] Asenkron Web Havuzu başlatıldı...")
        async with httpx.AsyncClient(timeout=6.0, verify=False, follow_redirects=True) as client:
            await self.analyze_infrastructure_files(client)
            await self.discover_common_paths(client)
            while self.urls_to_visit and len(self.visited_urls) < self.max_pages:
                batch = list(self.urls_to_visit)[:10]
                for u in batch:
                    self.urls_to_visit.discard(u)
                tasks = [self.process_async_page(client, u) for u in batch]
                await asyncio.gather(*tasks)

    # ---------- 13. Raporlama ----------
    def compile_private_report(self, mode_name="FULL RECON"):
        print("")
        draw_line(Fore.CYAN)
        print(Fore.GREEN + Style.BRIGHT + f"MARKOS WEB ANALIZYER RAPORU - [{mode_name}]")
        draw_line(Fore.CYAN)
        print(Fore.WHITE + (
            f" -> Hedef        : {self.domain}\n"
            f" -> IP Adresi    : {self.ip_address}\n"
            f" -> WAF Durumu   : {self.discovered_waf}\n"
            f" -> Harita       : {len(self.visited_urls)} sayfa\n"
            f" -> API Uçları   : {len(self.discovered_api_endpoints)} adet\n"
            f" -> Formlar      : {len(self.discovered_forms)} adet\n"
            f" -> Subdomain    : {len(self.discovered_subdomains)} adet\n"
            f" -> Teknolojiler : {', '.join(sorted(self.technologies)) or 'Tespit edilmedi'}\n"
            f" -> Zafiyetler   : {len(self.vulnerabilities)} adet"
        ))
        if self.open_ports:
            print(Fore.WHITE + f" -> Açık Portlar : {', '.join(map(str, self.open_ports))}")
        if self.dead_links:
            print(Fore.WHITE + f" -> Ölü/Bozuk Link : {len(self.dead_links)} adet")

        stamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        report_data = {
            "hedef": self.domain,
            "ip": self.ip_address,
            "waf": self.discovered_waf,
            "tarih": stamp,
            "portlar": self.open_ports,
            "subdomainler": sorted(self.discovered_subdomains),
            "teknolojiler": sorted(self.technologies),
            "sayfalar": sorted(self.visited_urls),
            "formlar": self.discovered_forms,
            "apis": self.discovered_api_endpoints,
            "olu_linkler": self.dead_links,
            "zafiyetler": self.vulnerabilities,
        }

        safe_name = re.sub(r"[^A-Za-z0-9._-]", "_", self.domain)
        json_path = os.path.join(self.report_dir, f"REPORT_{safe_name}.json")
        txt_path = os.path.join(self.report_dir, f"REPORT_{safe_name}.txt")

        try:
            with open(json_path, "w", encoding="utf-8") as jf:
                json.dump(report_data, jf, ensure_ascii=False, indent=4)
            print(Fore.CYAN + f"\n[+] JSON rapor kaydedildi: {json_path}")
        except OSError as e:
            print(Fore.RED + f"[-] JSON yazma hatası: {e}")

        try:
            with open(txt_path, "w", encoding="utf-8") as f:
                f.write("=" * 60 + "\n")
                f.write(" MARKOS WEB ANALIZYER GUVENLIK RAPORU\n")
                f.write(f" Hedef: {self.domain} | IP: {self.ip_address}\n")
                f.write(f" WAF: {self.discovered_waf}\n")
                f.write(f" Mod: {mode_name} | Tarih: {stamp}\n")
                f.write("=" * 60 + "\n\n")
                f.write("--- AÇIK PORTLAR ---\n")
                f.write(", ".join(map(str, self.open_ports)) or "Yok")
                f.write("\n\n--- SUBDOMAINLER ---\n")
                for s in sorted(self.discovered_subdomains):
                    f.write(f" - {s}\n")
                f.write("\n--- TEKNOLOJİLER ---\n")
                for t in sorted(self.technologies):
                    f.write(f" - {t}\n")
                f.write("\n--- HARİTALANAN SAYFALAR ---\n")
                for page in sorted(self.visited_urls):
                    f.write(f" - {page}\n")
                f.write("\n--- FORMLAR ---\n")
                for fm in self.discovered_forms:
                    f.write(f" - {fm}\n")
                f.write("\n--- API UÇLARI ---\n")
                for api in self.discovered_api_endpoints:
                    f.write(f" - {api}\n")
                f.write("\n--- ZAFİYET KANITLARI ---\n")
                for v in self.vulnerabilities:
                    f.write(f"[{v['tip']}] -> {v['url']}\n  Kanıt: {v['detay']}\n\n")
            print(Fore.CYAN + f"[+] TXT rapor kaydedildi: {txt_path}")
        except OSError as e:
            print(Fore.RED + f"[-] TXT yazma hatası: {e}")


# ============================== KONSOL MENÜSÜ ==============================

def show_menu_banner():
    clear_screen()
    print(Fore.RED + Style.BRIGHT + BANNER)
    print(Fore.GREEN + f" [MarkOs WEB ANALIZYER v2.3] | Sistem: {platform.system()} {platform.release()} | Python {platform.python_version()}")
    draw_line(Fore.CYAN)


def pause():
    input(Fore.WHITE + "\nMenüye dönmek için ENTER'a basın...")


def run_target_scan(menu_title, with_ports=True, with_subdomains=False):
    target = input(Fore.LIGHTBLUE_EX + "\nHedef URL veya Domain girin: ").strip()
    if not target:
        print(Fore.RED + "[-] Hedef boş olamaz.")
        return
    scanner = MarkOsProCoreScanner(target)
    scanner.run_raw_socket_recon()
    if with_ports:
        scanner.run_port_scan()
    if with_subdomains:
        scanner.run_subdomain_scan()
    try:
        asyncio.run(scanner.coordinate_scanner())
    except KeyboardInterrupt:
        print(Fore.YELLOW + "\n[!] Tarama kullanıcı tarafından durduruldu.")
    scanner.compile_private_report(menu_title)


def show_system_info():
    print(Fore.CYAN + "\n--- MARKOS SİSTEM PANELİ ---")
    total, used, free = shutil.disk_usage(os.path.abspath(os.sep))
    gb = 1024 ** 3
    print(Fore.WHITE + f" [+] Çekirdek Tipi    : {platform.machine()}")
    print(Fore.WHITE + f" [+] İşlemci          : {platform.processor() or 'Bilinmiyor'} ({os.cpu_count()} çekirdek)")
    print(Fore.WHITE + f" [+] Python Sürümü    : {platform.python_version()}")
    print(Fore.WHITE + f" [+] Depolama         : Toplam {total // gb}GB | Kullanılan {used // gb}GB | Boş {free // gb}GB")
    print(Fore.WHITE + " [+] Durum            : MarkOs WEB ANALIZYER Aktif")
    pause()


def main():
    while True:
        show_menu_banner()
        print(Fore.WHITE + " [1] Full Recon (DNS + Port + Web + Zafiyet + Rapor)")
        print(Fore.WHITE + " [2] Sadece Ham Socket Port Taraması")
        print(Fore.WHITE + " [3] Web & Zafiyet Taraması (Port taraması olmadan)")
        print(Fore.WHITE + " [4] Full Recon + Subdomain Keşfi")
        print(Fore.WHITE + " [5] Sistem Bilgileri ve Çekirdek Durumu")
        print(Fore.RED   + " [0] Güvenli Çıkış")
        draw_line(Fore.CYAN, "-")

        secim = input(Fore.WHITE + "Seçiminiz -> ").strip()

        if secim == "1":
            run_target_scan("FULL RECON", with_ports=True)
            pause()
        elif secim == "2":
            target = input(Fore.LIGHTBLUE_EX + "\nHedef URL veya Domain girin: ").strip()
            if target:
                scanner = MarkOsProCoreScanner(target)
                scanner.run_port_scan()
            pause()
        elif secim == "3":
            run_target_scan("BULGU ANALİZ", with_ports=False)
            pause()
        elif secim == "4":
            run_target_scan("FULL RECON + SUBDOMAIN", with_ports=True, with_subdomains=True)
            pause()
        elif secim == "5":
            show_system_info()
        elif secim == "0":
            print(Fore.GREEN + "\n[*] MarkOs WEB ANALIZYER kapatıldı.")
            break
        else:
            print(Fore.RED + "\n[-] Geçersiz seçim, tekrar deneyin.")
            time.sleep(1.2)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(Fore.GREEN + "\n[*] Çıkış yapılıyor...")
        sys.exit(0)
