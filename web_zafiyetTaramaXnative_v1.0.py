#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
=============================================================================
        MarkOs Tehdit İstihbaratı & Zafiyet Analiz Platformu
                web_zafiyetTaramaXnative_v1.0.py
=============================================================================
Kurulum: pip install httpx colorama
Kullanım: python3 web_zafiyetTaramaXnative_v1.0.py <hedef_url>
"""

import os
import sys
import socket
import re
import time
import asyncio
from urllib.parse import urlparse, urljoin

import httpx
from colorama import Fore, Style, init

init(autoreset=True)

BANNER = r"""
|  \/  | __ _ _ __ | |  / __ \      \ \   / /_ _(_) |
| |\/| |/ _` | '__| | / / _` \  ____\ \ / / _` | | |
| |  | | (_| | |    |/ / (_| | |_____\ V / (_| | | |
|_|  |_|\__,_|_|       \ \__,_|       \_/ \__,_|_|_|
"""


class MarkOsProCoreScanner:
    def __init__(self, target_url, max_pages=30):
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
        self.discovered_waf = "Tespit Edilemedi (Veya Bulunmuyor)"
        self.open_ports = []

        self.report_dir = "markos_private_reports"
        os.makedirs(self.report_dir, exist_ok=True)

    # ---------- 1. Ham Socket Recon ----------
    def run_raw_socket_recon(self):
        print(Fore.YELLOW + f"[*] [{time.strftime('%H:%M:%S')}] Ham Socket bağlantıları kuruluyor...")
        clean_domain = self.domain.split(':')[0]
        try:
            self.ip_address = socket.gethostbyname(clean_domain)
            print(Fore.GREEN + f" [+] DNS çözümleme: {clean_domain} -> [{self.ip_address}]")
        except socket.gaierror:
            print(Fore.RED + " [-] Kritik: Domain IP'ye çözülemedi. Tarama durduruluyor.")
            sys.exit(1)

        critical_ports = [21, 22, 23, 25, 53, 80, 110, 443, 445, 1433, 3306, 3389, 8080]
        print(Fore.YELLOW + "[*] Kritik portlarda TCP taraması yapılıyor...")

        for port in critical_ports:
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.settimeout(1.0)
                    if s.connect_ex((self.ip_address, port)) == 0:
                        print(Fore.RED + Style.BRIGHT +
                              f"  [!] AÇIK PORT: {port}")
                        self.open_ports.append(port)
            except OSError:
                continue

    # ---------- 2. WAF Pasif Analiz ----------
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
                print(Fore.LIGHTMAGENTA_EX + Style.BRIGHT +
                      f" [!] WAF tespit edildi: [{waf_name}]")
                return

    # ---------- 3. Zafiyet Analizi ----------
    def evaluate_web_vulnerabilities(self, url, html, headers):
        server = headers.get("server", "")
        x_powered = headers.get("x-powered-by", "")
        if server:
            self.vulnerabilities.append({"tip": "Sunucu Bilgi İfşası", "url": url,
                                         "detay": f"Sunucu başlığı: {server}"})
        if x_powered:
            self.vulnerabilities.append({"tip": "Teknoloji Sızıntısı", "url": url,
                                         "detay": f"Altyapı: {x_powered}"})

        comments = re.findall(r'<!--.*?-->', html, re.DOTALL)
        for comment in comments:
            low = comment.lower()
            if any(k in low for k in ["admin", "password", "key", "config",
                                      "test", "yedek", "sql"]):
                self.vulnerabilities.append(
                    {"tip": "Kaynak Kodda Şüpheli Yorum", "url": url,
                     "detay": comment.strip()[:120]})

        sql_errors = ["sql syntax", "mysql_fetch", "ora-", "postgresql",
                      "microsoft ole db", "unclosed quotation mark"]
        low = html.lower()
        if any(err in low for err in sql_errors):
            self.vulnerabilities.append(
                {"tip": "Potansiyel SQL Hata Yapısı", "url": url,
                 "detay": "Sayfa kaynağında SQL hata kalıpları tespit edildi!"})

        if url.startswith("http://"):
            self.vulnerabilities.append(
                {"tip": "Şifresiz HTTP Kullanımı", "url": url,
                 "detay": "Sayfa HTTPS yerine düz HTTP üzerinden sunuluyor."})

    # ---------- 4. Form Analizi ----------
    def evaluate_forms(self, url, html):
        for form in re.findall(r'<form\b.*?>', html, re.IGNORECASE | re.DOTALL):
            is_post = bool(re.search(r'method\s*=\s*["\']post["\']',
                                     form, re.IGNORECASE))
            action = re.search(r'action\s*=\s*["\'](.*?)["\']',
                               form, re.IGNORECASE)
            action_url = action.group(1) if action else "Mevcut URL"

            form_data = (f"Kaynak: {url} -> Hedef: {action_url} | "
                         f"Yöntem: {'POST' if is_post else 'GET'}")
            if form_data not in self.discovered_forms:
                self.discovered_forms.append(form_data)
                if url.startswith("http://") and is_post:
                    self.vulnerabilities.append(
                        {"tip": "Güvensiz Kimlik Doğrulama Formu", "url": url,
                         "detay": "HTTP üzerinden POST formu (MITM riski)."})

    # ---------- 5. Asenkron Sayfa İşleme ----------
    async def process_async_page(self, client, url):
        if url in self.visited_urls:
            return
        self.visited_urls.add(url)

        headers = {'User-Agent': 'MarkOs_Shield_Engine/2.0'}
        try:
            resp = await client.get(url, headers=headers,
                                    follow_redirects=True)
            html = resp.text

            if self.discovered_waf.startswith("Tespit"):
                self.detect_waf_presence(resp.headers, html)

            self.evaluate_web_vulnerabilities(url, html, resp.headers)
            self.evaluate_forms(url, html)

            for link in re.findall(r'href\s*=\s*["\'](.*?)["\']',
                                   html, re.IGNORECASE):
                full = urljoin(url, link)
                if urlparse(full).netloc == self.domain and full.startswith("http"):
                    clean = full.split('#')[0].rstrip('/')
                    if clean not in self.visited_urls:
                        self.urls_to_visit.add(clean)
        except httpx.HTTPError:
            pass
        except Exception:
            pass

    # ---------- 6. Orkestrasyon ----------
    async def coordinate_scanner(self):
        print(Fore.YELLOW +
              f"[*] Asenkron tarama havuzu başlatıldı (Maks sayfa: {self.max_pages})...")
        async with httpx.AsyncClient(
            timeout=8.0,
            verify=False,
            follow_redirects=True,
        ) as client:
            while self.urls_to_visit and len(self.visited_urls) < self.max_pages:
                batch = list(self.urls_to_visit)[:10]
                for u in batch:
                    self.urls_to_visit.discard(u)
                tasks = [self.process_async_page(client, u) for u in batch]
                await asyncio.gather(*tasks)

    # ---------- 7. Raporlama ----------
    def compile_private_report(self):
        os.system('cls' if os.name == 'nt' else 'clear')

        print(Fore.CYAN + "=" * 66)
        print(Fore.RED + Style.BRIGHT +
              " [GIZLI RAPOR] MARKOS SIBER ISTIHBARAT SONUCLARI")
        print(Fore.CYAN + "=" * 66)
        print(Fore.GREEN + f"\nHedef Domain  : {self.domain}")
        print(Fore.GREEN + f"Cozulen IP    : {self.ip_address}")
        print(Fore.GREEN + f"Koruma Duvari : {self.discovered_waf}")
        print(Fore.GREEN + f"Acik Portlar  : {self.open_ports or 'Kritik port bulunamadi'}")

        print(Fore.YELLOW +
              f"\n[+] SITE HARITASI ({len(self.visited_urls)} sayfa):")
        for page in sorted(self.visited_urls):
            print(Fore.WHITE + f"  - {page}")

        print(Fore.YELLOW +
              f"\n[+] FORMLAR ({len(self.discovered_forms)} adet):")
        for f_ in self.discovered_forms:
            print(Fore.WHITE + f"  - {f_}")

        print(Fore.YELLOW +
              f"\n[+] BULGULAR ({len(self.vulnerabilities)} adet):")
        for v in self.vulnerabilities:
            print(Fore.RED + Style.BRIGHT +
                  f"  [!] {v['tip']} -> {v['url']}")
            print(Fore.WHITE + f"      Detay: {v['detay']}")

        report_path = os.path.join(self.report_dir,
                                   f"PRIVATE_{self.domain}_recon.txt")
        try:
            with open(report_path, "w", encoding="utf-8") as f:
                f.write("=" * 52 + "\n")
                f.write(" MARKOS GIZLI GUVENLIK VE RECON RAPORU\n")
                f.write(f" Target: {self.domain} | IP: {self.ip_address}\n")
                f.write(f" WAF: {self.discovered_waf}\n")
                f.write(f" Tarih: {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write("=" * 52 + "\n\n")
                f.write("--- ACIK PORTLAR ---\n")
                f.write(", ".join(map(str, self.open_ports)) or "Yok")
                f.write("\n\n--- HARITALANAN LINKLER ---\n")
                for page in sorted(self.visited_urls):
                    f.write(f" - {page}\n")
                f.write("\n--- FORMLAR ---\n")
                for f_ in self.discovered_forms:
                    f.write(f" - {f_}\n")
                f.write("\n--- ZAFIYET KANITLARI ---\n")
                for v in self.vulnerabilities:
                    f.write(f"[{v['tip']}] -> {v['url']}\n"
                            f"Kanit: {v['detay']}\n\n")
            print(Fore.CYAN + f"\n[+] Rapor kaydedildi: {report_path}")
        except OSError as e:
            print(Fore.RED + f"[-] Dosya yazma hatası: {e}")


def main():
    if os.name == 'nt':
        os.system("title MarkOs Private Core Engine v1.0")

    print(Fore.RED + Style.BRIGHT + BANNER)
    print(Fore.CYAN + "=" * 66)
    print(Fore.RED + " [MarkOs Siber Tehdit Analiz Motoru]")
    print(Fore.GREEN + " [+] Yetki: Ham Ag Katmani, WAF Analiz, SQL Mantik Tarama")
    print(Fore.CYAN + "=" * 66 + "\n")

    if len(sys.argv) < 2:
        print(Fore.YELLOW +
              "Kullanim: python3 web_zafiyetTaramaXnative_v1.0.py <hedef_url>")
        sys.exit(1)

    scanner = MarkOsProCoreScanner(sys.argv[1], max_pages=30)
    scanner.run_raw_socket_recon()

    try:
        asyncio.run(scanner.coordinate_scanner())
    except Exception as e:
        print(Fore.RED + f"[-] Asenkron dongu hatasi: {e}")

    scanner.compile_private_report()


if __name__ == "__main__":
    main()
