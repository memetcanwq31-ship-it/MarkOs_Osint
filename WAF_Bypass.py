# ===================================================================
# PROJE ADI   : MarkOs Waf Bypass & Encoding Suite (Waf_bypass.py)
# GELİŞTİRİCİ : memetcanwq31-ship-it (BTK Akademi Uyumlu Mimarî)
# STATÜ       : %100 GERÇEK VE CANLI ÇALIŞAN PYTHON MASKÖRÜ
# ===================================================================

import urllib.parse

class MarkOsWafBypassPy:
    def __init__(self):
        self.version = "1.0.0-PythonEvasion"

    # Modül 1: Çift URL Kodlama Algoritması
    def double_url_encode(self, payload):
        first = urllib.parse.quote_plus(payload)
        return urllib.parse.quote_plus(first)

    # Modül 2: Boşlukları Yorum Satırıyla Parçalama Protokolü
    def sql_comment_bypass(self, payload):
        return payload.replace(" ", "/**/")

    # Modül 3: Karakterleri Karşılık Gelen Unicode Formata Çevirme
    def unicode_obfuscate(self, payload):
        return "".join([f"\\u{ord(c):04x}" for c in payload])

if __name__ == "__main__":
    bypass_engine = MarkOsWafBypassPy()
    print("\033[32m=== MARKOS PYTHON WAF BYPASS & OBFUSCATION SUITE ===\033[0m")
    raw_input = input("\033[36m[?] Maskelenecek Test Metnini Girin: \033[0m").strip()
    
    if not raw_input:
        print("\033[31m[!] Hata: Girdi alanı boş bırakılamaz!\033[0m")
        exit()

    print("\n\033[33m[+] Python Gerçek Zamanlı Maskeleme Katmanları:\033[0m")
    print(f"\033[32m  • [Double URL Encode] : \033[37m{bypass_engine.double_url_encode(raw_input)}\033[0m")
    print(f"\033[32m  • [SQL Comment Split] : \033[37m{bypass_engine.sql_comment_bypass(raw_input)}\033[0m")
    print(f"\033[32m  • [Unicode Obfuscate] : \033[37m{bypass_engine.unicode_obfuscate(raw_input)}\033[0m")
