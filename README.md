# ─── ███╗   ███╗ █████╗ ██████╗ ██╗  ██╗ ██████╗ ███████╗ ───
# ─── ████╗ ████║██╔══██╗██╔══██╗██║ ██╔╝██╔═══██╗██╔════╝ ───
# ─── ██╔████╔██║███████║██████╔╝█████╔╝ ██║   ██║███████╗ ───
# ─── ██║╚██╔╝██║██╔══██║██╔══██╗██╔═██╗ ██║   ██║╚════██║ ───
# ─── ██║ ╚═╝ ██║██║  ██║██║  ██╗██║  ██╗╚██████╔╝███████║ ───
# ─── ╚═╝     ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝ ╚══════╝ ───
#       M A R K O S   O S I N T   &   B 2 B   F R A M E W O R K
# ─────────────────────────────────────────────────────────────────

# MarkOs OSINT & B2B Framework

Welcome to the official repository of **MarkOs Enterprise Solutions** — a Purple Team security compliance and intelligence ecosystem developed by **memetcanwq31-ship-it**.

This suite is optimized for **Linux** and **Termux** environments, combining high-performance asynchronous networking with secure local storage.

## 📡 Core Enterprise Modules (Mevcut Cephanelik)

Bu ekosistem, kurumsal ağların ve sunucuların güvenlik dayanıklılığını test eden 3 ana çekirdek motordan oluşur:

1. **markos_b2b_scanner.py — B2B Advanced WAF Compliance Engine**
   - Çok katmanlı maskeleme tekniklerine (double encoding, comment splitting vb.) karşı sunucu dayanıklılığını test eder.
   - Kurumsal SIEM/SOC uyumlu `.json` formatında adli bilişim çıktısı üretir.

2. **MarkOs_Zanox_Pro.py — Asynchronous OSINT Engine**
   - `asyncio` ve `httpx` kullanarak hızlı, yasal subdomain keşifleri yapar.
   - Bulgular yerel, şifreli `sqlite3` veri tabanında saklanır (Vault).

3. **Waf_bypass.py / Waf_bypass.rb — Multi-Language Evasion Lab**
   - Laboratuvar ortamlarında imza analizi ve evasion testi yapmak için girdileri çeşitli mutasyonlarla dönüştüren motorlardır.

> Diğer araçlar ve paketler: MarkOsXzanox_v1.0, MarkOsXzanox_v2.0, run_all, NEARKOS (Sızma ve Zafiyet Tarama Paketleri), Analiz Araç Paketi, Paganes Antivirus, Wifi Analyzer araçları ve daha fazlası.

## 🚀 Kurulum & Çalıştırma (Installation & Deployment)

Aşağıdaki adımlar MarkOs ekosistemini yerel makinenize veya Termux ortamınıza kurmak ve başlatmak için temel yönlendirmedir:

```bash
# 1. Depoyu klonlayın
git clone https://github.com/memetcanwq31-ship-it/MarkOs_Osint.git

# 2. Proje dizinine girin
cd MarkOs_Osint

# 3. (Opsiyonel) Sanal ortam oluşturun ve etkinleştirin (Linux)
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

# 4. Ana framework'ü başlatın
python3 markos_python_framework.py

# 5. B2B tarayıcıyı çalıştırın
python3 markos_b2b_scanner.py
```

Not: Kullanılan Python sürümü 3.8+ olmalıdır. Termux üzerinde kullanım için ek bağımlılıklar gerekebilir — `requirements.txt` dosyasını kontrol edin.

## 🔒 Security Compliance & B2B Licensing

* **SOC / SIEM Integration:** Tüm tarama motorları, kurumsal SOC/SIEM çözümleriyle entegre edilebilecek standart formatlarda çıktı üretir.
* **Commercial Support:** B2B lisanslama, özel entegrasyonlar veya kurumsal destek için MarkOs Enterprise ile GitHub veya LinkedIn üzerinden iletişime geçin.

## 📄 License & Disclaimer

This repository is published under the **MIT License**. The tools and modules in this repo are developed for legal research, authorized penetration testing, red/purple team exercises, and academic purposes only. Misuse for unauthorized access or malicious activity is strictly prohibited.

MIT License (tam metin):

```text
MIT License

Copyright (c) 2026 memetcanwq31-ship-it

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

Lütfen lisans ayrıntıları için ayrıca `LICENSE` dosyasını da kontrol edin. Herhangi bir kurumsal dağıtım veya ticari kullanım öncesi hukuki onay alınmasını öneririz.

---

Geliştiren: memetcanwq31-ship-it
İletişim: https://github.com/memetcanwq31-ship-it

Son güncelleme: 2026-10-12
