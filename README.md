<!--
  MarkOs_Osint - README
  Polished, bilingual (TR/EN) README with full MIT license included and a separate LICENSE file.
  Edited by GitHub Copilot on user request.
-->

# ─── ███╗   ███╗ █████╗ ██████╗ ██╗  ██╗ ██████╗ ███████╗ ───
# ─── ████╗ ████║██╔══██╗██╔══██╗██║ ██╔╝██╔═══██╗██╔════╝ ───
# ─── ██╔████╔██║███████║██████╔╝█████╔╝ ██║   ██║███████╗ ───
# ─── ██║╚██╔╝██║██╔══██║██╔══██╗██╔═██╗ ██║   ██║╚════██║ ───
# ─── ██║ ╚═╝ ██║██║  ██║██║  ██╗██║  ██╗╚██████╔╝███████║ ───
# ─── ╚═╝     ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝ ╚══════╝ ───
#       M A R K O S   O S I N T   &   B 2 B   F R A M E W O R K
# ─────────────────────────────────────────────────────────────────

![MarkOs](https://img.shields.io/badge/MarkOs-OSINT%20%26%20B2B-blue)

## Kısa Tanıtım
MarkOs, kurumsal düzeyde Purple Team (Mor Takım) güvenlik uyumluluğu ve istihbarat çözümleri sunan hafif ama güçlü bir çerçevedir. Araç seti Linux ve Termux ortamlarında çalışmak üzere optimize edilmiş, yüksek performanslı asenkron ağ operasyonları ile yerel şifreli depolama (Vault) sağlar.

Bu repo: memetcanwq31-ship-it / MarkOs_Osint

## Öne Çıkan Modüller (Mevcut)
- markos_b2b_scanner.py — B2B Advanced WAF Compliance Engine
  - Çok katmanlı maskeleme (double encoding, comment splitting vb.) tekniklerine karşı dayanıklılık testleri.
  - SIEM/SOC uyumlu JSON çıktıları.

- MarkOs_Zanox_Pro.py — Asynchronous OSINT Engine
  - `asyncio` + `httpx` ile hızlı yasal subdomain keşifleri.
  - Bulgu kayıtları şifreli `sqlite3` veri tabanına yazılır.

- Waf_bypass.py / Waf_bypass.rb — Multi-language Evasion Lab
  - Laboratuvar amaçlı imza analizi ve evasion tekniklerini test eden mutasyon motorları.

Ek paketler: MarkOsXzanox_v1.0, MarkOsXzanox_v2.0, run_all, NEARKOS (sızma & zafiyet), analiz araçları, Paganes Antivirus, Wifi Analyzer vb.

---

## Hızlı Kurulum (Linux / Termux)
Aşağıdaki adımlar temel bir kurulum içindir. Ortamınıza göre ek bağımlılıklar gerekebilir.

```bash
# 1) Depoyu klonlayın
git clone https://github.com/memetcanwq31-ship-it/MarkOs_Osint.git
cd MarkOs_Osint

# 2) (Önerilen) Python sanal ortamı oluşturun
python3 -m venv venv
source venv/bin/activate

# 3) Bağımlılıkları yükleyin
pip install -r requirements.txt

# 4) Ana framework'ü başlatın
python3 markos_python_framework.py

# 5) B2B tarayıcıyı çalıştırın
python3 markos_b2b_scanner.py
```

Notlar:
- Python 3.8+ tavsiye edilir.
- Termux üzerinde ek paketler/izinler gerekebilir; Termux dokümantasyonunu kontrol edin.

---

## Kullanım & Örnekler
Her modül kendi CLI argümanlarına sahiptir. Yardım için:

```bash
python3 markos_b2b_scanner.py --help
python3 MarkOs_Zanox_Pro.py --help
```

---

## Güvenlik & Etik
Bu araçlar yalnızca yasal araştırma, yetkilendirilmiş penetrasyon testleri ve akademik kullanım içindir. Yetkisiz erişim veya kötüye kullanım yasal sorumluluk doğurur. Herhangi bir kurumsal dağıtımdan önce hukuki onay almanız önerilir.

---

## Katkıda Bulunma
Katkılar memnuniyetle karşılanır. Lütfen pull request, issue veya e-posta yoluyla iletişime geçin. Kod katkısı yaparken lütfen CONTRIBUTING.md yönergelerini takip edin (eğer varsa).

---

## Lisans (Tam Metin)
Aşağıda projenin lisans metni (MIT) tam olarak yer almaktadır. Ayrıca repo kökünde `LICENSE` dosyası bulunmaktadır.

```
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

---

Geliştiren: memetcanwq31-ship-it
İletişim: https://github.com/memetcanwq31-ship-it
Son güncelleme: 2026-10-12
