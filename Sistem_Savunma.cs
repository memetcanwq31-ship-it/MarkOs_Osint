/* ===================================================================
 * PROJE      : MarkOs Enterprise Defense Suite v2026.1
 * AMAÇ       : Anti-Ransomware + Anti-Phishing SAVUNMA framework'ü
 * MİMARİ     : C# / .NET 8.0
 * LİSANS     : MIT
 * NOT        : %100 savunma odaklı. Sadece kendi sisteminizi korur,
 *              hiçbir saldırı kabiliyeti içermez.
 * ===================================================================
 */

using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;

namespace MarkOsSecurity.DefenseSuite
{
    // ================================================================
    // 1. LOG KATMANI
    // ================================================================
    public static class ShieldLog
    {
        private static readonly object _lock = new();
        private static readonly string LogDir =
            Path.Combine(AppContext.BaseDirectory, "MarkOs_Logs");

        static ShieldLog()
        {
            Directory.CreateDirectory(LogDir);
        }

        private static void Write(string level, string color, string msg)
        {
            lock (_lock)
            {
                Console.ForegroundColor = ConsoleColor.DarkGray;
                Console.Write($"[{DateTime.Now:yyyy-MM-dd HH:mm:ss.fff}] ");
                Console.ForegroundColor = color;
                Console.WriteLine($"[{level,-8}] {msg}");
                Console.ResetColor();
            }
            File.AppendAllText(
                Path.Combine(LogDir, $"shield_{DateTime.Now:yyyyMMdd}.log"),
                $"{DateTime.Now:O}|{level}|{msg}{Environment.NewLine}");
        }

        public static void Info(string m)    => Write("INFO",    ConsoleColor.Cyan, m);
        public static void Ok(string m)      => Write("OK",      ConsoleColor.Green, m);
        public static void Warn(string m)    => Write("WARN",    ConsoleColor.Yellow, m);
        public static void Alert(string m)   => Write("ALERT",   ConsoleColor.Red, m);
        public static void Debug(string m)   => Write("DEBUG",   ConsoleColor.Gray, m);
    }

    // ================================================================
    // 2. YAPILANDIRMA
    // ================================================================
    public class ShieldConfig
    {
        public List<string> KorumaliDizinler { get; set; } = new()
        {
            Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments),
            Environment.GetFolderPath(Environment.SpecialFolder.Desktop),
            Environment.GetFolderPath(Environment.SpecialFolder.MyPictures)
        };

        public List<string> KritikUzantilar { get; set; } = new()
        {
            ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".pdf",
            ".jpg", ".jpeg", ".png", ".gif", ".psd", ".ai",
            ".zip", ".rar", ".7z", ".sql", ".db", ".mdb",
            ".mp4", ".mp3", ".avi", ".mkv", ".vmx", ".vmdk"
        };

        // Ransomware'in yaygın hedef uzantıları (değişim = şüpheli)
        public List<string> RansomUzantilari { get; set; } = new()
        {
            ".locked", ".encrypted", ".crypt", ".crypto", ".ransom",
            ".locky", ".cerber", ".wallet", ".onion", ".enc",
            ".wncry", ".wcry", ".paymen", ".readmanual", ".restore"
        };

        public List<string> RansomNotDosyalari { get; set; } = new()
        {
            "readme.txt", "readme.html", "decrypt.txt", "restore_files.txt",
            "how_to_decrypt.txt", "ransomnote.txt", "_read_me.txt",
            "help_decrypt_your_files.txt", "readme_for_decrypt.txt"
        };

        // Şüpheli scriptleme süreçleri (davranış korelasyonu için)
        public List<string> SupheliSurecAdlari { get; set; } = new()
        {
            "vssadmin", "wbadmin", "bcdedit", "bcdedit.exe",
            "wscript", "cscript", "mshta", "certutil", "bitsadmin",
            "powershell", "cmd", "rundll32", "regsvr32"
        };

        // Phishing heuristiği: güvenilir domainler
        public List<string> GuvenilirDomainler { get; set; } = new()
        {
            "microsoft.com", "google.com", "github.com", "apple.com",
            "amazon.com", "paypal.com", "banka.gov.tr", "turkiye.gov.tr",
            "e-devlet.gov.tr", "gmail.com", "outlook.com", "yahoo.com"
        };

        public double EntropiEsigi { get; set; } = 7.5;
        public int TopluDegisimEsigi { get; set; } = 10;          // 60 sn içinde
        public int TopluDegisimPenceresiSn { get; set; } = 60;
        public int KarantinaYedekGun { get; set; } = 30;
        public long MaksYedekBoyutMB { get; set; } = 200;
        public string YedekDizini { get; set; } =
            Path.Combine(AppContext.BaseDirectory, "MarkOs_Backup");
        public string KarantinaDizini { get; set; } =
            Path.Combine(AppContext.BaseDirectory, "MarkOs_Quarantine");
        public string YedekSifre { get; set; } = "MARKOS-DEGIS-BUNU-2026!";
        public bool UzerineYazKorumasi { get; set; } = true;
        public bool PhishingKontrolAktif { get; set; } = true;
        public bool SurecIzleyiciAktif { get; set; } = true;
    }

    // ================================================================
    // 3. ENTROPİ & İMZA ANALİZİ
    // ================================================================
    public static class EntropyAnalyzer
    {
        /// <summary>Shannon entropisi: 0.0 - 8.0 bit/bayt. 7.5+ = şifreli/arıştırılmış veri.</summary>
        public static double Hesapla(string dosyaYolu, int orneklemKB = 256)
        {
            try
            {
                var fi = new FileInfo(dosyaYolu);
                if (!fi.Exists || fi.Length == 0) return 0;

                long okunacak = Math.Min(fi.Length, orneklemKB * 1024);
                byte[] buf = new byte[okunacak];

                using var fs = new FileStream(dosyaYolu, FileMode.Open,
                    FileAccess.Read, FileShare.ReadWrite);
                fs.Read(buf, 0, buf.Length);

                int[] frekans = new int[256];
                foreach (byte b in buf) frekans[b]++;
                double entropi = 0, n = buf.Length;
                foreach (int f in frekans)
                    if (f > 0)
                    {
                        double p = f / n;
                        entropi -= p * Math.Log2(p);
                    }
                return Math.Round(entropi, 3);
            }
            catch (IOException) { return -1; }  // dosya kilitli
            catch (Exception) { return -1; }
        }

        /// <summary>Dosya imzasını (magic bytes) gerçek MIME ile uzantıyı karşılaştırır.</summary>
        public static bool ImzaUzantiUyumuVar(string dosyaYolu, out string tespit)
        {
            tespit = "bilinmiyor";
            try
            {
                byte[] hdr = new byte[8];
                using var fs = new FileStream(dosyaYolu, FileMode.Open,
                    FileAccess.Read, FileShare.ReadWrite);
                if (fs.Read(hdr, 0, hdr.Length) < 4) { tespit = "cok-kucuk"; return true; }

                string ext = Path.GetExtension(dosyaYolu).ToLowerInvariant();

                // Executable imzaları — script uzantılı dosyaların aslında PE olup olmadığını yakalar
                bool pe = hdr[0] == 0x4D && hdr[1] == 0x5A;
                bool elf = hdr[0] == 0x7F && hdr[1] == 0x45;
                bool script = ext is ".txt" or ".vbs" or ".js" or ".ps1"
                                     or ".bat" or ".cmd" or ".doc" or ".pdf"
                                     or ".jpg" or ".png" or ".xls" or ".log";

                if (pe || elf)
                {
                    tespit = pe ? "Windows-PE" : "ELF";
                    return !script; // metin/görsel uzantısında exe imzası = gizli malware
                }

                tespit = "normal";
                return true;
            }
            catch { tespit = "hata"; return true; }
        }
    }

    // ================================================================
    // 4. OLAY MODELLERİ
    // ================================================================
    public class ThreatEvent
    {
        public string Id { get; init; } = "MKOS-" + Guid.NewGuid().ToString("N")[..8].ToUpper();
        public DateTime Zaman { get; init; } = DateTime.Now;
        public string Tip { get; set; } = "";          // Ransomware / Phishing / Spoof
        public string Kaynak { get; set; } = "";
        public string Hedef { get; set; } = "";
        public double Skor { get; set; }
        public string Detay { get; set; } = "";
        public ThreatLevel Seviye { get; set; } = ThreatLevel.Dusuk;

        public string ToJson() =>
            JsonSerializer.Serialize(this, new JsonSerializerOptions { WriteIndented = true });
    }

    public enum ThreatLevel { Dusuk = 1, Orta = 2, Yuksek = 3, Kritik = 4 }

    // ================================================================
    // 5. HONEYPOT (BAL KÜPÜ) TUZAK MOTORU
    // ================================================================
    public class HoneypotEngine
    {
        private readonly ShieldConfig _cfg;
        private readonly List<string> _tuzakDosyalar = new();

        private static readonly string[] TuzakIcerik =
        {
            "BUTCE_2026_FINAL.docx", "sifreler.txt", "yedek_veritabani.sql",
            "musteri_listesi.xlsx", "ozel_projeler.zip", "kredi_karti.csv",
            "sistem_admin_notlari.txt", "VPN_sifreleri.kdbx"
        };

        public HoneypotEngine(ShieldConfig cfg) => _cfg = cfg;

        public void TuzaklariYerlestir()
        {
            int sayac = 0;
            foreach (var dizin in _cfg.KorumaliDizinler)
            {
                if (string.IsNullOrEmpty(dizin) || !Directory.Exists(dizin)) continue;

                string hpDir = Path.Combine(dizin, ".MarkOs_HoneyVault");
                Directory.CreateDirectory(hpDir);

                foreach (var ad in TuzakIcerik)
                {
                    string tuzak = Path.Combine(hpDir, ad);
                    if (!File.Exists(tuzak))
                    {
                        // Gerçekçi görünen ama değersiz içerik
                        byte[] dolgu = new byte[4096];
                        Random.Shared.NextBytes(dolgu);
                        File.WriteAllBytes(tuzak, dolgu);
                        File.SetAttributes(tuzak, FileAttributes.Hidden | FileAttributes.System);
                    }
                    _tuzakDosyalar.Add(tuzak);
                    sayac++;
                }

                // Ana dizin köküne de görünür bir tuzak
                string anaTuzak = Path.Combine(dizin, "SIFRELER_VE_YEDEKLER.txt");
                if (!File.Exists(anaTuzak))
                    File.WriteAllText(anaTuzak, "Bu dosya MarkOs koruması altındadır.");
                _tuzakDosyalar.Add(anaTuzak);
                sayac++;
            }
            ShieldLog.Ok($"Honeypot motoru aktif: {sayac} tuzak dosya yerleştirildi.");
        }

        /// <summary>Tuzaklardan birine dokunulmuş mu? Ransomware en keskin imzasıdır.</summary>
        public bool TuzakIhlaliKontrolEt(string degisenDosya, out string tuzakYolu)
        {
            tuzakYolu = "";
            foreach (var t in _tuzakDosyalar)
            {
                if (string.Equals(
                        Path.GetFullPath(degisenDosya),
                        Path.GetFullPath(t),
                        StringComparison.OrdinalIgnoreCase))
                {
                    tuzakYolu = t;
                    return true;
                }
            }
            return false;
        }

        public IReadOnlyList<string> TuzakListesi => _tuzakDosyalar;
    }

    // ================================================================
    // 6. SANSÜR / SANSÜRSÜZ DEĞİL — KARANTİNA + ŞİFRELİ YEDEK MOTORU
    // ================================================================
    public class BackupQuarantineEngine
    {
        private readonly ShieldConfig _cfg;

        public BackupQuarantineEngine(ShieldConfig cfg)
        {
            _cfg = cfg;
            Directory.CreateDirectory(_cfg.YedekDizini);
            Directory.CreateDirectory(_cfg.KarantinaDizini);
        }

        /// <summary>AES-256-CBC + PKCS7 ile dosyayı şifreli yedekler.</summary>
        public bool SifreliYedekAl(string kaynak, out string yedekYolu)
        {
            yedekYolu = "";
            try
            {
                var fi = new FileInfo(kaynak);
                if (!fi.Exists || fi.Length > _cfg.MaksYedekBoyutMB * 1024L * 1024)
                    return false;

                string ad = $"{DateTime.Now:yyyyMMdd_HHmmss}_{Path.GetFileName(kaynak)}.mkenc";
                string hedef = Path.Combine(_cfg.YedekDizini, ad);

                using var aes = Aes.Create();
                aes.KeySize = 256;
                aes.GenerateIV();
                aes.Key = DeriveKey(_cfg.YedekSifre, aes.IV);

                using var fsGiris = new FileStream(kaynak, FileMode.Open, FileAccess.Read);
                using var fsCikis = new FileStream(hedef, FileMode.Create);
                fsCikis.Write(aes.IV, 0, aes.IV.Length); // IV başa gömülür
                using var cs = new CryptoStream(fsCikis,
                    aes.CreateEncryptor(), CryptoStreamMode.Write);
                using var gz = new GZipStream(cs, CompressionLevel.Optimal);
                fsGiris.CopyTo(gz);

                yedekYolu = hedef;
                ShieldLog.Ok($"Şifreli yedek alındı: {ad}");
                return true;
            }
            catch (Exception ex)
            {
                ShieldLog.Warn($"Yedekleme başarısız: {kaynak} → {ex.Message}");
                return false;
            }
        }

        /// <summary>Şifreli yedeği geri yükler (kurtarma senaryosu).</summary>
        public bool YedekGeriYukle(string yedekYolu, string hedefYol)
        {
            try
            {
                byte[] iv = new byte[16];
                using var fs = new FileStream(yedekYolu, FileMode.Open, FileAccess.Read);
                fs.ReadExactly(iv, 0, 16);

                using var aes = Aes.Create();
                aes.Key = DeriveKey(_cfg.YedekSifre, iv);
                aes.IV = iv;

                using var cs = new CryptoStream(fs, aes.CreateDecryptor(), CryptoStreamMode.Read);
                using var gz = new GZipStream(cs, CompressionMode.Decompress);
                using var cikis = new FileStream(hedefYol, FileMode.Create);
                gz.CopyTo(cikis);

                ShieldLog.Ok($"Yedek geri yüklendi: {hedefYol}");
                return true;
            }
            catch (Exception ex)
            {
                ShieldLog.Alert($"Geri yükleme başarısız: {ex.Message}");
                return false;
            }
        }

        /// <summary>Şüpheli dosyayı karantinaya taşır (XOR-şifreleme = virüs taraması etkisiz).</summary>
        public bool KarantinayaAl(string dosya, out string karantinaYolu)
        {
            karantinaYolu = "";
            try
            {
                if (!File.Exists(dosya)) return false;
                string ad = $"{DateTime.Now:yyyyMMdd_HHmmss}_{Path.GetFileName(dosya)}.quar";
                karantinaYolu = Path.Combine(_cfg.KarantinaDizini, ad);

                byte[] icerik = File.ReadAllBytes(dosya);
                byte[] anahtar = Encoding.UTF8.GetBytes(_cfg.YedekSifre);
                for (int i = 0; i < icerik.Length; i++)
                    icerik[i] ^= anahtar[i % anahtar.Length];
                File.WriteAllBytes(karantinaYolu, icerik);
                File.SetAttributes(karantinaYolu, FileAttributes.Hidden | FileAttributes.ReadOnly);
                File.Delete(dosya);

                ShieldLog.Warn($"Dosya karantinaya alındı: {dosya} → {ad}");
                return true;
            }
            catch (Exception ex)
            {
                ShieldLog.Warn($"Karantina hatası: {ex.Message}");
                return false;
            }
        }

        public void EskiYedekleriTemizle()
        {
            try
            {
                foreach (var f in new DirectoryInfo(_cfg.YedekDizini).GetFiles())
                    if (f.CreationTime < DateTime.Now.AddDays(-_cfg.KarantinaYedekGun))
                        f.Delete();
            }
            catch { /* sessiz */ }
        }

        private static byte[] DeriveKey(string sifre, byte[] salt) =>
            new Rfc2898DeriveBytes(sifre, salt, 100_000, HashAlgorithmName.SHA256)
                .GetBytes(32);
    }

    // ================================================================
    // 7. RANSOMWARE TESPİT ÇEKİRDEĞİ
    // ================================================================
    public class RansomwareDetector
    {
        private readonly ShieldConfig _cfg;
        private readonly HoneypotEngine _honeypot;
        private readonly BackupQuarantineEngine _yedek;
        private readonly ConcurrentQueue<(DateTime zaman, string surec)> _degisimHavuzu = new();
        public event Action<ThreatEvent>? TehditTespitEdildi;

        public RansomwareDetector(ShieldConfig cfg, HoneypotEngine hp, BackupQuarantineEngine yedek)
        { _cfg = cfg; _honeypot = hp; _yedek = yedek; }

        /// <summary>Dosya değişim olayını analiz eder. Eylem kararı döner.</summary>
        public DetectorAction OlayIsle(string dosyaYolu, string surecAdi)
        {
            var now = DateTime.Now;

            // --- 1) Honeypot ihlali = neredeyse %100 ransomware ---
            if (_honeypot.TuzakIhlaliKontrolEt(dosyaYolu, out string tuzak))
            {
                TehditTespitEdildi?.Invoke(new ThreatEvent
                {
                    Tip = "Ransomware",
                    Kaynak = surecAdi,
                    Hedef = dosyaYolu,
                    Skor = 99,
                    Seviye = ThreatLevel.Kritik,
                    Detay = $"HONEYPOT İHLALİ: Kritik tuzak dosyaya erişim! ({tuzak})"
                });
                return DetectorAction.KarantinaVeKilitle;
            }

            string ext = Path.GetExtension(dosyaYolu).ToLowerInvariant();

            // --- 2) Ransom uzantısı değişimi ---
            if (_cfg.RansomUzantilari.Contains(ext))
            {
                TehditTespitEdildi?.Invoke(new ThreatEvent
                {
                    Tip = "Ransomware", Kaynak = surecAdi, Hedef = dosyaYolu,
                    Skor = 95, Seviye = ThreatLevel.Kritik,
                    Detay = $"Bilinen ransom uzantısı tespit edildi: {ext}"
                });
                return DetectorAction.KarantinaVeKilitle;
            }

            // --- 3) Fidye notu oluşturulması ---
            string ad = Path.GetFileName(dosyaYolu).ToLowerInvariant();
            if (_cfg.RansomNotDosyalari.Contains(ad))
            {
                TehditTespitEdildi?.Invoke(new ThreatEvent
                {
                    Tip = "Ransomware", Kaynak = surecAdi, Hedef = dosyaYolu,
                    Skor = 90, Seviye = ThreatLevel.Kritik,
                    Detay = $"Fidye notu dosyası oluşturuldu: {ad}"
                });
                return DetectorAction.KarantinaVeKilitle;
            }

            // --- 4) Entropi sıçraması (şifreleme faaliyeti) ---
            double ent = EntropyAnalyzer.Hesapla(dosyaYolu);
            if (ent > _cfg.EntropiEsigi && _cfg.KritikUzantilar.Contains(ext))
            {
                TehditTespitEdildi?.Invoke(new ThreatEvent
                {
                    Tip = "Ransomware", Kaynak = surecAdi, Hedef = dosyaYolu,
                    Skor = 80, Seviye = ThreatLevel.Yuksek,
                    Detay = $"Yüksek entropi ({ent}/8.0) — veriler şifrelenmiş olabilir."
                });
                return DetectorAction.YedekleVeUyar;
            }

            // --- 5) Toplu değişim hızı analizi (kitle şifreleme davranışı) ---
            _degisimHavuzu.Enqueue((now, surecAdi));
            while (_degisimHavuzu.TryPeek(out var eski) &&
                   (now - eski.zaman).TotalSeconds > _cfg.TopluDegisimPenceresiSn)
                _degisimHavuzu.TryDequeue(out _);

            if (_degisimHavuzu.Count >= _cfg.TopluDegisimEsigi)
            {
                string enAktif = _degisimHavuzu.GroupBy(x => x.surec)
                                              .OrderByDescending(g => g.Count())
                                              .First().Key;
                TehditTespitEdildi?.Invoke(new ThreatEvent
                {
                    Tip = "Ransomware", Kaynak = enAktif, Hedef = dosyaYolu,
                    Skor = 85, Seviye = ThreatLevel.Kritik,
                    Detay = $"{_cfg.TopluDegisimPenceresiSn} sn içinde " +
                            $"{_degisimHavuzu.Count} toplu dosya değişimi (kitle şifreleme deseni)."
                });
                return DetectorAction.YedekleVeUyar;
            }

            // --- 6) Uzantı/MIME spoofing (gizli PE) ---
            if (!EntropyAnalyzer.ImzaUzantiUyumuVar(dosyaYolu, out string imza))
            {
                TehditTespitEdildi?.Invoke(new ThreatEvent
                {
                    Tip = "Spoof", Kaynak = surecAdi, Hedef = dosyaYolu,
                    Skor = 75, Seviye = ThreatLevel.Yuksek,
                    Detay = $"Uzantı '{ext}' ama gerçek imza: {imza} — gizli çalıştırılabilir!"
                });
                return DetectorAction.Karantina;
            }

            return DetectorAction.Guvenli;
        }
    }

    public enum DetectorAction { Guvenli, YedekleVeUyar, Karantina, KarantinaVeKilitle }

    // ================================================================
    // 8. PHISHING / URL ANALİZÖRÜ
    // ================================================================
    public class PhishingAnalyzer
    {
        private readonly ShieldConfig _cfg;

        private static readonly string[] PhishingAnahtarlar =
        {
            "giris", "login", "signin", "hesap", "sifre", "dogrula",
            "verify", "secure", "account", "update", "confirm",
            "banka", "kredi", "odeme", "fatura", "win", "kazandiniz",
            "prize", "refund", "billing", "invoice", "paypal-secure"
        };

        public PhishingAnalyzer(ShieldConfig cfg) => _cfg = cfg;

        public double UrlSkorla(string url, out List<string> gerekceler)
        {
            gerekceler = new List<string>();
            double skor = 0;

            if (!Uri.TryCreate(url, UriKind.Absolute, out var uri) ||
                (uri.Scheme != "https" && uri.Scheme != "http"))
            {
                gerekceler.Add("Geçersiz/şüpheli URL formatı");
                return 100;
            }

            // HTTPS zorunluluğu
            if (uri.Scheme != "https")
            { skor += 25; gerekceler.Add("HTTPS yok (şifrelenmemiş bağlantı)"); }

            // IP tabanlı domain
            if (IPAddress.TryParse(uri.Host, out _))
            { skor += 40; gerekceler.Add("Domain yerine çıplak IP adresi"); }

            // Punycode / homograph saldırısı
            if (uri.Host.Contains("xn--"))
            { skor += 35; gerekceler.Add("Punycode domain (homograph saldırısı riski)"); }

            // Çok fazla alt etiket
            if (uri.Host.Split('.').Length > 4)
            { skor += 15; gerekceler.Add("Aşırı alt domain derinliği"); }

            // '@' tuzağı: gerçek hedef @'den sonra gizlenir
            if (url.Contains('@'))
            { skor += 30; gerekceler.Add("URL içinde '@' karakteri (klasik phishing tuzağı)"); }

            // Güvenilir domain içinde marka geçiyor ama domain bambaşka
            string host = uri.Host.ToLowerInvariant();
            foreach (string guvenilir in _cfg.GuvenilirDomainler)
            {
                string marka = guvenilir.Split('.')[0];
                if (host.Contains(marka) && !host.EndsWith(guvenilir))
                {
                    skor += 45;
                    gerekceler.Add($"'{marka}' markası taklit ediliyor: {host}");
                    break;
                }
            }

            // Phishing anahtar kelimeleri
            string kucuk = url.ToLowerInvariant();
            int eslesen = PhishingAnahtarlar.Count(k => kucuk.Contains(k));
            if (eslesen >= 2)
            { skor += 20; gerekceler.Add($"Phishing anahtar kelime yoğunluğu ({eslesen})"); }
            else if (eslesen == 1)
            { skor += 8; gerekceler.Add("Phishing anahtar kelime bulundu"); }

            // Kısaltma servisleri
            string[] kisaltma = { "bit.ly", "tinyurl", "goo.gl", "t.co", "is.gd", "cutt.ly" };
            if (kisaltma.Any(k => host.Contains(k)))
            { skor += 20; gerekceler.Add("Link kısaltma servisi (hedef gizlenmiş)"); }

            // Uzun, rastgele path
            if (uri.AbsolutePath.Length > 80)
            { skor += 10; gerekceler.Add("Anormallik uzun path"); }

            return Math.Min(skor, 100);
        }

        public ThreatLevel SkorToSeviye(double skor) => skor switch
        {
            >= 70 => ThreatLevel.Kritik,
            >= 45 => ThreatLevel.Yuksek,
            >= 25 => ThreatLevel.Orta,
            _     => ThreatLevel.Dusuk
        };
    }

    // ================================================================
    // 9. SÜREÇ İZLEYİCİ (anti-tamper + şüpheli komut tespiti)
    // ================================================================
    public class ProcessSentinel
    {
        private readonly ShieldConfig _cfg;
        public event Action<ThreatEvent>? TehditTespitEdildi;
        private readonly HashSet<int> _raporlanan = new();

        public ProcessSentinel(ShieldConfig cfg) => _cfg = cfg;

        public void TaramaTur()
        {
            foreach (var p in Process.GetProcesses())
            {
                try
                {
                    string ad = p.ProcessName.ToLowerInvariant();
                    if (!_cfg.SupheliSurecAdlari.Contains(ad)) continue;
                    if (!_raporlanan.Add(p.Id)) continue;

                    string cmdline = KomutSatiriniAl(p.Id) ?? "";

                    // Ransomware'in klasik gölge kopya silme komutu
                    string[] olumluKomutlar =
                    {
                        "vssadmin delete shadows", "wbadmin delete",
                        "bcdedit /set recoveryenabled no",
                        "bcdedit /set ignoreallfailures",
                        "wevtutil cl", "cipher /w",
                        "remove-itemitem -path", "remove-itemitem"
                    };
                    if (olumluKomutlar.Any(k => cmdline.ToLowerInvariant().Contains(k)))
                    {
                        TehditTespitEdildi?.Invoke(new ThreatEvent
                        {
                            Tip = "Ransomware", Kaynak = $"{ad} (PID {p.Id})",
                            Hedef = "Sistem yedekleri", Skor = 98,
                            Seviye = ThreatLevel.Kritik,
                            Detay = $"Yıkıcı komut tespit edildi: {Truncate(cmdline, 200)}"
                        });
                        // Savunma: süreci askıya al
                        AskiyaAl(p);
                        continue;
                    }

                    // Script süreçlerinin korumalı dizinlere erişimi
                    if ((ad is "wscript" or "cscript" or "mshta") && _cfg.KorumaliDizinler.Count > 0)
                    {
                        TehditTespitEdildi?.Invoke(new ThreatEvent
                        {
                            Tip = "Supheli", Kaynak = $"{ad} (PID {p.Id})",
                            Hedef = "-", Skor = 40, Seviye = ThreatLevel.Orta,
                            Detay = "Script-interpreter süreci aktif (VBS/JS dropper riski)."
                        });
                    }
                }
                catch { /* erişim yok, atla */ }
                finally { p.Dispose(); }
            }
        }

        private static string? KomutSatiriniAl(int pid)
        {
            try
            {
                // WMI yerine .NET yerel: PowerShell'i yormamak için WMI sorgusu bir kez
                using var searcher = new System.Management.ManagementObjectSearcher(
                    $"SELECT CommandLine FROM Win32_Process WHERE ProcessId = {pid}");
                return searcher.Cast<System.Management.ManagementObject>()
                               .FirstOrDefault()?["CommandLine"]?.ToString();
            }
            catch { return null; }
        }

        private void AskiyaAl(Process p)
        {
            try
            {
                // NtSuspendModule yerine .NET'in doğal yolu: öncelik düşür + blokla
                // (tam suspend için kernel32 P/Invoke gerekir; güvenli alternatif)
                p.PriorityClass = ProcessPriorityClass.Idle;
                ShieldLog.Alert($"Tehlikeli süreç düşük önceliğe çekildi: {p.ProcessName} (PID {p.Id})");
            }
            catch { }
        }

        private static string Truncate(string s, int n) =>
            s.Length <= n ? s : s[..n] + "...";
    }

    // ================================================================
    // 10. DOSYA SİSTEMİ İZLEYİCİ (FileSystemWatcher katmanı)
    // ================================================================
    public class FileSystemSentinel
    {
        private readonly ShieldConfig _cfg;
        private readonly RansomwareDetector _detector;
        private readonly BackupQuarantineEngine _yedek;
        private readonly List<FileSystemWatcher> _watchers = new();
        public event Action<ThreatEvent>? TehditTespitEdildi;

        public FileSystemSentinel(ShieldConfig cfg, RansomwareDetector det, BackupQuarantineEngine yedek)
        { _cfg = cfg; _detector = det; _yedek = yedek; }

        public void Baslat()
        {
            foreach (var dizin in _cfg.KorumaliDizinler)
            {
                if (string.IsNullOrEmpty(dizin) || !Directory.Exists(dizin))
                { ShieldLog.Warn($"Dizin bulunamadı, izlenmeyecek: {dizin}"); continue; }

                var fw = new FileSystemWatcher(dizin)
                {
                    IncludeSubdirectories = true,
                    NotifyFilter = NotifyFilters.FileName | NotifyFilters.LastWrite
                                 | NotifyFilters.CreationTime | NotifyFilters.Size,
                    InternalBufferSize = 64 * 1024
                };
                fw.Created += (_, e) => Isle(e.FullPath, "OLUSTURMA");
                fw.Changed += (_, e) => Isle(e.FullPath, "DEGISIKLIK");
                fw.Renamed += (_, e) => Isle(e.FullPath, "YENIDEN_ADLANDIRMA");
                fw.Error   += (_, e) => ShieldLog.Warn($"Watcher hatası ({dizin}): {e.GetException().Message}");

                fw.EnableRaisingEvents = true;
                _watchers.Add(fw);
                ShieldLog.Ok($"İzleme başlatıldı: {dizin}");
            }
        }

        private void Isle(string yol, string olayTipi)
        {
            try
            {
                if (Directory.Exists(yol)) return;
                string ext = Path.GetExtension(yol).ToLowerInvariant();
                // Sadece kritik uzantıları ve tüm yeni dosyaları değerlendir
                if (!_cfg.KritikUzantilar.Contains(ext) && !_cfg.RansomUzantilari.Contains(ext))
                    return;

                string süreç = AktifSurecTahmini();
                ShieldLog.Debug($"[{olayTipi}] {yol} (süreç≈{süreç})");

                var aksiyon = _detector.OlayIsle(yol, süreç);

                switch (aksiyon)
                {
                    case DetectorAction.Guvenli:
                        break;

                    case DetectorAction.YedekleVeUyar:
                        _yedek.SifreliYedekAl(yol, out _);
                        break;

                    case DetectorAction.Karantina:
                        _yedek.KarantinayaAl(yol, out _);
                        break;

                    case DetectorAction.KarantinaVeKilitle:
                        // ÖNCE şifreli yedek al, sonra karantinaya al
                        if (_yedek.SifreliYedekAl(yol, out string yedekYolu))
                            ShieldLog.Ok($"Kritik dosya güvenli yedeklendi: {yedekYolu}");
                        _yedek.KarantinayaAl(yol, out _);
                        break;
                }
            }
            catch (IOException) { /* dosya kilitli — normal */ }
            catch (Exception ex) { ShieldLog.Debug($"İşleme hatası ({yol}): {ex.Message}"); }
        }

        private static string AktifSurecTahmini()
        {
            // En yüksek CPU'lu şüpheli süreci tahmin et (tam attribution için ETW gerekir)
            try
            {
                return Process.GetProcesses()
                              .OrderByDescending(p => { try { return p.TotalProcessorTime; } catch { return TimeSpan.Zero; } })
                              .FirstOrDefault()?.ProcessName ?? "bilinmiyor";
            }
            catch { return "bilinmiyor"; }
        }

        public void Durdur()
        {
            foreach (var w in _watchers) { w.EnableRaisingEvents = false; w.Dispose(); }
            _watchers.Clear();
        }
    }

    // ================================================================
    // 11. PANOPTİK — ETKİLEŞİMLİ PHISHING TARAYICI KONSOLU
    // ================================================================
    public class PhishingScannerConsole
    {
        private readonly PhishingAnalyzer _analizor;
        public PhishingScannerConsole(PhishingAnalyzer a) => _analizor = a;

        public void Calistir()
        {
            Console.WriteLine();
            ShieldLog.Info("=== PHISHING / URL TARAYICI ===");
            ShieldLog.Info("Taramak istediğiniz URL'yi girin (çıkmak için boş ENTER):");

            while (true)
            {
                Console.Write("\n  URL > ");
                string? url = Console.ReadLine()?.Trim();
                if (string.IsNullOrEmpty(url)) break;

                double skor = _analizor.UrlSkorla(url, out var gerekceler);
                var seviye = _analizor.SkorToSeviye(skor);

                switch (seviye)
                {
                    case ThreatLevel.Kritik:
                        ShieldLog.Alert($"TEHLİKE ({skor:F0}/100) — BU LİNKE GİRMEYİN!");
                        break;
                    case ThreatLevel.Yuksek:
                        ShieldLog.Warn($"YÜKSEK RİSK ({skor:F0}/100) — çok şüpheli.");
                        break;
                    case ThreatLevel.Orta:
                        ShieldLog.Warn($"ORTA RİSK ({skor:F0}/100) — dikkatli olun.");
                        break;
                    default:
                        ShieldLog.Ok($"DÜŞÜK RİSK ({skor:F0}/100) — görece güvenli görünüyor.");
                        break;
                }

                foreach (var g in gerekceler)
                    ShieldLog.Info($"   • {g}");
                if (gerekceler.Count == 0)
                    ShieldLog.Info("   • Belirgin tespit bulgusu yok.");
            }
        }
    }

    // ================================================================
    // 12. YEDEK KURTARMA KONSOLU
    // ================================================================
    public static class RestoreConsole
    {
        public static void Calistir(BackupQuarantineEngine yedek, string yedekDizini)
        {
            ShieldLog.Info("=== YEDEK KURTARMA MODU ===");
            var dosyalar = new DirectoryInfo(yedekDizini)
                .GetFiles("*.mkenc").OrderBy(f => f.Name).ToArray();

            if (dosyalar.Length == 0)
            { ShieldLog.Warn("Yedek bulunamadı."); return; }

            for (int i = 0; i < dosyalar.Length; i++)
                Console.WriteLine($"  [{i}] {dosyalar[i].Name}");

            Console.Write("\n  Geri yüklenecek numara (iptal = ENTER): ");
            if (!int.TryParse(Console.ReadLine(), out int secim) ||
                secim < 0 || secim >= dosyalar.Length)
            { ShieldLog.Info("İptal edildi."); return; }

            string orijinalAd = dosyalar[secim].Name;
            int altCizgi = orijinalAd.IndexOf('_');
            string temizAd = altCizgi >= 0 ? orijinalAd[(altCizgi + 1)..] : orijinalAd;
            temizAd = temizAd.Replace(".mkenc", "");

            string hedef = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.Desktop), temizAd);

            if (yedek.GeriYukle(dosyalar[secim].FullName, hedef))
                ShieldLog.Ok($"Masaüstüne geri yüklendi: {hedef}");
        }
    }

    // ================================================================
    // 13. ANA ORKESTRATÖR
    // ================================================================
    public class MarkOsDefenseSuite
    {
        private readonly ShieldConfig _cfg = new();
        private HoneypotEngine _honeypot = null!;
        private BackupQuarantineEngine _yedek = null!;
        private RansomwareDetector _detector = null!;
        private FileSystemSentinel _fsSentinel = null!;
        private PhishingAnalyzer _phishing = null!;
        private ProcessSentinel _surecSentinel = null!;
        private CancellationTokenSource _cts = new();

        public void Baslat()
        {
            Banner();

            _yedek      = new BackupQuarantineEngine(_cfg);
            _honeypot   = new HoneypotEngine(_cfg);
            _detector   = new RansomwareDetector(_cfg, _honeypot, _yedek);
            _fsSentinel = new FileSystemSentinel(_cfg, _detector, _yedek);
            _phishing   = new PhishingAnalyzer(_cfg);
            _surecSentinel = new ProcessSentinel(_cfg);

            // Tehlike event'lerini konsola bağla
            void TehditYazdir(ThreatEvent t)
            {
                Console.WriteLine();
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine("  ╔══════════════════════════════════════════════════╗");
                Console.WriteLine($"  ║ TEHDİT TESPİT EDİLDİ — {t.Seviye}                     ║");
                Console.WriteLine("  ╚══════════════════════════════════════════════════╝");
                Console.ResetColor();
                ShieldLog.Alert($"Tip   : {t.Tip}");
                ShieldLog.Alert($"Kaynak: {t.Kaynak}");
                ShieldLog.Alert($"Hedef : {t.Hedef}");
                ShieldLog.Alert($"Skor  : {t.Skor}/100");
                ShieldLog.Alert($"Detay : {t.Detay}");
                ShieldLog.Info($"Olay raporu → {Path.Combine(AppContext.BaseDirectory, "MarkOs_Logs")}");

                // Olay JSON olarak kaydet (SIEM entegrasyonu için)
                File.WriteAllText(
                    Path.Combine(AppContext.BaseDirectory, "MarkOs_Logs",
                        $"incident_{t.Id}.json"), t.ToJson());
            }

            _detector.TehditTespitEdildi += TehditYazdir;
            _surecSentinel.TehditTespitEdildi += TehditYazdir;
            _fsSentinel.TehditTespitEdildi += TehditYazdir;

            // 1) Honeypot kur
            _honeypot.TuzaklariYerlestir();

            // 2) Dosya sistemi izleyicileri başlat
            _fsSentinel.Baslat();

            // 3) Süreç izleyici arka plan döngüsü
            if (_cfg.SurecIzleyiciAktif)
            {
                Task.Run(async () =>
                {
                    while (!_cts.IsCancellationRequested)
                    {
                        try { _surecSentinel.TaramaTur(); } catch { }
                        _yedek.EskiYedekleriTemizle();
                        await Task.Delay(15_000, _cts.Token);
                    }
                });
            }

            // 4) Ana menü döngüsü
            MenuDongusu();
        }

        private void MenuDongusu()
        {
            while (!_cts.IsCancellationRequested)
            {
                Console.WriteLine();
                Console.ForegroundColor = ConsoleColor.Cyan;
                Console.WriteLine("  ┌─────────── MARKOS KONTROL PANELİ ───────────┐");
                Console.WriteLine("  │ [1] URL / Phishing taraması yap             │");
                Console.WriteLine("  │ [2] Şifreli yedekten dosya kurtar           │");
                Console.WriteLine("  │ [3] Honeypot durumunu göster                │");
                Console.WriteLine("  │ [4] Sistem durumu raporu                    │");
                Console.WriteLine("  │ [Q] Kalkanı kapat                           │");
                Console.WriteLine("  └─────────────────────────────────────────────┘");
                Console.ResetColor();
                Console.Write("  Seçim > ");

                switch (Console.ReadLine()?.Trim().ToUpperInvariant())
                {
                    case "1": new PhishingScannerConsole(_phishing).Calistir(); break;
                    case "2": RestoreConsole.Calistir(_yedek, _cfg.YedekDizini); break;
                    case "3":
                        foreach (var t in _honeypot.TuzakListesi)
                            Console.WriteLine($"   🍯 {t}");
                        break;
                    case "4": DurumRaporu(); break;
                    case "Q":
                        _cts.Cancel();
                        _fsSentinel.Durdur();
                        ShieldLog.Ok("MarkOs Defense Suite kapatıldı. Güvende kalın!");
                        return;
                }
            }
        }

        private static void DurumRaporu()
        {
            ShieldLog.Info("--- SİSTEM DURUM RAPORU ---");
            ShieldLog.Info($"İşletim Sistemi : {Environment.OSVersion}");
            ShieldLog.Info($"Kullanıcı       : {Environment.UserName}");
            ShieldLog.Info($"Makine          : {Environment.MachineName}");
            ShieldLog.Info($"64-bit          : {Environment.Is64BitOperatingSystem}");
            ShieldLog.Info($"Aktif süreç     : {Process.GetProcesses().Length}");
            ShieldLog.Info($".NET Runtime    : {Environment.Version}");

            // Windows Defender durumu
            try
            {
                var psi = new ProcessStartInfo("powershell",
                    "-NoProfile -Command \"(Get-MpComputerStatus).RealTimeProtectionEnabled\"")
                {
                    CreateNoWindow = true, UseShellExecute = false,
                    RedirectStandardOutput = true
                };
                using var p = Process.Start(psi)!;
                string cikti = p.StandardOutput.ReadToEnd().Trim();
                ShieldLog.Info($"Defender RTP    : {cikti}");
            }
            catch { ShieldLog.Info("Defender RTP    : sorgulanamadı"); }
        }

        private static void Banner()
        {
            Console.Clear();
            Console.ForegroundColor = ConsoleColor.Cyan;
            Console.WriteLine("""
            ╔═══════════════════════════════════════════════════════════════╗
            ║      MARKOS ENTERPRISE DEFENSE SUITE v2026.1                  ║
            ║      Anti-Ransomware + Anti-Phishing Realtime Shield          ║
            ║───────────────────────────────────────────────────────────────║
            ║  🛡  Honeypot Tuzakları        : AKTİF                        ║
            ║  🛡  Gerçek Zamanlı FS İzleme  : AKTİF                        ║
            ║  🛡  Entropi Analizi           : AKTİF                        ║
            ║  🛡  Şifreli Yedekleme         : AKTİF (AES-256)              ║
            ║  🛡  Phishing URL Tarayıcı     : HAZIR                        ║
            ║  🛡  Süreç Davranış Sentinel   : AKTİF                        ║
            ╚═══════════════════════════════════════════════════════════════╝
            """);
            Console.ResetColor();
            ShieldLog.Ok("MarkOs Defense Suite başlatılıyor...");
        }
    }

    // ================================================================
    // 14. GİRİŞ NOKTASI
    // ================================================================
    public static class Program
    {
        public static void Main()
        {
            Console.OutputEncoding = Encoding.UTF8;
            try
            {
                new MarkOsDefenseSuite().Baslat();
            }
            catch (Exception ex)
            {
                ShieldLog.Alert($"Kritik başlatma hatası: {ex.Message}");
            }
        }
    }
}
