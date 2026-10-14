/* ===================================================================
 * PROJE ADI   : MarkOs Enterprise Anti-Cheat & Honeypot Suite v2026
 * GELİŞTİRİCİ : memetcanwq31-ship-it (Beyaz Şapkalı Elit Hacker)
 * MİMARÎ      : C# (.NET 8.0 High-Performance System Programming)
 * LİSANS      : MIT Open Source License (Halka Açık / Meşru Proje)
 * STATÜ       : %100 YASAL EĞİTİM VE SİBER SAVUNMA FRAMEWORKÜ
 * ===================================================================
 */

using System;
using System.Text;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;

namespace MarkOsSecurity.AntiCheat
{
    #region EKRAN VE RENK YÖNETİM MOTORU
    /// <summary>
    /// MarkOs terminal ekranının kurumsal loglarını ve renk paletini yöneten çekirdek sınıf.
    /// Thread-safe lock mekanizması ile çakışmasız çıktı garantisi verir.
    /// </summary>
    public static class MarkOsLogger
    {
        private static readonly object _lockObject = new object();
        private static long _logSayaci = 0;

        public static long ToplamLogSayisi => Interlocked.Read(ref _logSayaci);

        private static void Yaz(ConsoleColor renk, string seviye, string mesaj)
        {
            lock (_lockObject)
            {
                Console.ForegroundColor = renk;
                Console.WriteLine($"[{DateTime.Now:HH:mm:ss.fff}] [{seviye}] {mesaj}");
                Console.ResetColor();
                Interlocked.Increment(ref _logSayaci);
            }
        }

        public static void Info(string mesaj)    => Yaz(ConsoleColor.Cyan,    "INFO", mesaj);
        public static void Success(string mesaj) => Yaz(ConsoleColor.Green,   "🛡️ SUCCESS", mesaj);
        public static void Warning(string mesaj) => Yaz(ConsoleColor.Yellow,  "⚠️ WARNING", mesaj);
        public static void Alert(string mesaj)   => Yaz(ConsoleColor.Red,     "🚨 ALERT - TRAP ACTIVATED", mesaj);
        public static void Debug(string mesaj)   => Yaz(ConsoleColor.DarkGray,"🔍 DEBUG", mesaj);
        public static void Critical(string mesaj)=> Yaz(ConsoleColor.DarkRed, "☠️ CRITICAL", mesaj);

        public static void Banner(string baslik)
        {
            lock (_lockObject)
            {
                Console.ForegroundColor = ConsoleColor.Magenta;
                Console.WriteLine();
                Console.WriteLine("═══════════════════════════════════════════════════════════════");
                Console.WriteLine($"  {baslik}");
                Console.WriteLine("═══════════════════════════════════════════════════════════════");
                Console.ResetColor();
            }
        }
    }
    #endregion

    #region ENUM SABİTLERİ
    public enum TehditSeviyesi
    {
        Temiz = 0,
        Supheli = 1,
        Riskli = 2,
        Tehlikeli = 3,
        KritikTehdit = 4
    }

    public enum CezaTipi
    {
        Uyari = 0,
        GeciciBan = 1,
        KaliciBan = 2,
        TersYansitma = 3,
        SurecIzolasyonu = 4
    }
    #endregion

    #region VERİ YAPILARI VE AĞ MODELLERİ
    /// <summary>
    /// Ağ üzerinden gelen veya simüle edilen mermi/oyuncu veri paketlerinin veri modeli.
    /// SHA256 bütünlük imzası ile Zero Trust doğrulaması destekler.
    /// </summary>
    public class NetworkPacket
    {
        public string TokenId { get; }
        public string OyuncuAdi { get; }
        public int GelenHasar { get; }
        public bool HileModuAktifMi { get; }
        public string PaketHash { get; }
        public DateTime ZamanDamgasi { get; }
        public string KaynakIp { get; }
        public int PingMs { get; }
        public TehditSeviyesi TehditDerecesi { get; set; }

        public NetworkPacket(string oyuncuAdi, int gelenHasar, bool hileModuAktifMi,
                             string kaynakIp = "127.0.0.1", int pingMs = 25)
        {
            TokenId = Guid.NewGuid().ToString("N").Substring(0, 8);
            OyuncuAdi = oyuncuAdi;
            GelenHasar = gelenHasar;
            HileModuAktifMi = hileModuAktifMi;
            ZamanDamgasi = DateTime.UtcNow;
            KaynakIp = kaynakIp;
            PingMs = pingMs;
            PaketHash = HesaplaSHA256(oyuncuAdi + gelenHasar + hileModuAktifMi + ZamanDamgasi.Ticks);
        }

        private static string HesaplaSHA256(string girdi)
        {
            byte[] girdiBaytlari = Encoding.UTF8.GetBytes(girdi);
            byte[] hashBaytlari = SHA256.HashData(girdiBaytlari);
            StringBuilder sb = new StringBuilder(64);
            foreach (byte b in hashBaytlari)
                sb.Append(b.ToString("x2"));
            return sb.ToString();
        }

        public string KisaHash => PaketHash.Substring(0, 16);
    }

    /// <summary>
    /// Hilecinin kendi süreç matrisine yansıtılacak olan ceza veri modeli.
    /// </summary>
    public class TrapReflectionEventArgs : EventArgs
    {
        public string HileciAdi { get; }
        public int YansitilanHasar { get; }
        public string KayitId { get; }
        public CezaTipi Ceza { get; }
        public TehditSeviyesi Seviye { get; }
        public DateTime OlayZamani { get; }

        public TrapReflectionEventArgs(string hileciAdi, int yansitilanHasar,
                                       string kayitId, CezaTipi ceza, TehditSeviyesi seviye)
        {
            HileciAdi = hileciAdi;
            YansitilanHasar = yansitilanHasar;
            KayitId = kayitId;
            Ceza = ceza;
            Seviye = seviye;
            OlayZamani = DateTime.UtcNow;
        }
    }

    /// <summary>
    /// Hileci profili: tekrarlanan ihlalleri takip ederek kademeli ceza sistemi besler.
    /// </summary>
    public class HileciProfili
    {
        public string OyuncuAdi { get; }
        public int IhlalSayisi { get; private set; }
        public int ToplamYansitilanHasar { get; private set; }
        public DateTime IlkIhlal { get; private set; }
        public DateTime SonIhlal { get; private set; }
        public List<string> AdliKayitlar { get; } = new();

        public HileciProfili(string oyuncuAdi)
        {
            OyuncuAdi = oyuncuAdi;
            IlkIhlal = DateTime.UtcNow;
        }

        public void IhlalEkle(string kayitId, int hasar)
        {
            IhlalSayisi++;
            ToplamYansitilanHasar += hasar;
            SonIhlal = DateTime.UtcNow;
            AdliKayitlar.Add(kayitId);
        }

        public CezaTipi OnerilenCeza()
        {
            return IhlalSayisi switch
            {
                1 => CezaTipi.Uyari,
                2 => CezaTipi.GeciciBan,
                >= 3 => CezaTipi.KaliciBan,
                _ => CezaTipi.Uyari
            };
        }
    }
    #endregion

    #region İSTATİSTİK MOTORU
    /// <summary>
    /// Çalışma zamanı metriklerini thread-safe olarak toplayan telemetri sınıfı.
    /// </summary>
    public class TelemetriMotoru
    {
        private long _toplamPaket;
        private long _temizPaket;
        private long _hileliPaket;
        private long _yansitilanToplamHasar;

        public void PaketKaydet(bool hileli)
        {
            Interlocked.Increment(ref _toplamPaket);
            if (hileli) Interlocked.Increment(ref _hileliPaket);
            else Interlocked.Increment(ref _temizPaket);
        }

        public void HasarKaydet(int hasar) => Interlocked.Add(ref _yansitilanToplamHasar, hasar);

        public void RaporYaz()
        {
            MarkOsLogger.Banner("MARKOS TELEMETRİ RAPORU");
            MarkOsLogger.Info($"Toplam İşlenen Paket       : {Interlocked.Read(ref _toplamPaket)}");
            MarkOsLogger.Success($"Dürüst (Temiz) Paket       : {Interlocked.Read(ref _temizPaket)}");
            MarkOsLogger.Alert($"Hileli (Trap'e Düşen)      : {Interlocked.Read(ref _hileliPaket)}");
            MarkOsLogger.Warning($"Yansıtılan Toplam Hasar    : {Interlocked.Read(ref _yansitilanToplamHasar)} HP");
            MarkOsLogger.Info($"Toplam Üretilen Log        : {MarkOsLogger.ToplamLogSayisi}");

            double tespitOrani = Interlocked.Read(ref _toplamPaket) > 0
                ? (double)Interlocked.Read(ref _hileliPaket) / Interlocked.Read(ref _toplamPaket) * 100.0
                : 0.0;
            MarkOsLogger.Info($"Tespit Oranı               : %{tespitOrani:F2}");
        }
    }
    #endregion

    #region AĞ PAKET SÜZGECİ VE TERS KÖŞE BAL KÜPÜ MOTORU
    /// <summary>
    /// Hilecileri yakalayan ve sahte istekleri kendi süreçlerine geri yansıtan ana motor.
    /// ConcurrentQueue ile lock-free asenkron paket işleme, SHA256 bütünlük doğrulaması
    /// ve kademeli ceza profilleme sistemi içerir.
    /// </summary>
    public class MarkOsTrapEngine
    {
        private readonly ConcurrentQueue<NetworkPacket> _packetQueue = new();
        private readonly ConcurrentDictionary<string, HileciProfili> _hileciProfilleri = new();
        private readonly TelemetriMotoru _telemetri;
        private readonly int _islemGecikmesiMs;

        public event EventHandler<TrapReflectionEventArgs>? OnTrapTriggered;
        public event EventHandler<string>? OnOyuncuBanlandi;

        public MarkOsTrapEngine(TelemetriMotoru telemetri, int islemGecikmesiMs = 400)
        {
            _telemetri = telemetri;
            _islemGecikmesiMs = islemGecikmesiMs;
        }

        public IReadOnlyDictionary<string, HileciProfili> Profiller => _hileciProfilleri;

        public void KuyrugaPaketEkle(NetworkPacket paket)
        {
            _packetQueue.Enqueue(paket);
            _telemetri.PaketKaydet(paket.HileModuAktifMi);
            MarkOsLogger.Info($"Ağ Giriş Katmanı: Yeni paket kuyruğa alındı. ID: {paket.TokenId} | Kaynak: {paket.OyuncuAdi} | IP: {paket.KaynakIp} | Ping: {paket.PingMs}ms");
        }

        public async Task StartProcessingAsync(CancellationToken cancellationToken)
        {
            MarkOsLogger.Success("MarkOs Asenkron Bal Küpü (Honeypot) Filtre Motoru Ateşlendi!");

            while (!cancellationToken.IsCancellationRequested)
            {
                if (_packetQueue.TryDequeue(out var mevcutPaket))
                {
                    // 1. Ağ Kriptoloji Doğrulaması (SHA256 Integrity Check)
                    MarkOsLogger.Debug($"Veri Bütünlüğü Denetleniyor... Paket Hash: {mevcutPaket.KisaHash}");

                    if (!PaketButunlugunuDogrula(mevcutPaket))
                    {
                        MarkOsLogger.Critical($"PAKET BOZUK! Hash doğrulaması başarısız. Paket karantinaya alındı: {mevcutPaket.TokenId}");
                        continue;
                    }

                    // 2. Hile Kontrolü Katmanı
                    if (mevcutPaket.HileModuAktifMi)
                    {
                        MarkOsLogger.Alert($"Anomali Yakalandı! Kullanıcı '{mevcutPaket.OyuncuAdi}' illegal mermi hilesi kullanıyor.");
                        TetikleTrapEvent(mevcutPaket);
                    }
                    else
                    {
                        MarkOsLogger.Success($"Dürüst Oyuncu Doğrulandı. Kullanıcı: {mevcutPaket.OyuncuAdi} | Hasar: {mevcutPaket.GelenHasar} HP");
                    }
                }

                // İşlemciyi yormamak için kısa asenkron duraklama (Zero Trust Kaynak Yönetimi)
                await Task.Delay(_islemGecikmesiMs, cancellationToken);
            }
        }

        private static bool PaketButunlugunuDogrula(NetworkPacket paket)
        {
            // Simülasyon: hash uzunluğu ve token kontrolü
            return !string.IsNullOrEmpty(paket.PaketHash)
                   && paket.PaketHash.Length == 64
                   && !string.IsNullOrEmpty(paket.TokenId);
        }

        protected virtual void TetikleTrapEvent(NetworkPacket paket)
        {
            HileciProfili profil = _hileciProfilleri.GetOrAdd(paket.OyuncuAdi, ad => new HileciProfili(ad));
            string kayitId = $"ADLI-{paket.TokenId}-{DateTime.UtcNow:yyyyMMddHHmmss}";
            profil.IhlalEkle(kayitId, paket.GelenHasar);

            CezaTipi ceza = profil.OnerilenCeza();
            _telemetri.HasarKaydet(paket.GelenHasar);

            var args = new TrapReflectionEventArgs(paket.OyuncuAdi, paket.GelenHasar, kayitId, ceza, TehditSeviyesi.KritikTehdit);
            OnTrapTriggered?.Invoke(this, args);

            if (ceza == CezaTipi.KaliciBan)
            {
                OnOyuncuBanlandi?.Invoke(this, paket.OyuncuAdi);
            }
        }
    }
    #endregion

    #region BAN VE CEZA YÖNETİM MERKEZİ
    /// <summary>
    /// Banlı oyuncuları ve ceza geçmişini yöneten merkezi kayıt defteri.
    /// </summary>
    public class BanYonetimMerkezi
    {
        private readonly ConcurrentDictionary<string, DateTime> _banListesi = new();

        public void Banla(string oyuncuAdi, CezaTipi ceza)
        {
            _banListesi[oyuncuAdi] = DateTime.UtcNow;
            MarkOsLogger.Critical($"[BAN MERKEZİ] '{oyuncuAdi}' kalıcı ban listesine eklendi! Ceza Tipi: {ceza}");
        }

        public bool BanliMi(string oyuncuAdi) => _banListesi.ContainsKey(oyuncuAdi);

        public void RaporYaz()
        {
            MarkOsLogger.Banner("AKTİF BAN LİSTESİ");
            if (_banListesi.IsEmpty)
            {
                MarkOsLogger.Success("Ban listesi temiz. Sistem sağlam.");
                return;
            }
            foreach (var kv in _banListesi)
                MarkOsLogger.Alert($"🚫 {kv.Key} | Ban Zamanı: {kv.Value:HH:mm:ss} UTC");
        }
    }
    #endregion

    #region PROGRAM ANA GİRİŞ KAPISI (MAIN ENTERPRISE INTERFACE)
    class Program
    {
        static async Task Main(string[] args)
        {
            Console.Clear();
            Console.WriteLine("=====================================================================");
            Console.WriteLine("    MARKOS C# OPEN-SOURCE ANTI-CHEAT & HONEYPOT FRAMEWORK v2026.2    ");
            Console.WriteLine("=====================================================================");
            Console.WriteLine("  [👤] GELİŞTİRİCİ : memetcanwq31-ship-it | LİSANS: MIT OpenSource  ");
            Console.WriteLine("  [🛡️] STANDART    : BTK Akademi Standartları & Mor Takım Defansı    ");
            Console.WriteLine("=====================================================================\n");

            // 1. Motorun ve yardımcı servislerin ayağa kaldırılması
            TelemetriMotoru telemetri = new();
            MarkOsTrapEngine trapEngine = new(telemetri);
            BanYonetimMerkezi banMerkezi = new();
            CancellationTokenSource cts = new();

            // İşte o şanlı "Ne atarsa hileyi açana dönsün" event abonesi babuş!
            trapEngine.OnTrapTriggered += (sender, eventArgs) =>
            {
                Console.WriteLine("\n---------------------------------------------------------------------");
                MarkOsLogger.Alert($"[MÜDAHALE MÜHÜRÜ] -> Adli Kayıt ID: {eventArgs.KayitId}");
                MarkOsLogger.Alert($"Hileci '{eventArgs.HileciAdi}' kendi açtığı kuyuya düştü!");
                MarkOsLogger.Alert($"İllegal fırlatılan hasar tersine döndü: -{eventArgs.YansitilanHasar} HP hasar hilecinin kendisine uygulandı!");
                MarkOsLogger.Warning($"Uygulanan Ceza: {eventArgs.Ceza}");
                MarkOsLogger.Success($"[🛡️ MOR TAKIM] Sunucu dengesi korundu. Hileci süreci 'localhost' üzerinde izole edildi.");
                Console.WriteLine("---------------------------------------------------------------------\n");
            };

            // Kalıcı ban tetiklendiğinde ban merkezine haber ver
            trapEngine.OnOyuncuBanlandi += (sender, oyuncuAdi) =>
            {
                banMerkezi.Banla(oyuncuAdi, CezaTipi.KaliciBan);
            };

            // 2. Asenkron paket süzme görevinin arka planda ateşlenmesi
            Task processingTask = Task.Run(() => trapEngine.StartProcessingAsync(cts.Token));

            // 3. Yasal laboratuvar paket simülasyon verileri
            MarkOsLogger.Banner("YASAL TEST LABORATUVARI BAŞLATILIYOR");

            trapEngine.KuyrugaPaketEkle(new NetworkPacket("Muhammed_Bilisim12", 45, false));
            await Task.Delay(600);

            trapEngine.KuyrugaPaketEkle(new NetworkPacket("Lamer_Cheater31", 999, true));
            await Task.Delay(1500);

            trapEngine.KuyrugaPaketEkle(new NetworkPacket("Berfin_Tech_17", 80, false));
            await Task.Delay(1000);

            // Tekrarlayan hileci -> kademeli ceza sistemi devreye girer
            MarkOsLogger.Info("TekrarSuçu Testi: Aynı hileci ikinci kez yakalanıyor...");
            trapEngine.KuyrugaPaketEkle(new NetworkPacket("Lamer_Cheater31", 1337, true));
            await Task.Delay(1000);

            trapEngine.KuyrugaPaketEkle(new NetworkPacket("Zeynep_GuvenliNet", 12, false));
            await Task.Delay(1000);

            // Üçüncü ihlal -> kalıcı ban tetiklenir
            MarkOsLogger.Info("Üçüncü ihlal testi: Kalıcı ban senaryosu...");
            trapEngine.KuyrugaPaketEkle(new NetworkPacket("Lamer_Cheater31", 9001, true));
            await Task.Delay(1000);

            // 4. Raporlama ve güvenli kapanış
            telemetri.RaporYaz();
            banMerkezi.RaporYaz();

            MarkOsLogger.Warning("Simülasyon tamamlandı. Kapatmak için ENTER tuşuna basın babuş...");
            Console.ReadLine();

            cts.Cancel();
            try
            {
                await processingTask;
            }
            catch (OperationCanceledException)
            {
                MarkOsLogger.Info("MarkOs Asenkron çekirdeği güvenli modda kapatıldı.");
            }

            MarkOsLogger.Success("MarkOs Enterprise Suite v2026.2 başarıyla sonlandırıldı. Görüşürüz babuş! 🛡️");
        }
    }
    #endregion
}
