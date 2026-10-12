/* name=markos_hunter.c
   Tamamlanmış ve güçlendirilmiş MarkOs Threat Hunter & Backdoor Analyzer v2.0
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <errno.h>
#include <ctype.h>
#include <stdbool.h>

#ifdef _WIN32
    #include <windows.h>
#else
    #include <unistd.h>
    #include <sys/types.h>
    #include <sys/stat.h>
    #include <sys/wait.h>
#endif

#define GREEN  "\x1b[32m"
#define RED    "\x1b[31m"
#define YELLOW "\x1b[33m"
#define CYAN   "\x1b[36m"
#define MAGENTA "\x1b[35m"
#define RESET  "\x1b[0m"
#define MAX_BUF 4096
#define LINE_BUF 2048

/* Bilinen kötü amaçlı / nadiren meşru olan portlar (araştırma taraması) */
static const int suspicious_ports[] = {4444, 4445, 5555, 6666, 6667, 7777, 8888, 9999, 1337, 31337, 12345, 54321};
static const int num_suspicious = sizeof(suspicious_ports) / sizeof(suspicious_ports[0]);

/* ---------- Fonksiyon prototipleri ---------- */
void show_banner(void);
void log_event(const char *severity, const char *msg);
void clear_screen(void);
void press_enter(void);
void safe_sleep(int seconds);
int  read_int(int min, int max);

/* Modüller */
void module_network_connections(void);
void module_system_files(void);
void module_process_scan(void);
void module_persistence_check(void);
void module_hosts_analysis(void);
void module_suspicious_port_map(void);
void module_log_summary(void);
void module_full_scan(void);

/* Yardımcılar */
int  is_suspicious_port(int port);
void print_seperator(const char *title);
bool line_contains_port(const char *line, int port);

/* =================================================================== */
/* ANA PROGRAM                                                         */
/* =================================================================== */
int main(void) {
    int running = 1;
    int choice;

    log_event("INFO", "MarkOs Threat Hunter v2.0 baslatildi.");

    while (running) {
        clear_screen();
        show_banner();
        printf("%s── SAVUNMA MODÜLLERİ ──────────────────────────────────%s\n", CYAN, RESET);
        printf("  [%s1%s]  Canlı Ağ Bağlantıları ve RAT Tüneli Taraması\n", GREEN, RESET);
        printf("  [%s2%s]  Kritik Sistem Dosyası Bütünlük Denetimi\n", GREEN, RESET);
        printf("  [%s3%s]  Süreç (Process) Anomali Taraması\n", GREEN, RESET);
        printf("  [%s4%s]  Kalıcılık (Persistence) Mekanizma Denetimi\n", GREEN, RESET);
        printf("  [%s5%s]  Hosts Dosyası DNS Zehirlenmesi Analizi\n", GREEN, RESET);
        printf("  [%s6%s]  Şüpheli Port - PID Eşleştirme Analizi\n", GREEN, RESET);
        printf("  [%s7%s]  Sistem Log Özeti (Son Oturum / Hatalar)\n", GREEN, RESET);
        printf("  [%s8%s]  TAM TARAMA (Tüm Modüller Peş Peşe)\n", MAGENTA, RESET);
        printf("  [%s0%s]  Çıkış\n", RED, RESET);
        printf("%s───────────────────────────────────────────────────────%s\n", CYAN, RESET);
        printf("MarkOs_Hunter > Seçiminiz: ");

        choice = read_int(-1, 8);
        if (choice == -1) {
            printf("%s[!] Geçersiz girdi! Menü yenileniyor...%s\n", RED, RESET);
            safe_sleep(1);
            continue;
        }

        switch (choice) {
            case 1: clear_screen(); module_network_connections(); press_enter(); break;
            case 2: clear_screen(); module_system_files();        press_enter(); break;
            case 3: clear_screen(); module_process_scan();        press_enter(); break;
            case 4: clear_screen(); module_persistence_check();   press_enter(); break;
            case 5: clear_screen(); module_hosts_analysis();      press_enter(); break;
            case 6: clear_screen(); module_suspicious_port_map(); press_enter(); break;
            case 7: clear_screen(); module_log_summary();         press_enter(); break;
            case 8: clear_screen(); module_full_scan();           press_enter(); break;
            case 0:
                printf("\n%s[!] MarkOs Savunma Motoru Kapatıldı. Görüşürüz!%s\n", RED, RESET);
                log_event("INFO", "MarkOs Threat Hunter kapatildi.");
                running = 0;
                break;
            default:
                printf("%s[!] Geçersiz seçim!%s\n", RED, RESET);
                safe_sleep(1);
        }
    }
    return 0;
}

/* =================================================================== */
/* YARDIMCI FONKSİYONLAR                                               */
/* =================================================================== */

void show_banner(void) {
    printf("%s=====================================================\n", GREEN);
    printf("   MARKOS THREAT HUNTER & BACKDOOR ANALYZER v2.0     \n");
    printf("=====================================================\n");
    printf("   [🛡️] STATÜ : Savunma Odaklı Sistem Analizi         \n");
    printf("   [👤] MİMAR : memetcanwq31-ship-it | DİL: SAF C     \n");
    printf("=====================================================%s\n\n", RESET);
}

/* Basit dosya tabanlı loglama - zaman damgalı */
void log_event(const char *severity, const char *msg) {
    FILE *fp = fopen("markos_hunter.log", "a");
    if (fp == NULL) return;

    time_t now = time(NULL);
    char tbuf[64];
    if (localtime(&now) != NULL)
        strftime(tbuf, sizeof(tbuf), "%Y-%m-%d %H:%M:%S", localtime(&now));
    else
        snprintf(tbuf, sizeof(tbuf), "0000-00-00 00:00:00");

    fprintf(fp, "[%s] [%s] %s\n", tbuf, severity, msg);
    fclose(fp);
}

void clear_screen(void) {
#ifdef _WIN32
    system("cls");
#else
    system("clear");
#endif
}

void press_enter(void) {
    printf("%s\nAna menüye dönmek için Enter'a basın...%s", GREEN, RESET);
    char buf[16];
    if (fgets(buf, sizeof(buf), stdin) == NULL) { /* ignore */ }
}

void safe_sleep(int seconds) {
#ifdef _WIN32
    Sleep(seconds * 1000);
#else
    sleep(seconds);
#endif
}

/* Güvenli tam sayı okuma - taşma ve sonsuz döngü korumalı */
int read_int(int min, int max) {
    char buf[64];
    long val;
    char *endptr;

    if (fgets(buf, sizeof(buf), stdin) == NULL) return -1;
    /* Satır sonu kontrolü - taşan girdi varsa temizle */
    if (strchr(buf, '\n') == NULL) {
        int c;
        while ((c = getchar()) != '\n' && c != EOF);
        return -1;
    }
    errno = 0;
    val = strtol(buf, &endptr, 10);
    if (endptr == buf || (*endptr != '\n' && *endptr != '\0')) return -1;
    if ((errno == ERANGE) || val < min || val > max) return -1;
    return (int)val;
}

void print_seperator(const char *title) {
    printf("\n%s──────── %s ────────%s\n", CYAN, title, RESET);
}

/* Bilinen şüpheli port kontrolü */
int is_suspicious_port(int port) {
    int i;
    for (i = 0; i < num_suspicious; i++) {
        if (suspicious_ports[i] == port) return 1;
    }
    return 0;
}

/* Satırda belirli portun anlamlı bir eşleşmesi var mı? (ör: :4444, :4444/...) */
bool line_contains_port(const char *line, int port) {
    char pattern[32];
    snprintf(pattern, sizeof(pattern), ":%d", port);
    const char *p = strstr(line, pattern);
    while (p) {
        const char after = *(p + strlen(pattern));
        /* Eğer sonlandıysa veya ayırıcı ise (space, colon, slash, tab) kabul et */
        if (after == '\0' || isspace((unsigned char)after) || after == '/' || after == ':' ) return true;
        /* Eğer sonraki karakter rakamsa bu ör. :44445 gibi yanlış pozitif olabilir; o zaman devam et */
        if (!isdigit((unsigned char)after)) return true;
        /* aksi halde sonraki olası konumu ara */
        p = strstr(p + 1, pattern);
    }
    return false;
}

/* =================================================================== */
/* MODÜL 1: AĞ BAĞLANTILARI                                            */
/* =================================================================== */
void module_network_connections(void) {
    print_seperator("MODÜL 1: CANLI AĞ BAĞLANTILARI");
    printf("%s[*] Aktif soket tablosu ve ESTABLISHED bağlantılar süzülüyor...%s\n", YELLOW, RESET);

#ifdef _WIN32
    log_event("INFO", "Ag baglantilari taramasi (Windows).");
    /* Windows'ta büyük çıktıyı pipe ile göster */
    system("netstat -ano | findstr ESTABLISHED");
#else
    log_event("INFO", "Ag baglantilari taramasi (Linux/Termux).");
    printf("%s[i] Yerel soket durumları ve ağ tablosu:%s\n\n", CYAN, RESET);
    int rc = system("ss -antp 2>/dev/null || netstat -antp 2>/dev/null");
    if (rc != 0) {
        printf("%s[!] Soket listesi alınamadı - yetki gerekebilir (root/sudo deneyin).%s\n", RED, RESET);
        log_event("WARN", "Soket tablosu okunamadi.");
    }
#endif
    printf("%s[+] Ağ seviyesinde analiz tamamlandı. Şüpheli dış bağlantıları elle inceleyin.%s\n", GREEN, RESET);
    printf("%s[i] İPUCU: Tanımadığınız uzak IP:port eşleşmelerini OSINT araçlarıyla doğrulayın.%s\n", CYAN, RESET);
}

/* =================================================================== */
/* MODÜL 2: KRİTİK SİSTEM DOSYALARI                                    */
/* =================================================================== */
void module_system_files(void) {
    print_seperator("MODÜL 2: KRİTİK SİSTEM DOSYA BÜTÜNLÜĞÜ");
    FILE *file;

#ifdef _WIN32
    /* Windows: hosts dosyası erişim kontrolü */
    file = fopen("C:\\Windows\\System32\\drivers\\etc\\hosts", "r");
    if (file != NULL) {
        printf("%s[+] Hosts dosyası okunabilir.%s\n", GREEN, RESET);
        fclose(file);
        log_event("INFO", "Windows hosts dosyasi erisilebilir.");
    } else {
        printf("%s[!] UYARI: Hosts dosyası kilitli veya erişim izinleri değiştirilmiş!%s\n", RED, RESET);
        log_event("WARN", "Windows hosts dosyasina erisilemedi.");
    }

    /* Windows: SAM ve sistem yapılandırma dosyalarının varlık kontrolü */
    file = fopen("C:\\Windows\\System32\\config\\SAM", "r");
    if (file == NULL) {
        printf("%s[i] SAM veritabanı erişimi kısıtlı (normal - yönetici hakları gerekir).%s\n", CYAN, RESET);
    } else {
        printf("%s[!] DİKKAT: SAM veritabanı okunabilir - ayrıcalık yükseltme riski!%s\n", RED, RESET);
        fclose(file);
        log_event("HIGH", "SAM veritabani okunabilir - yetki sorunu.");
    }
#else
    /* Linux/Termux: kritik dosya bütünlüğü */
    struct { const char *path; const char *desc; } checks[] = {
        {"/etc/passwd",  "Kullanıcı hesap tablosu"},
        {"/etc/shadow",  "Şifre hash deposu"},
        {"/etc/ssh/sshd_config", "SSH sunucu yapılandırması"},
        {"/etc/crontab", "Zamanlanmış görev tablosu"},
        {"/etc/sudoers", "Yönetici yetki tablosu"}
    };
    int i, total = sizeof(checks) / sizeof(checks[0]);

    for (i = 0; i < total; i++) {
        if (access(checks[i].path, R_OK) == 0) {
            if (strstr(checks[i].path, "shadow") != NULL || strstr(checks[i].path, "sudoers") != NULL) {
                printf("%s[!] RİSK: %s (%s) OKUNABİLİR - izin hatası olabilir!%s\n", RED, checks[i].desc, checks[i].path, RESET);
                char logmsg[256];
                snprintf(logmsg, sizeof(logmsg), "Kritik dosya okunabilir: %s", checks[i].path);
                log_event("HIGH", logmsg);
            } else {
                printf("%s[+] %s (%s): DOĞRULANDI%s\n", GREEN, checks[i].desc, checks[i].path, RESET);
            }
        } else {
            printf("%s[i] %s (%s): erişilemiyor (root gerekebilir)%s\n", CYAN, checks[i].desc, checks[i].path, RESET);
        }
    }
#endif
    printf("%s[+] Sistem bütünlük analizi tamamlandı.%s\n\n", GREEN, RESET);
}

/* =================================================================== */
/* MODÜL 3: SÜREÇ ANOMALİ TARAMASI                                     */
/* =================================================================== */
void module_process_scan(void) {
    print_seperator("MODÜL 3: SÜREÇ (PROCESS) ANOMALİ TARAMASI");
    printf("%s[*] Çalışan süreçler listeleniyor, bilinen tehlikeli isimler aranıyor...%s\n", YELLOW, RESET);

    /* Yaygın olarak kötü amaçlı yazılımların taklit ettiği / kullandığı isimler */
    const char *danger_names[] = {"nc", "ncat", "netcat", "cryptominer", "xmrig", "kdevtmpfsi", "kinsing", "dropbear", "weathersvc"};
    int ndanger = sizeof(danger_names) / sizeof(danger_names[0]);

#ifdef _WIN32
    system("tasklist /v");
#else
    /* Süreç listesi çekilir, her satır tehlikeli isimlere karşı taranır */
    FILE *fp = popen("ps aux 2>/dev/null", "r");
    if (fp == NULL) {
        printf("%s[!] Süreç listesi alınamadı.%s\n", RED, RESET);
        return;
    }

    char line[LINE_BUF];
    int findings = 0;
    /* İlk satır başlık - atla */
    if (fgets(line, sizeof(line), fp) == NULL) { pclose(fp); return; }

    while (fgets(line, sizeof(line), fp) != NULL) {
        int i;
        for (i = 0; i < ndanger; i++) {
            /* Kısmi isim eşleşmesi (word-boundary olmasa da) */
            if (strcasestr(line, danger_names[i]) != NULL) {
                printf("%s[!] ŞÜPHELİ SÜREÇ: %s%s", RED, line, RESET);
                findings++;
                log_event("HIGH", "Supheli surec bulundu");
            }
        }
    }
    pclose(fp);

    if (findings == 0)
        printf("%s[+] Tarama tamamlandı - bilinen tehlikeli süreç imzası bulunamadı.%s\n", GREEN, RESET);
    else
        printf("%s[!] %d şüpheli süreç bulundu - detaylı inceleme önerilir!%s\n", RED, findings, RESET);
#endif
}

/* =================================================================== */
/* MODÜL 4: KALICILIK (PERSISTENCE) DENETİMİ                           */
/* =================================================================== */
void module_persistence_check(void) {
    print_seperator("MODÜL 4: KALICILIK MEKANİZMA DENETİMİ");
    printf("%s[*] Saldırganların kalıcı erişim için kullandığı mekanizmalar denetleniyor...%s\n", YELLOW, RESET);

#ifdef _WIN32
    /* Windows: Kayıt defteri Run anahtarları - en yaygın Windows persistence noktası */
    printf("%s[i] HKCU Run anahtarları (otomatik başlatılan programlar):%s\n", CYAN, RESET);
    system("reg query HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run");
    printf("%s[i] HKLM Run anahtarları (sistem geneli):%s\n", CYAN, RESET);
    system("reg query HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run");
    printf("%s[i] Zamanlanmış görevler:%s\n", CYAN, RESET);
    system("schtasks /query /fo LIST | findstr /i \"TaskName\"");
#else
    /* Linux: cron, systemd, rc.local, bash profil dosyaları */
    const char *persist_paths[] = {
        "/etc/crontab", "/etc/cron.d/", "/var/spool/cron/crontabs/",
        "/etc/rc.local", "/etc/systemd/system/", "/etc/init.d/",
        "/etc/profile.d/", "/root/.bashrc", "/root/.profile"
    };
    int np = sizeof(persist_paths) / sizeof(persist_paths[0]);
    int i;

    for (i = 0; i < np; i++) {
        if (access(persist_paths[i], R_OK) == 0) {
            printf("%s[+] Var: %s%s\n", GREEN, persist_paths[i], RESET);
            /* cron dosyaları için içerik özeti göster */
            if (strstr(persist_paths[i], "cron") != NULL || strstr(persist_paths[i], "rc.local") != NULL) {
                FILE *fp = fopen(persist_paths[i], "r");
                if (fp) {
                    char line[LINE_BUF];
                    while (fgets(line, sizeof(line), fp) != NULL) {
                        if (line[0] != '#' && line[0] != '\n' && line[0] != '\0')
                            printf("    %s> %s%s", YELLOW, line, RESET);
                    }
                    fclose(fp);
                }
            }
        } else {
            /* var olmayan dizinler için sessiz kal */
        }
    }
    printf("%s[i] İPUCU: Bilmediğiniz bir cron görevi veya systemd servisi gördüyseniz inceleyin.%s\n", CYAN, RESET);
#endif
    log_event("INFO", "Persistence denetimi tamamlandi.");
}

/* =================================================================== */
/* MODÜL 5: HOSTS DOSYASI DNS ZEHİRLENMESİ ANALİZİ                     */
/* =================================================================== */
void module_hosts_analysis(void) {
    print_seperator("MODÜL 5: HOSTS DOSYASI ANALİZİ");
    printf("%s[*] DNS yönlendirme zehirlenmesi (bank/phishing yönlendirme) kontrolü...%s\n", YELLOW, RESET);

#ifdef _WIN32
    const char *hosts_path = "C:\\Windows\\System32\\drivers\\etc\\hosts";
#else
    const char *hosts_path = "/etc/hosts";
#endif

    FILE *fp = fopen(hosts_path, "r");
    if (fp == NULL) {
        printf("%s[!] Hosts dosyası okunamadı - yetki gerekebilir.%s\n", RED, RESET);
        log_event("WARN", "hosts dosyasi okunamadi.");
        return;
    }

    char line[LINE_BUF];
    int entries = 0, suspicious = 0;
    /* Phishing'de sık hedeflenen alan adları */
    const char *targets[] = {"bank", "paypal", "gmail", "facebook", "instagram", "twitter", "garanti", "ziraat", "isbank", "hsbc", "wellsfargo"};
    int ntargets = sizeof(targets) / sizeof(targets[0]);

    while (fgets(line, sizeof(line), fp) != NULL) {
        /* Yorum satırlarını ve boş satırları atla */
        char *trim = line;
        while (*trim && isspace((unsigned char)*trim)) trim++;
        if (*trim == '#' || *trim == '\0' || *trim == '\n') continue;

        entries++;
        /* lowercase kopya */
        char lower[LINE_BUF];
        size_t j;
        for (j = 0; j < sizeof(lower)-1 && line[j] != '\0'; j++)
            lower[j] = (char)tolower((unsigned char)line[j]);
        lower[j] = '\0';

        int i;
        for (i = 0; i < ntargets; i++) {
            if (strstr(lower, targets[i]) != NULL) {
                printf("%s[!] ŞÜPHELİ GİRİŞ: %s%s", RED, line, RESET);
                suspicious++;
                log_event("HIGH", "hosts dosyasinda supheli giris");
            }
        }
    }
    fclose(fp);

    printf("\n%s[i] Toplam aktif girişler: %d%s\n", CYAN, entries, RESET);
    if (suspicious == 0)
        printf("%s[+] DNS zehirlenmesi imzası bulunamadı.%s\n", GREEN, RESET);
    else
        printf("%s[!] %d şüpheli yönlendirme bulundu - acilen inceleyin!%s\n", RED, suspicious, RESET);
}

/* =================================================================== */
/* MODÜL 6: ŞÜPHELİ PORT - PID EŞLEŞTİRME                              */
/* =================================================================== */
void module_suspicious_port_map(void) {
    print_seperator("MODÜL 6: ŞÜPHELİ PORT - PID EŞLEŞTİRME");
    printf("%s[*] Bilinen backdoor/C2 portları (4444, 31337, 1337, 12345...) aranıyor...%s\n", YELLOW, RESET);

    int i;
    printf("%s[i] Denetlenen portlar: ", CYAN, RESET);
    for (i = 0; i < num_suspicious; i++)
        printf("%d ", suspicious_ports[i]);
    printf("%s\n\n", RESET);

#ifdef _WIN32
    FILE *fp = popen("netstat -ano", "r");
#else
    FILE *fp = popen("ss -antup 2>/dev/null || netstat -antup 2>/dev/null", "r");
#endif

    if (fp == NULL) {
        printf("%s[!] Soket tablosu alınamadı.%s\n", RED, RESET);
        return;
    }

    char line[LINE_BUF];
    int hits = 0;
    while (fgets(line, sizeof(line), fp) != NULL) {
        for (i = 0; i < num_suspicious; i++) {
            if (line_contains_port(line, suspicious_ports[i])) {
                printf("%s[!] EŞLEŞME BULUNDU (port %d): %s%s", RED, suspicious_ports[i], line, RESET);
                hits++;
                log_event("HIGH", "Supheli port aktivitesi");
            }
        }
    }
    pclose(fp);

    if (hits == 0)
        printf("%s[+] Bilinen backdoor portlarında aktivite bulunamadı.%s\n", GREEN, RESET);
    else
        printf("%s[!] %d eşleşme bulundu! İlgili PID'leri 'ps -p <PID>' veya 'sudo lsof -i :<port>' ile inceleyin.%s\n", RED, hits, RESET);
}

/* =================================================================== */
/* MODÜL 7: SİSTEM LOG ÖZETİ                                           */
/* =================================================================== */
void module_log_summary(void) {
    print_seperator("MODÜL 7: SİSTEM LOG ÖZETİ");
    printf("%s[*] Kimlik doğrulama ve sistem logları özetleniyor...%s\n", YELLOW, RESET);

#ifdef _WIN32
    printf("%s[i] Son güvenlik olayları (Event Log - Security, son 10):%s\n", CYAN, RESET);
    system("wevtutil qe Security /c:10 /rd:true /f:text");
#else
    /* Oturum açma hataları (brute-force göstergesi) */
    FILE *fp = popen("grep -i 'failed password' /var/log/auth.log 2>/dev/null | tail -n 10 || "
                     "grep -i 'failed password' /var/log/secure 2>/dev/null | tail -n 10 || "
                     "echo 'Log dosyasina erisilemiyor (root gerekebilir)'", "r");
    if (fp) {
        char line[LINE_BUF];
        while (fgets(line, sizeof(line), fp) != NULL)
            printf("    %s", line);
        pclose(fp);
    }
    printf("%s[i] İPUCU: Aynı IP'den çok sayıda 'failed password' brute-force saldırısı göstergesidir.%s\n", CYAN, RESET);
#endif
    log_event("INFO", "Log ozeti modulu calistirildi.");
}

/* =================================================================== */
/* TAM TARAMA                                                          */
/* =================================================================== */
void module_full_scan(void) {
    print_seperator("TAM TARAMA BAŞLATILIYOR");
    log_event("INFO", "Tam tarama baslatildi.");
    printf("%s[▶] Tüm savunma modülleri sırayla çalıştırılıyor...%s\n\n", MAGENTA, RESET);

    module_network_connections();
    module_system_files();
    module_process_scan();
    module_persistence_check();
    module_hosts_analysis();
    module_suspicious_port_map();
    module_log_summary();

    printf("\n%s═══════════════════════════════════════════════════════%s\n", GREEN, RESET);
    printf("%s[✔] TAM TARAMA TAMAMLANDI. Detaylar: markos_hunter.log%s\n", GREEN, RESET);
    printf("%s═══════════════════════════════════════════════════════%s\n\n", GREEN, RESET);
    log_event("INFO", "Tam tarama tamamlandi.");
}
