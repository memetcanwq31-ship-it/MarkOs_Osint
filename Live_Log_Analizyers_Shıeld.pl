#!/usr/bin/env perl
# ===================================================================
#  MARKOS PERL CANLI LOG GÜVENLİK KALKANI v2.1
#  Dev: memetcanwq31-ship-it | MIT
#  DEPENDENCY YOK — saf Perl, Termux'ta direkt çalışır
#  Manuel tail-f implementasyonu (File::Tail'e gerek kalmadı)
# ===================================================================

use strict;
use warnings;

# Renk kodları
my $GREEN  = "\e[32m";
my $RED    = "\e[31m";
my $YELLOW = "\e[33m";
my $CYAN   = "\e[36m";
my $RESET  = "\e[0m";

sub show_banner {
    system('clear');
    print "${GREEN}=====================================================$RESET\n";
    print "${GREEN}   MARKOS PERL LIVE LOG ANALYZER & SHIELD v2.1       $RESET\n";
    print "${GREEN}=====================================================$RESET\n";
    print "${CYAN}   [📡] DOSYA : 'access.log' canlı izleniyor...       $RESET\n";
    print "${GREEN}=====================================================$RESET\n\n";
}

show_banner();

my $log_file = "access.log";

# access.log yoksa oluştur
unless (-e $log_file) {
    open(my $fh, '>', $log_file) or die "Dosya oluşturulamadı: $!";
    print $fh "127.0.0.1 - - [11/Oct/2026:22:00:00 +0300] \"GET / HTTP/1.1\" 200 45\n";
    close($fh);
}

# ── Manuel tail -f implementasyonu ──
# Dosyanın son konumunu takip et, dosya büyüyünce yeni satırları oku
sub open_log {
    open(my $fh, '<', $log_file) or die "Log dosyası açılamadı: $!";
    # Dosyanın sonuna git (mevcut geçmişi atla, sadece yeni satırları oku)
    seek($fh, 0, 2);
    return $fh;
}

# ── IP bazlı saldırı sayacı ve ban listesi ──
my %attack_count = ();
my %banned       = ();
my $ban_threshold = 3;   # 3 saldırı = ban

# ── Saldırı imzaları (8 kategori) ──
my @signatures = (
    [ 'SQL Injection',      qr/(union\s+select|select\s+.+\s+from|insert\s+into|drop\s+table|or\s+1\s*=\s*1)/i ],
    [ 'XSS',                qr/(<script|javascript:|onerror\s*=|onload\s*=|<svg|<iframe)/i ],
    [ 'LFI/Path Traversal', qr/(\.\.\/|\.\.\\|\/etc\/passwd|\/windows\/win\.ini|%2e%2e%2f)/i ],
    [ 'Command Injection',  qr/(;\s*(whoami|id|cat|nc|wget|curl)|\|whoami|\`id\`)/i ],
    [ 'Webshell',           qr/(c99\.php|r57\.php|shell\.php|b374k|wso\.php)/i ],
    [ 'Log4Shell RCE',      qr/\$\{jndi:(ldap|rmi|dns):/i ],
    [ 'Scanner',            qr/(sqlmap|nikto|nmap|gobuster|dirbuster|masscan)/i ],
    [ 'Brute-Force Login',  qr/POST\s+\S*(login|signin|auth)\S*\s+HTTP/i ],
);

print "${CYAN}[*] ${log_file} canlı izlemeye alındı... (Ctrl+C ile çık)${RESET}\n\n";

my $fh = open_log();

# Ana izleme döngüsü — dosya büyüyene kadar bekle, yeni satırları oku
while (1) {
    while (defined(my $line = <$fh>)) {
        chomp($line);
        next if $line =~ /^\s*$/;  # boş satırları atla

        # Kaynak IP'yi çıkar (Apache/Nginx common log format)
        my ($ip) = $line =~ /^(\d{1,3}(?:\.\d{1,3}){3})/;
        $ip ||= 'bilinmeyen';

        print "${CYAN}[TRAFİK] $line${RESET}\n";

        # Ban kontrolü
        if ($banned{$ip}) {
            print "${RED}[🚫] $ip BAN LİSTESİNDE — istek engellendi$RESET\n\n";
            next;
        }

        # İmza eşleştirme motoru
        my $hit = 0;
        foreach my $sig (@signatures) {
            my ($name, $regex) = @$sig;
            if ($line =~ $regex) {
                $hit = 1;
                $attack_count{$ip}++;
                print "${RED}[🚨] [SALDIRI] $name tespit edildi! Kaynak: $ip (sayacı: $attack_count{$ip})$RESET\n";
                print "${YELLOW}    • [DEFANS] İstek imza katmanında işaretlendi.$RESET\n";

                if ($attack_count{$ip} >= $ban_threshold) {
                    $banned{$ip} = 1;
                    print "${RED}    • [BAN] $ip ban listesine alındı ($ban_threshold saldırı sınırı aşıldı)${RESET}\n";
                }
                last;
            }
        }

        unless ($hit) {
            print "${GREEN}[+] Temiz istek: $ip${RESET}\n";
        }
        print "\n";
    }

    # Log dosyası truncate/rotate edildiyse (boyut küçüldüyse) yeniden aç
    my $size = -s $log_file;
    my $pos  = tell($fh);
    if (defined($size) && $pos > $size) {
        close($fh);
        $fh = open_log();
        print "${YELLOW}[*] Log dosyası rotate edildi, yeniden takip başlatıldı.$RESET\n";
    }

    # 0.5 saniye bekle (CPU dostu)
    select(undef, undef, undef, 0.5);
}
