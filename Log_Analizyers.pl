#!/usr/bin/env perl
# ===================================================================
# PROJE ADI   : MarkOs Perl Canlı Paket & Log Güvenlik Kalkanı
# GELİŞTİRİCİ : memetcanwq31-ship-it (BTK Akademi Standartları)
# LİSANS      : MIT Open Source | %100 GERÇEK TEHDİT İSTİHBARATI
# ===================================================================

use strict;
use warnings;
use File::Tail;

my $GREEN  = "\e[32m";
my $RED    = "\e[31m";
my $YELLOW = "\e[33m";
my $CYAN   = "\e[36m";
my $RESET  = "\e[0m";

print "${GREEN}=====================================================$RESET\n";
print "${GREEN}   MARKOS PERL LIVE PACKET LOG ANALYZER & SHIELD     $RESET\n";
print "${GREEN}=====================================================$RESET\n\n";

my $log_file = "access.log";

unless (-e $log_file) {
    open(my $fh, '>', $log_file) or die "Dosya oluşturulamadı: $!";
    print $fh "127.0.0.1 - - [12/Oct/2026:20:05:00 +0300] \"GET / HTTP/1.1\" 200 45\n";
    close($fh);
}

my $file = File::Tail->new(name => $log_file, maxinterval => 1, adjustinterval => 1);

while (defined(my $line = $file->read)) {
    chomp($line);
    print "${CYAN}[TRAFİK] $line${RESET}\n";

    if ($line =~ /(union\s+select|select\s+.*\s+from|insert\s+into)/i) {
        print "${RED}[🚨] [SALDIRI TESPİT EDİLDİ] SQL Injection Girişimi Yakalandı!${RESET}\n";
    }
    elsif ($line =~ /(<script>|javascript:|onerror=|alert\()/i) {
        print "${RED}[🚨] [SALDIRI TESPİT EDİLDİ] Cross-Site Scripting (XSS) Girişimi Yakalandı!${RESET}\n";
    }
    elsif ($line =~ /(\.\.\/|\/etc\/passwd)/i) {
        print "${RED}[🚨] [SALDIRI TESPİT EDİLDİ] Local File Inclusion (LFI) Girişimi!${RESET}\n";
    }
}
