#!/usr/bin/env ruby
# ===================================================================
# MARKOS PURPLE TEAM - ADVANCED ZAFİYET TARAMA MOTORU v1.0
# ===================================================================
# Geliştirici: memetcanwq31-ship-it (BTK Akademi Standartları)
# Statü: %100 Meşru Açık Bulma ve Siber Tehdit İstihbaratı
# ===================================================================

require 'net/http'
require 'socket'
require 'uri'

class MarkOsZafiyetScanner
  def initialize
    @intel_ports = [22, 80, 443, 8080]
  end

  def scan_target(domain)
    puts "\n\e[32m[*] MarkOs Zafiyet Denetimi Başlatıldı: #{domain}\e[0m"
    sleep(1)

    # 1. Aşama: DNS ve IP Çözümleme
    begin
      target_ip = IPSocket.getaddress(domain)
      puts "\e[36m[+] Çözümlenen IP Adresi: #{target_ip}\e[0m"
    rescue
      puts "\e[31m[!] Kritik Hata: Alan adı IP adresine çözümlenemedi!\e[0m"
      return
    end

    # 2. Aşama: HTTP Güvenlik Başlıkları Analizi (Açık Tarama)
    begin
      uri = URI("https://#{domain}")
      res = Net::HTTP.get_response(uri)
      headers = res.to_hash

      puts "\n\e[33m── GÜVENLİK KALKANI VE BAŞLIK AÇIKLARI ──\e[0m"
      if headers.include?('strict-transport-security')
        puts "\e[32m[+] HSTS Kalkanı AKTİF: #{res['strict-transport-security']}\e[0m"
      else
        puts "\e[31m[!] RİSK (AÇIK): HSTS Başlığı Eksik! (Trafik Şifresiz Dinleme / MitM Riski)\e[0m"
      end

      if headers.include?('x-frame-options')
        puts "\e[32m[+] Clickjacking Defansı AKTİF: #{res['x-frame-options']}\e[0m"
      else
        puts "\e[31m[!] RİSK (AÇIK): X-Frame-Options Eksik! (Clickjacking/Arayüz Giydirme Riski)\e[0m"
      end
    rescue => e
      puts "\e[31m[!] Web Sunucu Yanıtı Alınamadı (WAF Engeli Olabilir): #{e}\e[0m"
    end

    # 3. Aşama: Soket Seviyesinde Kritik Servis Port Keşfi
    puts "\n\e[33m── KRİTİK SERVİS PORT KEŞİF MOTORU ──\e[0m"
    @intel_ports.each do |port|
      begin
        sock = Socket.new(:INET, :STREAM)
        raw = Socket.sockaddr_in(port, target_ip)
        sock.connect_timeout = 1.5
        sock.connect(raw)
        puts "\e[31m  [!] AÇIK SERVİS BELİRLENDİ: Port #{port} DIŞA AÇIK!\e[0m"
        sock.close
      rescue Errno::ETIMEDOUT, Errno::ECONNREFUSED
        # Port dış ağa güvenli şekilde kapalı
      rescue => e
        # Diğer soket istisnaları
      end
    end
  end
end

if __FILE__ == $0
  print "\e[32m[?] Analiz Edilecek Domain: \e[0m"
  target = gets.chomp.strip
  scanner = MarkOsZafiyetScanner.new
  scanner.scan_target(target)
end
