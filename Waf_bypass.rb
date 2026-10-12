# ===================================================================
# PROJE ADI   : MarkOs Waf Bypass & Encoding Simulator (Waf_bypass.rb)
# GELİŞTİRİCİ : memetcanwq31-ship-it (MIT Open Source License)
# STATÜ       : %100 Meşru Lab Test ve Antivirüs Evasion Araştırması
# ===================================================================

require 'uri'

class MarkOsWafBypass
  def initialize
    @version = "1.0.0-RubyEvasion"
  end

  # Modül 1: Double URL Encoding (Çift Kodlama İle Regex Filtre Testi)
  def double_encode(payload)
    first_encode = URI.encode_www_form_component(payload)
    URI.encode_www_form_component(first_encode)
  end

  # Modül 2: SQL Yorum Satırı Araya Ekleme (Obfuscation Analizi)
  def sql_comment_obfuscate(payload)
    payload.gsub(" ", "/**/")
  end

  # Modül 3: HTML Hex Dönüşüm Maskelemesi
  def html_hex_encode(payload)
    payload.chars.map { |c| "&#x%02x;" % c.ord }.join
  end
end

if __FILE__ == $0
  sim = MarkOsWafBypass.new
  puts "\e[32m=== MARKOS RUBY WAF BYPASS & EVASION SIMULATOR ===\e[0m"
  print "\e[36m[?] Test Edilecek Ham Payload Metnini Girin: \e[0m"
  raw = gets.chomp.strip
  if raw.empty?
    puts "\e[31m[!] Hata: Girdi boş bırakılamaz!\e[0m"
    exit
  end

  puts "\n\e[33m[+] Kodlanmış ve Maskelenmiş Çıktı Katmanları:\e[0m"
  puts "\e[32m  • [Double URL Encode] : \e[37m#{sim.double_encode(raw)}\e[0m"
  puts "\e[32m  • [SQL Comment Inject]: \e[37m#{sim.sql_comment_obfuscate(raw)}\e[0m"
  puts "\e[32m  • [HTML Hex Mask]     : \e[37m#{sim.html_hex_encode(raw)}\e[0m"
end
