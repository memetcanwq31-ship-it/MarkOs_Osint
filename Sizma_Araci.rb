#!/usr/bin/env ruby
# ===================================================================
# MARKOS PURPLE TEAM - ENCRYPTED PAYLOAD GENERATION SUITE v1.0
# ===================================================================
# Geliştirici: memetcanwq31-ship-it | Statü: AV Evasion / Lab Test
# ===================================================================

require 'openssl'
require 'base64'

class MarkOsPayloadEvasion
  def initialize
    # Kurumsal AES 256-bit Gizli Anahtar ve IV Şablonu
    @aes_key = "markos_secret_key_32_bytes_long!"
    @aes_iv = "markos_initial_iv" # 16 Bytes
  end

  # Modül 1: Saf XOR Maskeleme Motoru
  def xor_cipher(data, key_char)
    puts "\e[33m[*] Girdi Verisi Dinamik XOR Algoritması ile Maskeleniyor...\e[0m"
    sleep(0.8)
    # Her bir baytı seçilen karakterle XOR işlemine sokar
    result = data.bytes.map { |b| b ^ key_char.ord }.pack('C*')
    Base64.strict_encode64(result)
  end

  # Modül 2: Kurumsal AES-256-CBC Şifreleme Motoru
  def aes_encrypt(payload_data)
    puts "\e[33m[*] Girdi Verisi AES-256-CBC Askeri Standartla Şifreleniyor...\e[0m"
    sleep(0.8)
    
    cipher = OpenSSL::Cipher.new('AES-256-CBC')
    cipher.encrypt
    cipher.key = @aes_key
    cipher.iv = @aes_iv

    encrypted = cipher.update(payload_data) + cipher.final
    Base64.strict_encode64(encrypted)
  end
end

if __FILE__ == $0
  evasion = MarkOsPayloadEvasion.new
  
  puts "\e[32m=== MARKOS CRYPTOGRAPHY & PAYLOAD GENERATOR ===\e[0m"
  print "\e[36m[?] Maskelenecek Test Payload Verisini Girin: \e[0m"
  raw_payload = gets.chomp.strip
  
  if raw_payload.empty?
    puts "\e[31m[!] Hata: Payload içeriği boş bırakılamaz!\e[0m"
    exit
  end

  # 1. Adım: XOR Algoritması Çalıştırılıyor
  xor_result = evasion.xor_cipher(raw_payload, 'M')
  puts "\e[32m[+] [XOR] Base64 Formatında Maskelenmiş Payload:\e[0m"
  puts "\e[37m    #{xor_result}\e[0m\n\n"

  # 2. Adım: AES Algoritması Çalıştırılıyor
  aes_result = evasion.aes_encrypt(raw_payload)
  puts "\e[32m[+] [AES-256] Güvenli Şifrelenmiş Çıktı Blokları:\e[0m"
  puts "\e[37m    #{aes_result}\e[0m"
  puts "\e[36m---------------------------------------------------------\e[0m"
  puts "\e[32m[i] Analist Notu: Bu çıktılar antivirüs (AV/EDR) imza testlerinde kullanılabilir.\e[0m"
end
