# ===================================================================
# PROJE ADI   : MarkOs Waf Analyzer & Fuzzer (Waf_Analyzer_Fuzzer.rb)
# GELİŞTİRİCİ : memetcanwq31-ship-it | Statü: Mor Takım Analiz Laboratuvarı
# ===================================================================

require 'net/http'
require 'uri'

class WafAnalyzerFuzzer
  def initialize
    # WAF koruma duvarının kelime analiz yeteneğini ölçen test girdileri
    @fuzz_payloads = {
      "XSS_Double_Encoding" => "%253Cscript%253Ealert(1)%253C/script%253E",
      "SQLi_Comment_Splitting" => "UNION/**/SELECT/**/null,username/**/FROM/**/users",
      "LFI_Path_Traversal"  => "../../../../etc/passwd"
    }
  end

  def run_fuzzer(domain)
    puts "\n\e[32m[*] MarkOs WAF Analiz ve Fuzzing İşlemi Başlatıldı: #{domain}\e[0m"
    @fuzz_payloads.each do |attack_type, payload|
      puts "\n\e[33m[*] Test Ediliyor Katman: #{attack_type}\e[0m"
      uri = URI("https://#{domain}/?search=#{payload}")
      begin
        res = Net::HTTP.get_response(uri)
        # WAF kalkanının koruma kodlarını (403/406/503) kontrol ediyoruz
        if res.code.to_i == 403 || res.code.to_i == 406
          puts "\e[32m  [+] DURUM: BAŞARILI! WAF Filtresi Aktif. İstek Engellendi (HTTP #{res.code})\e[0m"
        else
          puts "\e[31m  [!] UYARI (POTANSİYEL AÇIK): İstek filtrelenmedi, sunucu HTTP #{res.code} döndü!\e[0m"
        end
      rescue => e
        puts "\e[31m  [!] Bağlantı Hatası: #{e}\e[0m"
      end
    end
  end
end

if __FILE__ == $0
  print "\e[36m[?] Test Edilecek Domain (Örn: example.com): \e[0m"
  target = gets.chomp.strip
  exit if target.empty?
  fuzzer = WafAnalyzerFuzzer.new
  fuzzer.run_fuzzer(target)
end
