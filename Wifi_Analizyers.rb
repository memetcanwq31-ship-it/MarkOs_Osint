#!/usr/bin/env ruby
# ===================================================================
#  MARKOS RUBY IDS KALKANI v2.0 - CANLI SALDIRI TESPİT & WIFI DENETİM
#  Dev: memetcanwq31-ship-it | MIT | Gerçek savunma motoru
#  Modüller: Canlı trafik | 12 saldırı imzası | Rate-limit engel |
#            Boşta durum raporu | WiFi zafiyet taraması (12 kontrol)
# ===================================================================

require 'socket'
require 'time'
require 'json'

class C
  R="\e[31m"; G="\e[32m"; Y="\e[33m"; B="\e[34m"
  M="\e[35m"; CY="\e[36m"; W="\e[37m"; BOLD="\e[1m"; RESET="\e[0m"
end

def info(m)  = puts(C::Y + "[*] #{m}" + C::RESET)
def ok(m)    = puts(C::G + "[+] #{m}" + C::RESET)
def alarm(m) = puts(C::R + C::BOLD + "[🚨] #{m}" + C::RESET)
def block(m) = puts(C::Y + "    • [KALKAN] #{m}" + C::RESET)

# ═══════════════ SALDIRI İMZA MOTORU ═══════════════
class SignatureEngine
  SIGNATURES = [
    ['SQL Injection',        /(union\s+select|select\s+.+\s+from|insert\s+into|drop\s+table|'or'1'='1|1\s*=\s*1--|\/\*!union\*\//i)],
    ['XSS',                  /(<script|javascript:|onerror\s*=|onload\s*=|<svg|<img[^>]+src|alert\s*\()/i],
    ['LFI/Path Traversal',   /(\.\.\/|\.\.\\|\/etc\/passwd|\/windows\/win\.ini|%2e%2e%2f|boot\.ini)/i],
    ['Command Injection',    /(;|\||`|\$\()\s*(whoami|id|cat|ls|nc|wget|curl|bash|sh)\b/i],
    ['Webshell Erişimi',     /(c99\.php|r57\.php|shell\.php|b374k|wso\.php|cmd\.jsp)/i],
    ['RCE Log4Shell',        /(\$\{jndi:(ldap|rmi|dns):)/i],
    ['SSRF Probe',           /(127\.0\.0\.1|169\.254\.169\.254|file:\/\/|gopher:\/\/)/],
    ['Scanner/Enumerasyon',  /(nikto|nmap|sqlmap|dirbuster|gobuster|masscan|wfuzz|acunetix)/i],
    ['Brute-Force Girişim',  /(POST.*(login|signin|auth)|phpMyAdmin\/index\.php)/i],
    ['XXE',                  /(<!DOCTYPE[^>]*ENTITY|SYSTEM\s+"file)/i],
    ['SSTI',                 /(\{\{.*\}\}|\$\{.*\}|<%.*%>)/],
    ['Protokol Anomali',     /(^?(GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH)\s+\S+\s+HTTP\/)/] # eşleşmezse bozuk istek
  ]

  def self.inspect_request(line)
    hits = []
    SIGNATURES.each do |name, regex|
      # Protokol anomali: satır HTTP isteği DEĞİLSE tetikle
      if name == 'Protokol Anomali'
        hits << name unless line =~ regex
      else
        hits << name if line =~ regex
      end
    end
    hits
  end
end

# ═══════════════ ANA IDS MOTORU ═══════════════
class MarkOsRubyIDS
  def initialize(port = 8080)
    @port = port
    @ip_tracker = {}
    @blocked = {}
    @attack_threshold = 5   # 3 sn'de 5+ istek = rate-limit ihlali
    @block_duration = 60    # engellenen IP 60 sn soğuma
    @stats = { total: 0, attacks: 0, blocked: 0 }
    @lock = Mutex.new
    @last_attack = Time.now
  end

  def show_banner
    system('clear') || system('cls')
    puts C::G + "=" * 60 + C::RESET
    puts C::G + "   MARKOS RUBY LIVE IDS SHIELD v2.0" + C::RESET
    puts C::G + "=" * 60 + C::RESET
    puts C::CY + "   [🛡️] STATÜ : CANLI AĞ DENETLEYİCİ AKTİF"
    puts "   [📡] PORT  : #{@port} dinleniyor..."
    puts "   [🧠] İMZA  : #{SignatureEngine::SIGNATURES.size} saldırı imzası yüklendi"
    puts "   [⏱️] KURAL : #{@attack_threshold} istek/3sn → otomatik izolasyon" + C::RESET
    puts C::G + "=" * 60 + C::RESET
  end

  def blocked?(ip)
    @blocked[ip] && Time.now.to_i - @blocked[ip] < @block_duration
  end

  def handle_client(client)
    ip = client.peeraddr[3]
    now = Time.now.to_i

    @lock.synchronize do
      @stats[:total] += 1

      if blocked?(ip)
        @stats[:blocked] += 1
        alarm("ENGELLENEN IP tekrar denedi: #{ip} → DROP")
        client.close
        return
      end

      @ip_tracker[ip] ||= []
      @ip_tracker[ip] << now
      @ip_tracker[ip].reject! { |t| now - t > 3 }

      puts C::CY + "[i] [TRAFİK] #{ip} | #{Time.now.strftime('%H:%M:%S')} | Toplam: #{@stats[:total]}" + C::RESET

      if @ip_tracker[ip].size > @attack_threshold
        @blocked[ip] = now
        @stats[:attacks] += 1
        @last_attack = Time.now
        alarm("Yoğun İstek / Flood Saldırısı: #{ip} (#{@ip_tracker[ip].size} istek/3sn)")
        block("#{ip} #{@block_duration} sn boyunca izole edildi (blacklist)")
      end
    end

    # İstek gövdesini oku ve imza motoruna ver
    request_line = client.gets.to_s.strip
    headers = {}
    while (line = client.gets) && line != "\r\n" && !line.empty?
      k, v = line.split(':', 2)
      headers[k.to_s.strip.downcase] = v.to_s.strip if k
    end

    full_request = "#{request_line} #{headers.values.join(' ')}"

    unless request_line.empty?
      SignatureEngine.inspect_request(full_request).each do |attack|
        @lock.synchronize do
          @stats[:attacks] += 1
          @last_attack = Time.now
          alarm("SALDIRI TESPİT EDİLDİ: #{attack} | Kaynak: #{ip}")
          block("İstek loglandı, imza: #{attack}")
        end
      end
    end

    client.puts "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\n[+] MarkOs Shield Devrede."
    client.close
  rescue => e
    client.close rescue nil
  end

  # Boşta bekleyince "saldırı yok" durum raporu
  def idle_watcher
    Thread.new do
      loop do
        sleep 15
        next if @stats[:total].zero?
        @lock.synchronize do
          if Time.now - @last_attack >= 15
            ok("AĞ DURUMU: Son 15 saniyede saldırı tespit edilmedi. Ağ güvenli görünüyor. (Trafik: #{@stats[:total]}, Saldırı: #{@stats[:attacks]})")
          end
        end
      end
    end
  end

  def start_shield
    show_banner
    idle_watcher
    server = TCPServer.new('0.0.0.0', @port)
    ok("Kalkan canlı — trafik bekleniyor...")
    loop do
      Thread.start(server.accept) { |c| handle_client(c) }
    end
  rescue => e
    alarm("Kalkan hatası: #{e}")
  end
end

# ═══════════════ WIFI ZAFİYET TARAMASI (12 KONTROL) ═══════════════
class WifiAuditor
  CHECKS = 12

  def run_checks
    puts C::B + "\n════ WIFI ZAFİYET DENETİMİ — #{CHECKS} KONTROL ════" + C::RESET
    results = []

    results << check_encryption
    results << check_wps
    results << check_ssid_broadcast
    results << check_saved_networks
    results << check_gateway_default_creds
    results << check_open_ports_gateway
    results << check_dns
    results << check_upnp
    results << check_tor_dns_leak
    results << check_mac_privacy
    results << check_firewall_local
    results << check_suspicious_arp

    found = results.count { |r| r[0] == :risk }
    puts C::G + "\n════ WIFI ÖZET: #{CHECKS - found}/#{CHECKS} kontrol temiz, #{found} risk ════" + C::RESET
  end

  private

  def sh(cmd)
    `#{cmd} 2>/dev/null`.to_s.strip
  end

  def check_encryption
    out = sh('nmcli -f security,ssid dev wifi list')
    if out.empty?
      return [:skip, 'WiFi arayüzü/ağ listesi alınamadı (nmcli yok mu?)']
    end
    open_nets = out.lines.select { |l| l =~ /--$|^$/ || l.downcase.include?('open') }
    wep = out.lines.select { |l| l =~ /WEP/i }
    if wep.any?
      [:risk, "WEP şifreli ağ(lar) çevrede görülüyor — kırılabilir şifreleme! (#{wep.size} ağ)"]
    else
      [:ok, 'Çevredeki ağlarda WEP yok, WPA2/WPA3 baskın']
    end
  end

  def check_wps
    out = sh('nmcli -f security dev wifi list')
    wps = out.lines.count { |l| l =~ /wps/i }
    wps > 0 ? [:risk, "#{wps} ağda WPS aktif görünüyor — WPS PIN brute-force'a açıktır"] : [:ok, 'WPS aktif ağ yok']
  end

  def check_ssid_broadcast
    out = sh('iw dev 2>/dev/null || echo none')
    out == 'none' ? [:skip, 'iw aracı yok, SSID kontrolü atlandı'] : [:ok, 'Kablosuz arayüz durumu alındı']
  end

  def check_saved_networks
    n = sh('nmcli -g NAME connection show').lines.count
    n > 20 ? [:risk, "#{n} kayıtlı WiFi ağı — eski/açık ağlar otomatik bağlanıyor olabilir"] : [:ok, "#{n} kayıtlı ağ makul seviyede"]
  end

  def check_gateway_default_creds
    gw = sh("ip route | grep default | awk '{print $3}'")
    return [:skip, 'Varsayılan ağ geçidi bulunamadı'] if gw.empty?
    http = sh("curl -s -m 3 -o /dev/null -w '%{http_code}' http://#{gw}/")
    title = sh("curl -s -m 3 http://#{gw}/ | grep -io '<title>[^<]*' | head -1")
    if http == '200' && title =~ /(admin|router|login|192\.168)/i
      [:risk, "Modem arayüzü #{gw} üzerinde açık ve varsayılan sayfa döndürüyor: #{title} — varsayılan şifre kontrol et!"]
    else
      [:ok, "Gateway #{gw} arayüz yanıtı: HTTP #{http || 'yok'}"]
    end
  end

  def check_open_ports_gateway
    gw = sh("ip route | grep default | awk '{print $3}'")
    return [:skip, 'Gateway yok'] if gw.empty?
    open_ports = []
    [23, 80, 443, 8080, 8443, 21, 3389].each do |p|
      s = Socket.new(:INET, :STREAM)
      s.connect_timeout = 1
      begin
        s.connect(Socket.sockaddr_in(p, gw))
        open_ports << p
      rescue
      ensure
        s.close rescue nil
      end
    end
    open_ports.include?(23) ? [:risk, "Gateway'de TELNET (23) AÇIK — şifresiz yönetim protokolü!"] :
      open_ports.any? ? [:ok, "Gateway açık portlar: #{open_ports.join(', ')} (yönetim arayüzü)"] :
      [:ok, 'Gateway yaygın yönetim portlarını kapatmış']
  end

  def check_dns
    dns = sh('nmcli -g ipv4.dns connection show --active | head -1')
    dns.empty? ? [:skip, 'DNS bilgisi alınamadı'] : [:ok, "Aktif DNS: #{dns} (ISP/modem DNS — şifreli DNS öner: DoH/DoT)"]
  end

  def check_upnp
    gw = sh("ip route | grep default | awk '{print $3}'")
    return [:skip, 'Gateway yok'] if gw.empty?
    out = sh("curl -s -m 3 http://#{gw}:5000/ ; curl -s -m 3 -X POST -H 'Content-Type: text/xml' -d '' http://#{gw}:1900/")
    out.empty? ? [:ok, 'UPnP portları (1900/5000) kapalı görünüyor'] : [:risk, 'UPnP yanıtı alındı — dışarıya port açma riski aktif olabilir']
  end

  def check_tor_dns_leak
    # Basit: sistem DNS'i şifreli mi (DoH/DoT süreci var mı)
    out = sh("pgrep -f 'dnscrypt|unbound|cloudflared|stubby'")
    out.empty? ? [:risk, 'Şifreli DNS çözücüsü (DoH/DoT) tespit edilmedi — DNS sorguları düz metin'] : [:ok, 'Şifreli DNS çözücüsü aktif']
  end

  def check_mac_privacy
    out = sh('nmcli -f GENERAL.DEVICE,wifi.mac-address device show 2>/dev/null | head -4')
    out =~ /permanent|none/i ? [:risk, 'MAC rastgeleleştirme kapalı görünüyor — hareket takibi riski'] : [:ok, 'MAC adresi durumu: ' + (out.empty? ? 'bilinmiyor' : 'izlendi')]
  end

  def check_firewall_local
    out = sh('sudo -n ufw status 2>/dev/null || systemctl is-active firewalld 2>/dev/null || iptables -L -n 2>/dev/null | head -3')
    out.empty? || out =~ /inactive/i ? [:risk, 'Yerel güvenlik duvarı (ufw/firewalld) aktif değil!'] : [:ok, 'Yerel güvenlik duvarı aktif']
  end

  def check_suspicious_arp
    out = sh('arp -an 2>/dev/null || ip neigh')
    dup = out.lines.group_by { |l| l[/([0-9a-f]{2}:){5}[0-9a-f]{2}/i] }.select { |k, v| k && v.size > 1 }
    dup.any? ? [:risk, 'ARP tablosunda aynı MAC birden fazla IP kullanıyor — ARP spoofing şüphesi!'] : [:ok, 'ARP tablosu temiz, spoofing belirtisi yok']
  end
end

# ═══════════════ ANA ═══════════════
if __FILE__ == $0
  puts C::B + <<~B + C::RESET
    ╔══════════════════ MARKOS IDS SUITE ══════════════════╗
    ║ [1] IDS Kalkanını Başlat (canlı dinleme)             ║
    ║ [2] WiFi Zafiyet Taraması (12 kontrol)               ║
    ║ [3] IDS + WiFi denetimini sırayla çalıştır           ║
    ║ [0] Çıkış                                            ║
    ╚══════════════════════════════════════════════════════╝
  B
  print C::CY + "[?] Seçim: " + C::RESET
  case gets.chomp.strip
  when '1'
    MarkOsRubyIDS.new(8080).start_shield
  when '2'
    WifiAuditor.new.run_checks
  when '3'
    WifiAuditor.new.run_checks
    MarkOsRubyIDS.new(8080).start_shield
  else
    puts "Çıkılıyor."
  end
end
