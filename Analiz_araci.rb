#!/usr/bin/env ruby
# ===================================================================
#  MARKOS PURPLE TEAM - ADVANCED ZAFİYET TARAMA MOTORU v2.0
# ===================================================================
#  Dev    : memetcanwq31-ship-it          | Statü : Authorized Lab Scan
#  Modüller: WAF Tespiti | Port Keşfi | robots/sitemap | Admin Panel
#           DB Parmak İzi | Güvenlik Başlıkları | Tech Fingerprint
# ===================================================================

require 'net/http'
require 'socket'
require 'uri'
require 'openssl'
require 'json'

# --- Renk Sabitleri ---
class C
  R  = "\e[31m"; G = "\e[32m"; Y = "\e[33m"; B = "\e[34m"
  M  = "\e[35m"; CY = "\e[36m"; W = "\e[37m"; BOLD = "\e[1m"; RESET = "\e[0m"
end

def banner
  puts C::B + C::BOLD + <<~'BANNER' + C::RESET
    ███╗   ██╗███████╗ █████╗ ██████╗ ██╗  ██╗ ██████╗ ███████╗
    ████╗  ██║██╔════╝██╔══██╗██╔══██╗██║ ██╔╝██╔═══██╗██╔════╝
    ██╔██╗ ██║█████╗  ███████║██████╔╝█████╔╝ ██║   ██║███████╗
    ██║╚██╗██║██╔══╝  ██╔══██║██╔══██╗██╔═██╗ ██║   ██║╚════██║
    ██║ ╚████║███████╗██║  ██║██║  ██║██║  ██╗╚██████╔╝███████║
    ╚═╝  ╚═══╝╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝ ╚══════╝
  BANNER
  puts C::G + "  ╔══════════════════════════════════════════════════════════════╗"
  puts "  ║   MARKOS VULN SCANNER v2.0 - ADVANCED RECON ENGINE           ║"
  puts "  ║   WAF | PORTS | ROBOTS/SITEMAP | ADMIN PANEL | DB FINGERPRINT║"
  puts "  ╚══════════════════════════════════════════════════════════════╝" + C::RESET
end

def info(msg) = puts(C::Y + "[*] #{msg}" + C::RESET)
def ok(msg)   = puts(C::G + "[+] #{msg}" + C::RESET)
def risk(msg) = puts(C::R + "[!] RİSK: #{msg}" + C::RESET)
def found(msg)= puts(C::M + "[~] BULUNDU: #{msg}" + C::RESET)
def section(t)= puts("\n" + C::CY + C::BOLD + "════ #{t} ════" + C::RESET)

class MarkOsZafiyetScanner
  CRITICAL_PORTS = [21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 1433, 1521,
                    3306, 3389, 5432, 5900, 6379, 8080, 8443, 9200, 27017, 11211]

  ADMIN_PATHS = [
    'admin', 'admin/', 'admin/login', 'administrator/', 'adminpanel/',
    'admin/login.php', 'admin/index.php', 'login', 'login.html',
    'wp-admin/', 'wp-login.php', 'administrator/index.php',
    'manage/', 'manager/', 'panel/', 'cpanel', 'dashboard/',
    'user/login', 'auth/login', 'admin/admin.html', 'admin.html'
  ]

  DB_ERROR_SIGNATURES = {
    'MySQL'      => [/mysql_fetch/i, /You have an error in your SQL syntax/i,
                     /Warning: mysql_/i, /mysqli?./i, /MySQLSyntaxErrorException/i],
    'PostgreSQL' => [/PostgreSQL.*ERROR/i, /pg_query\(/i, /valid PostgreSQL result/i,
                     /Npgsql\./i, /PG::SyntaxError/i],
    'MSSQL'      => [/Microsoft OLE DB Provider for SQL Server/i,
                     /Unclosed quotation mark after the character string/i,
                     /\bSQL Server\b.*\bError\b/i, /SQLSTATE\b/i],
    'Oracle'     => [/ORA-\d{5}/i, /Oracle error/i, /Oracle.*Driver/i,
                     /Warning: oci_/i],
    'SQLite'     => [/SQLite\/JDBCDriver/i, /SQLite\.Exception/i,
                     /System\.Data\.SQLite/i, /Warning: sqlite_/i, /SQLITE_ERROR/i],
    'MongoDB'    => [/MongoDB/i, /MongoError/i, /BSONError/i],
    'MariaDB'    => [/MariaDB/i],
    'MS Access'  => [/Microsoft Access Driver/i, /JET Database Engine/i]
  }

  TECH_SIGNATURES = {
    'WordPress'  => ['/wp-content/', '/wp-includes/'],
    'Drupal'     => ['/sites/default/', 'drupal.js'],
    'Joomla'     => ['/media/jui/', 'Joomla!'],
    'Laravel'    => ['XSRF-TOKEN', 'laravel_session'],
    'Django'     => ['csrftoken', '__Secure-COOKIE'],
    'Rails'      => ['_rails_session', 'X-Rails'],
    'ASP.NET'    => ['ASP.NET_SessionId', 'X-Powered-By: ASP.NET'],
    'PHP'        => ['X-Powered-By: PHP', 'PHPSESSID'],
    'Next.js'    => ['__NEXT_DATA__', 'x-nextjs'],
    'Shopify'    => ['x-shopid', 'Shopify'],
    'Cloudflare' => ['cf-ray', 'cloudflare']
  }

  WAF_SIGNATURES = {
    'Cloudflare'    => ['cf-ray', '__cfduid', 'cloudflare-nginx'],
    'AWS WAF'       => ['awswaf', 'x-amzn-requestid'],
    'Akamai'        => ['akamai', 'x-akamai'],
    'Sucuri'        => ['sucuri', 'x-sucuri-id'],
    'Imperva'       => ['incap_ses', 'visid_incap'],
    'ModSecurity'   => ['mod_security', 'modsecurity'],
    'F5 BIG-IP'     => ['bigipserver', 'x-cnection'],
    'Barracuda'     => ['barra', 'barracuda'],
    'Citrix'        => ['ns_af', 'citrix'],
    'Radware'       => ['x-sl-compid', 'radware'],
    'Squarespace'   => ['x-served-by: cache'],
    'KeyCDN'        => ['x-cache: hit'],
    'DDoS-Guard'    => ['ddos-guard'],
    'FortiWeb'      => ['fortiwaf', 'fortigate']
  }

  def initialize
    @user_agent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0 Safari/537.36"
    @findings = []
    @scheme   = 'https'
    @port     = 443
  end

  attr_reader :findings

  # ── HTTP İstek Motoru ──
  def http_request(path = '/', use_ssl = nil, host = nil)
    uri = URI("#{@scheme}://#{host || @target}#{path}")
    http = Net::HTTP.new(uri.host, uri.port)
    http.use_ssl = (uri.scheme == 'https')
    http.verify_mode = OpenSSL::SSL::VERIFY_NONE
    http.open_timeout = 8
    http.read_timeout = 10
    req = Net::HTTP::Get.new(uri.request_uri, { 'User-Agent' => @user_agent, 'Accept' => '*/*' })
    res = http.request(req)
    { code: res.code.to_i, headers: res, body: (res.body rescue ''), uri: uri }
  rescue => e
    { code: 0, error: e.message }
  end

  def header_of(res, name) = res[:headers][name].to_s.downcase rescue ''

  # ── 1. DNS + TLS Analizi ──
  def dns_resolve
    section('1. DNS & IP ÇÖZÜMLEME')
    begin
      @ip = IPSocket.getaddress(@target)
      ok("Çözümlenen IP: #{@ip}")
      @findings << "IP: #{@ip}"
      # PTR kaydı (reverse DNS)
      begin
        ptr = Resolv.getname(@ip)
      rescue
        ptr = nil
      end
      ok("Reverse DNS: #{ptr}") if ptr
    rescue
      risk("Alan adı IP'ye çözümlenemedi!")
      @ip = nil
    end
  end

  def tls_check
    section('2. TLS/SSL SERTİFİKA ANALİZİ')
    begin
      ctx = OpenSSL::SSL::SSLContext.new
      ctx.verify_mode = OpenSSL::SSL::VERIFY_NONE
      tcp = TCPSocket.new(@target, 443)
      ssl = OpenSSL::SSL::SSLSocket.new(tcp, ctx)
      ssl.connect
      cert = ssl.peer_cert
      ok("TLS Sürümü: #{ssl.ssl_version}")
      ok("Sertifika Sahibi: #{cert.subject.to_s.split('/').last(3).join(', ')}")
      not_after = cert.not_after
      days_left = ((not_after - Time.now) / 86_400).to_i
      days_left < 15 ? risk("Sertifika #{days_left} gün içinde doluyor!") : ok("Sertifika geçerlilik: #{days_left} gün")
      ssl.close rescue nil
    rescue => e
      info("TLS analizi atlandı: #{e.message}")
    end
  end

  # ── 2. Güvenlik Duvarı (WAF) Tespiti ──
  def detect_waf
    section('3. GÜVENLİK DUVARI (WAF) TESPİTİ')
    detected = []

    # Yöntem A: Yanıt başlıkları
    res = http_request('/')
    return risk("Ana sayfaya erişilemedi, WAF analizi durdu.") if res[:code].zero?

    header_str = res[:headers].each_header.map { |k, v| "#{k}: #{v}" }.join("\n").downcase
    WAF_SIGNATURES.each do |waf, sigs|
      sigs.each do |sig|
        if header_str.include?(sig.downcase)
          detected << waf unless detected.include?(waf)
        end
      end
    end

    # Yöntem B: WAF challenge sayfası (403 + imza)
    probe = http_request('/?q=<script>alert(1)</script>')
    body = probe[:body].to_s.downcase
    WAF_SIGNATURES.each do |waf, sigs|
      sigs.each do |sig|
        if body.include?(sig.downcase) && !detected.include?(waf)
          detected << waf
        end
      end
    end

    if detected.any?
      found("AKTİF GÜVENLİK DUVARI: #{detected.join(', ')}")
      @findings << "WAF: #{detected.join(', ')}"
      info("Not: Tarama hızını düşür, WAF rate-limit uygulayabilir.")
    else
      ok("Bilinen WAF imzası tespit edilmedi (saf giriş olabilir).")
    end
    detected
  end

  # ── 3. Port Taraması ──
  def port_scan
    section('4. KRİTİK SERVİS PORT KEŞFİ')
    return risk("IP çözümlenemedi, port taraması atlandı.") unless @ip

    open_ports = []
    threads = []
    mutex = Mutex.new
    CRITICAL_PORTS.each do |port|
      threads << Thread.new do
        begin
          sock = Socket.new(:INET, :STREAM)
          sock.connect_timeout = 2
          sock.connect(Socket.sockaddr_in(port, @ip))
          mutex.synchronize do
            svc = service_banner(port)
            found("Port #{port} AÇIK#{svc ? " (#{svc})" : ''}")
            open_ports << port
          end
          sock.close
        rescue Errno::ECONNREFUSED, Errno::ETIMEDOUT, Errno::EHOSTUNREACH, IOError
        rescue => _
        end
      end
    end
    threads.each(&:join)
    risk("Toplam #{open_ports.size} açık port: #{open_ports.join(', ')}") if open_ports.any?
    @findings << "Açık portlar: #{open_ports.join(', ')}"
    open_ports
  end

  def service_banner(port)
    { 21 => 'FTP', 22 => 'SSH', 23 => 'Telnet!', 25 => 'SMTP', 53 => 'DNS',
      80 => 'HTTP', 110 => 'POP3', 143 => 'IMAP', 443 => 'HTTPS',
      445 => 'SMB!', 1433 => 'MSSQL', 1521 => 'Oracle DB', 3306 => 'MySQL DB',
      3389 => 'RDP!', 5432 => 'PostgreSQL DB', 5900 => 'VNC!', 6379 => 'Redis DB!',
      8080 => 'HTTP-Alt', 8443 => 'HTTPS-Alt', 9200 => 'Elasticsearch!',
      27017 => 'MongoDB!', 11211 => 'Memcached!' }[port]
  end

  # ── 4. HTTP Güvenlik Başlıkları (Genişletilmiş) ──
  def header_audit
    section('5. HTTP GÜVENLİK BAŞLIKLARI DENETİMİ')
    res = http_request('/')
    return if res[:code].zero?

    h = {}
    %w[strict-transport-security x-frame-options x-content-type-options
       content-security-policy referrer-policy permissions-policy
       x-xss-protection x-powered-by server].each { |k| h[k] = header_of(res, k) }

    checks = {
      'strict-transport-security'   => 'HSTS yok → MitM/şifresiz dinleme riski',
      'x-frame-options'             => 'X-Frame-Options yok → Clickjacking riski',
      'x-content-type-options'      => 'X-Content-Type-Options yok → MIME sniffing riski',
      'content-security-policy'     => 'CSP yok → XSS/inline script riski',
      'referrer-policy'             => 'Referrer-Policy yok → bilgi sızıntısı',
      'permissions-policy'          => 'Permissions-Policy yok → API izin denetimi zayıf'
    }
    checks.each do |hdr, msg|
      h[hdr].empty? ? risk(msg) : ok("#{hdr}: #{h[hdr]}")
    end

    risk("Server sürümü ifşa: #{h['server']}") unless h['server'].empty?
    risk("Backend dili ifşa: #{h['x-powered-by']}") unless h['x-powered-by'].empty?
    @findings << "Server: #{h['server']}" unless h['server'].empty?
    h
  end

  # ── 5. robots.txt & sitemap.xml Analizi ──
  def recon_files
    section('6. ROBOTS.TXT & SITEMAP.XML ANALİZİ')

    # robots.txt
    res = http_request('/robots.txt')
    if res[:code] == 200 && res[:body] && !res[:body].empty?
      ok("robots.txt mevcut (HTTP 200):")
      disallows = []
      sitemaps = []
      res[:body].each_line do |line|
        l = line.strip
        if l.downcase.start_with?('disallow:') && !l[9..].to_s.strip.empty?
          path = l.split(':', 2)[1].strip
          disallows << path
          puts C::W + "      Disallow: #{path}" + C::RESET
        elsif l.downcase.start_with?('sitemap:')
          sitemaps << l.split(':', 2)[1].strip
          puts C::W + "      Sitemap: #{sitemaps.last}" + C::RESET
        end
      end
      interesting = disallows.select { |d| d =~ /admin|panel|backup|config|secret|private|\.sql|\.bak|\.env|test|dev|old|\.git/i }
      interesting.each { |p| found("robots.txt gizli yol: #{p} → ilginç keşif!") }
      risk("robots.txt üzerinden hassas yol ifşası: #{interesting.join(', ')}") if interesting.any?
      @findings << "robots.txt: #{disallows.size} disallow, #{sitemaps.size} sitemap"
    else
      info("robots.txt bulunamadı (#{res[:code]})")
    end

    # sitemap.xml
    res2 = http_request('/sitemap.xml')
    if res2[:code] == 200 && res2[:body] =~ /<urlset|<sitemapindex/i
      ok("sitemap.xml mevcut (HTTP 200)")
      urls = res2[:body].scan(/<loc>(.*?)<\/loc>/i).flatten
      ok("sitemap.xml toplam #{urls.size} URL listeliyor")
      urls.first(10).each { |u| puts C::W + "      #{u}" + C::RESET }
      admin_urls = urls.select { |u| u =~ /admin|login|panel|dashboard|manage/i }
      admin_urls.each { |u| found("sitemap admin URL: #{u}") }
      @findings << "sitemap.xml: #{urls.size} URL"
    else
      # sitemap_index.xml alternatifi
      res3 = http_request('/sitemap_index.xml')
      ok("sitemap_index.xml mevcut") if res3[:code] == 200
      info("sitemap.xml bulunamadı")
    end

    # Bonus: .env / .git sızıntı kontrolü (kritik zafiyet)
    %w[.env .git/config .git/HEAD backup.sql db.sql].each do |p|
      r = http_request("/#{p}")
      if r[:code] == 200 && !r[:body].to_s.empty? && r[:body].length < 200_000
        found("KRİTİK SIZINTI: /#{p} erişilebilir (HTTP 200)!")
        risk("/#{p} dosyası dış dünyaya açık — veritabanı kimlik bilgileri içerebilir!")
        @findings << "Sızıntı: /#{p}"
      end
    end
  end

  # ── 6. Admin Panel Keşfi ──
  def admin_panel_discovery
    section('7. ADMİN PANEL KEŞFİ MOTORU')
    found_panels = []
    ADMIN_PATHS.each do |path|
      res = http_request("/#{path}")
      next if res[:code].zero?
      # 200/301/302 → panel olabilir; 404 → yok
      if [200, 301, 302, 401, 403].include?(res[:code])
        body = res[:body].to_s.downcase
        login_hints = ['password', 'login', 'giriş', 'kullanıcı', 'username', 'auth', 'oturum']
        is_login = login_hints.count { |h| body.include?(h) } >= 2 || res[:code] != 200
        status = res[:code]
        found_panels << "/#{path}" if [200, 401, 403].include?(status) || is_login
        puts C::M + "    [#{status}] /#{path}" + (is_login ? " ← LOGIN FORM GÖRÜNÜMÜ" : '') + C::RESET
      end
    end

    if found_panels.any?
      found("#{found_panels.size} aday admin paneli tespit edildi:")
      found_panels.each { |p| puts C::M + "      → #{@scheme}://#{@target}#{p.start_with?('/') ? p : '/' + p}" + C::RESET }
      risk("Admin panelleri dış ağdan erişilebilir — brute-force/kimlik denemelerine açık")
      @findings << "Admin panelleri: #{found_panels.join(', ')}"
    else
      ok("Yaygın admin panel yollarında erişilebilir panel bulunamadı.")
    end
    found_panels
  end

  # ── 7. Veritabanı Parmak İzi ──
  def db_fingerprint
    section('8. VERİTABANI PARMAK İZİ ANALİZİ')
    detected_dbs = Set.new([]) rescue []
    detected_dbs = []

    # Yöntem A: Ana sayfa + hata sayfaları gövdesinde DB imza tarama
    ['/','/nonexistent_page_xyz123','/?id=1\'','/?id=1%27','/?search=\'' ,
     '/index.php?id=1\'','/item.php?id=1\''].each do |probe|
      res = http_request(probe)
      body = res[:body].to_s
      DB_ERROR_SIGNATURES.each do |db, sigs|
        sigs.each do |sig|
          if body =~ sig && !detected_dbs.include?(db)
            detected_dbs << db
            found("Veritabanı imzası: #{db} (#{probe} yanıtında)")
          end
        end
      end
    end

    # Yöntem B: Teknoloji imzalarından çıkarım
    res = http_request('/')
    body = res[:body].to_s + res[:headers].each_header.map { |k, v| "#{k}: #{v}" }.join(' ')
    tech_hits = []
    TECH_SIGNATURES.each do |tech, sigs|
      sigs.each do |sig|
        if body.downcase.include?(sig.downcase)
          tech_hits << tech
          break
        end
      end
    end

    # Teknoloji → olası DB çıkarımı
    tech_db_map = {
      'WordPress' => 'MySQL/MariaDB', 'Drupal' => 'MySQL/PostgreSQL',
      'Joomla' => 'MySQL/MariaDB', 'Laravel' => 'MySQL/PostgreSQL',
      'Django' => 'PostgreSQL/MySQL/SQLite', 'Rails' => 'PostgreSQL/MySQL',
      'ASP.NET' => 'MSSQL', 'Next.js' => 'MongoDB/PostgreSQL (yapılandırmaya bağlı)'
    }
    if tech_hits.any?
      ok("Tespit edilen teknolojiler: #{tech_hits.join(', ')}")
      tech_hits.each do |t|
        if tech_db_map[t]
          info("#{t} → muhtemel veritabanı: #{tech_db_map[t]}")
          tech_db_map[t].split('/').each { |d| detected_dbs << d unless detected_dbs.include?(d) }
        end
      end
    else
      info("Yaygın CMS/framework imzası bulunamadı.")
    end

    # Yöntem C: Açık DB portlarından kesin çıkarım
    port_db = { 3306 => 'MySQL/MariaDB', 5432 => 'PostgreSQL', 1433 => 'MSSQL',
                1521 => 'Oracle', 27017 => 'MongoDB', 6379 => 'Redis', 9200 => 'Elasticsearch' }
    open_ports = port_scan_quiet
    open_ports.each do |p|
      if port_db[p]
        found("Port #{p} açık → VERİTABANI DIŞA AÇIK: #{port_db[p]}")
        detected_dbs << port_db[p] unless detected_dbs.include?(port_db[p])
        risk("#{port_db[p]} portu internete açık! (güvenlik duvarı kural eksiği)")
      end
    end

    if detected_dbs.any?
      found("VERİTABANI SONUÇ: #{detected_dbs.uniq.join(', ')}")
      @findings << "DB: #{detected_dbs.uniq.join(', ')}"
    else
      info("Veritabanı imzası doğrudan tespit edilemedi (arka planda gizlenmiş olabilir).")
    end
    detected_dbs.uniq
  end

  def port_scan_quiet
    return [] unless @ip
    open = []
    threads = []
    mutex = Mutex.new
    [3306, 5432, 1433, 1521, 27017, 6379, 9200, 11211].each do |port|
      threads << Thread.new do
        begin
          s = Socket.new(:INET, :STREAM)
          s.connect_timeout = 2
          s.connect(Socket.sockaddr_in(port, @ip))
          mutex.synchronize { open << port }
          s.close
        rescue
        end
      end
    end
    threads.each(&:join)
    open
  end

  # ── 8. Yaygın Zafiyet Probe Testleri ──
  def common_vuln_probes
    section('9. YAYGIN ZAFİYET PROBE TESTLERİ')

    # SQL Injection hata tabanlı probe
    info("Hata tabanlı SQLi probe testi...")
    ['?id=1\'', '?id=1 OR 1=1', '?page=1\''].each do |q|
      res = http_request("/#{q}")
      body = res[:body].to_s
      DB_ERROR_SIGNATURES.values.flatten.each do |sig|
        if body =~ sig
          risk("SQL ENJEKSİYON İŞARETİ: '#{q}' isteğinde veritabanı hatası sızdı!")
          @findings << "SQLi işareti: #{q}"
          break
        end
      end
    end

    # Directory listing
    info("Directory listing kontrolü...")
    ['/uploads/', '/backup/', '/files/', '/static/'].each do |d|
      res = http_request(d)
      if res[:code] == 200 && res[:body] =~ /index of|directory listing for/i
        found("Directory Listing AÇIK: #{d}")
        @findings << "DirListing: #{d}"
      end
    end

    # Güvenli olmayan CORS
    res = http_request('/')
    acao = header_of(res, 'access-control-allow-origin')
    acac = header_of(res, 'access-control-allow-credentials')
    if acao == '*'
      risk("CORS wildcard (*) ile allow-credentials açık → kimlik hırsızlığı riski") if acac == 'true'
    end

    # Cookie güvenlik bayrakları
    set_cookie = res[:headers].get_fields('set-cookie').to_s.downcase rescue ''
    if set_cookie.include?('session') || set_cookie.include?('sess')
      risk("Cookie'de HttpOnly bayrağı yok → XSS ile oturum çalma riski") unless set_cookie.include?('httponly')
      risk("Cookie'de Secure bayrağı yok → şifresiz aktarımda oturum sızıntısı") unless set_cookie.include?('secure')
    end
  end

  # ── Rapor ──
  def final_report
    section('TARAMA RAPORU ÖZETİ')
    @findings.each_with_index { |f, i| puts C::W + "  #{i + 1}. #{f}" + C::RESET }
    puts C::G + "  " + "─" * 60 + C::RESET
    ok("Tarama tamamlandı. Toplam #{@findings.size} kayıt.")
  end

  # ── Ana Akış ──
  def scan(target)
    @target = target
    puts "\n#{C::B}[*] MARKOS Zafiyet Denetimi Başlatıldı: #{target}#{C::RESET}"
    dns_resolve
    return unless @ip
    tls_check
    detect_waf
    header_audit
    recon_files
    admin_panel_discovery
    db_fingerprint
    common_vuln_probes
    final_report
  end
end

# Set sınıfı için basit yedek (require 'set' olmadan)
module Kernel
  class Set; def initialize(x = []) @a = x.uniq; end; end rescue nil
end
require 'set'

if __FILE__ == $0
  banner
  print C::CY + "[?] Analiz Edilecek Domain: " + C::RESET
  target = gets.chomp.strip.sub(/^https?:\/\//, '').sub(/\/.*$/, '')
  if target.empty?
    puts C::R + "[!] Hedef boş olamaz!" + C::RESET
    exit
  end
  scanner = MarkOsZafiyetScanner.new
  scanner.scan(target)
end
