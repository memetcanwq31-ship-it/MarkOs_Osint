# ===================================================================
# PROJE ADI   : MarkOs Ruby Canlı Tehdit Yakalama Kalkanı (IDS)
# GELİŞTİRİCİ : memetcanwq31-ship-it | Statü: %100 Gerçek Ağ Savunma Zırhı
# ===================================================================

require 'socket'
require 'time'

class MarkOsLiveIDS
  def initialize(port = 8080)
    @port = port
    @ip_tracker = {}
    @attack_threshold = 5
  end

  def start_shield
    puts "\e[32m[*] MARKOS LIVE IDS SHIELD AKTİF! PORT: #{@port} DİNLENİYOR...\e[0m"
    server = TCPServer.new('0.0.0.0', @port)
    loop do
      Thread.start(server.accept) do |client|
        client_ip = client.peeraddr[3]
        curr_time = Time.now.to_i
        @ip_tracker[client_ip] ||= []
        @ip_tracker[client_ip] << curr_time
        @ip_tracker[client_ip].reject! { |t| curr_time - t > 3 }

        puts "\e[36m[i] [TRAFİK] Gelen Bağlantı -> Kaynak IP: #{client_ip}\e[0m"
        if @ip_tracker[client_ip].size > @attack_threshold
          puts "\e[31m[🚨] [SALDIRI ALARMI] #{client_ip} Konumundan Port Taraması Algılandı!\e[0m"
        end
        client.puts "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\n[+] MarkOs Zırhı Devrede."
        client.close
      end
    end
  end
end

if __FILE__ == $0
  shield = MarkOsLiveIDS.new(8080)
  shield.start_shield
end
