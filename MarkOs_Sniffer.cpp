/* ===================================================================
 * PROJE ADI    : MarkOs Sniffer Pro v2.0 - Full-Scale Packet Analyzer
 * GELISTIRICI  : memetcanwq31-ship-it (Mor Takim / White Hat)
 * DIL          : Saf C++17, ham soket (Raw Socket) framework
 * OZELLIKLER   : Ethernet / ARP / IPv4 / IPv6 / TCP / UDP / ICMP
 *                DNS sorgu cozumleme, HTTP tespiti, hex-dump,
 *                port/proto/host filtreleme, PCAP kaydi, istatistik
 * DERLEME      : g++ -O2 -std=c++17 markos_pro.cpp -o markos
 * CALISTIRMA   : sudo ./markos -i eth0 -v      (root/yonetici sart)
 * =================================================================== */

#include <iostream>
#include <fstream>
#include <cstring>
#include <cstdint>
#include <csignal>
#include <cstdlib>
#include <ctime>
#include <iomanip>
#include <sstream>
#include <string>
#include <chrono>
#include <map>
#include <vector>
#include <algorithm>

#ifdef _WIN32
    #ifndef _WIN32_WINNT
    #define _WIN32_WINNT 0x0600
    #endif
    #include <winsock2.h>
    #include <ws2tcpip.h>
    #include <mstcpip.h>
    #pragma comment(lib, "ws2_32.lib")
    using socket_t = SOCKET;
    #define SOCKET_INVALID INVALID_SOCKET
#else
    #include <sys/socket.h>
    #include <sys/ioctl.h>
    #include <sys/select.h>
    #include <net/if.h>
    #include <arpa/inet.h>
    #include <unistd.h>
    #include <fcntl.h>
    #include <linux/if_packet.h>
    #include <linux/if_ether.h>
    using socket_t = int;
    #define SOCKET_INVALID (-1)
#endif

/* ------------------------- Renk Motoru --------------------------- */
static bool g_no_color = false;
#define C_RESET  "\x1b[0m"
#define C_GREEN  "\x1b[32m"
#define C_YELLOW "\x1b[33m"
#define C_CYAN   "\x1b[36m"
#define C_RED    "\x1b[31m"
#define C_MAGENTA "\x1b[35m"
#define C_DIM    "\x1b[90m"

/* ------------------------- Yapilar (bit-level) ------------------- */
#pragma pack(push, 1)
struct EthHeader {
    uint8_t  dst[6];
    uint8_t  src[6];
    uint16_t ethertype;
};
struct ArpHeader {
    uint16_t htype, ptype;
    uint8_t  hlen, plen;
    uint16_t oper;
    uint8_t  sha[6];
    uint8_t  spa[4];
    uint8_t  tha[6];
    uint8_t  tpa[4];
};
struct IPv4Header {
    uint8_t  ihl_ver;      // low nibble: IHL, high nibble: version
    uint8_t  tos;
    uint16_t total_len;
    uint16_t id;
    uint16_t frag_off;
    uint8_t  ttl;
    uint8_t  protocol;
    uint16_t checksum;
    uint32_t src;
    uint32_t dst;
};
struct IPv6Header {
    uint32_t ver_tc_fl;    // version(4) | traffic class(8) | flow(20)
    uint16_t payload_len;
    uint8_t  next_header;
    uint8_t  hop_limit;
    uint8_t  src[16];
    uint8_t  dst[16];
};
struct TCPHeader {
    uint16_t src_port;
    uint16_t dst_port;
    uint32_t seq;
    uint32_t ack;
    uint8_t  data_off_res; // high nibble: data offset
    uint8_t  flags;
    uint16_t window;
    uint16_t checksum;
    uint16_t urgent;
};
struct UDPHeader {
    uint16_t src_port;
    uint16_t dst_port;
    uint16_t len;
    uint16_t checksum;
};
struct ICMPHeader {
    uint8_t  type;
    uint8_t  code;
    uint16_t checksum;
    uint32_t rest;
};
struct DNSHeader {
    uint16_t id;
    uint16_t flags;
    uint16_t qdcount;
    uint16_t ancount;
    uint16_t nscount;
    uint16_t arcount;
};
#pragma pack(pop)

/* ------------------------- Global Durum -------------------------- */
static volatile std::sig_atomic_t g_stop = 0;
static void on_signal(int) { g_stop = 1; }
#ifdef _WIN32
static BOOL WINAPI on_console(DWORD) { g_stop = 1; return TRUE; }
#endif

struct Stats {
    uint64_t total_pkts = 0, total_bytes = 0;
    uint64_t eth = 0, arp = 0, ipv4 = 0, ipv6 = 0;
    uint64_t tcp = 0, udp = 0, icmp = 0, icmp6 = 0, dns = 0, http = 0, other = 0;
    std::map<std::string, uint64_t> talkers;
};
static Stats g_stats;

struct Config {
    std::string iface;          // Linux icin arayuz adi (eth0, wlan0...)
    std::string proto;          // tcp|udp|icmp|arp|all
    int         port = 0;       // 0 = filtre yok
    std::string host;           // IP filtre
    long long   max_packets = 0;// 0 = sinirsiz
    bool        verbose = false;
    bool        hex = true;
    bool        quiet = false;
    std::string pcap;           // .pcap kayit dosyasi
};

/* ========================= Yardimcilar =========================== */
static std::string mac_str(const uint8_t* m) {
    std::ostringstream o;
    o << std::hex << std::setfill('0');
    for (int i = 0; i < 6; i++) o << std::setw(2) << (int)m[i] << (i < 5 ? ":" : "");
    return o.str();
}
static std::string ip4_str(uint32_t a) {
    char b[INET_ADDRSTRLEN] = {0};
    struct in_addr ia; ia.s_addr = a;
    if (inet_ntop(AF_INET, &ia, b, sizeof b)) return b;
    return "?";
}
static std::string ip6_str(const uint8_t* a) {
    char b[INET6_ADDRSTRLEN] = {0};
    if (inet_ntop(AF_INET6, a, b, sizeof b)) return b;
    return "?";
}
static std::string now_str() {
    auto tp = std::chrono::system_clock::now();
    auto us = std::chrono::duration_cast<std::chrono::microseconds>(tp.time_since_epoch()) % 1000000;
    std::time_t t = std::chrono::system_clock::to_time_t(tp);
    std::tm tmv;
#ifdef _WIN32
    localtime_s(&tmv, &t);
#else
    localtime_r(&t, &tmv);
#endif
    std::ostringstream o;
    o << std::put_time(&tmv, "%H:%M:%S") << "." << std::setw(6) << std::setfill('0') << us.count();
    return o.str();
}
static void hexdump(const uint8_t* d, size_t len, size_t maxn = 192) {
    size_t n = std::min(len, maxn);
    for (size_t i = 0; i < n; i += 16) {
        std::ostringstream hex, asc;
        for (size_t j = i; j < i + 16 && j < n; j++) {
            hex << std::hex << std::setw(2) << std::setfill('0') << (int)d[j] << " ";
            asc << (d[j] >= 32 && d[j] < 127 ? (char)d[j] : '.');
        }
        std::cout << "        " << C_DIM << std::setw(4) << std::setfill('0') << std::hex << i
                  << "  " << std::left << std::setw(48) << std::setfill(' ') << hex.str()
                  << " |" << asc.str() << "|" << C_RESET << std::endl;
    }
    if (len > maxn) std::cout << "        " << C_DIM << "... (+" << (len - maxn) << " bayt daha)" << C_RESET << std::endl;
}
static uint16_t ip_checksum(const void* data, size_t len) {
    const uint16_t* p = (const uint16_t*)data;
    uint32_t sum = 0;
    while (len > 1) { sum += *p++; len -= 2; }
    if (len) sum += *(const uint8_t*)p;
    while (sum >> 16) sum = (sum & 0xFFFF) + (sum >> 16);
    return (uint16_t)~sum;
}

/* ========================= PCAP Yazici =========================== */
class PcapWriter {
    std::ofstream f;
public:
    bool open(const std::string& path) {
        f.open(path, std::ios::binary);
        if (!f) return false;
        uint32_t magic = 0xA1B2C3D4;         // microsecond pcap
        uint16_t vmaj = 2, vmin = 4;
        int32_t  tz = 0, sig = 0;
        uint32_t snap = 65535, link = 1;     // LINKTYPE_ETHERNET
        f.write((char*)&magic, 4);
        f.write((char*)&vmaj, 2); f.write((char*)&vmin, 2);
        f.write((char*)&tz, 4);   f.write((char*)&sig, 4);
        f.write((char*)&snap, 4); f.write((char*)&link, 4);
        return true;
    }
    void write_packet(const uint8_t* d, size_t caplen, size_t origlen, uint32_t sec, uint32_t usec) {
        if (!f) return;
        f.write((char*)&sec, 4); f.write((char*)&usec, 4);
        uint32_t c = (uint32_t)caplen, o = (uint32_t)origlen;
        f.write((char*)&c, 4); f.write((char*)&o, 4);
        f.write((const char*)d, caplen);
    }
    void close() { if (f) f.close(); }
};

/* ========================= DNS Cozumleme ========================= */
static std::string dns_read_name(const uint8_t* p, size_t pkt_len, size_t off, size_t& name_end) {
    std::string out;
    size_t pos = off, jumps = 0;
    bool jumped = false;
    name_end = off;
    while (pos < pkt_len && jumps < 10) {
        uint8_t l = p[pos];
        if (l == 0) { if (!jumped) name_end = pos + 1; break; }
        if ((l & 0xC0) == 0xC0) {            // compression pointer
            if (pos + 1 >= pkt_len) break;
            uint16_t ptr = ((l & 0x3F) << 8) | p[pos + 1];
            if (!jumped) name_end = pos + 2;
            jumped = true; pos = ptr; jumps++;
            continue;
        }
        pos++;
        if (pos + l > pkt_len) break;
        if (!out.empty()) out += '.';
        out.append((const char*)p + pos, l);
        pos += l;
        if (!jumped) name_end = pos;
    }
    return out;
}
static std::string dns_type_name(uint16_t t) {
    switch (t) {
        case 1: return "A";    case 2: return "NS";   case 5: return "CNAME";
        case 6: return "SOA";  case 12: return "PTR"; case 15: return "MX";
        case 16: return "TXT"; case 28: return "AAAA"; case 33: return "SRV";
        case 255: return "ANY"; default: { std::ostringstream o; o << "T" << t; return o.str(); }
    }
}

/* ========================= Filtre Motoru ========================= */
static bool proto_match(const std::string& f, const std::string& actual) {
    return f.empty() || f == "all" || f == actual;
}
static bool port_match(int filter, int p1, int p2) {
    return filter == 0 || p1 == filter || p2 == filter;
}

/* ========================= TCP Bayraklari ======================== */
static std::string tcp_flags_str(uint8_t f) {
    std::string s;
    if (f & 0x01) s += "FIN ";
    if (f & 0x02) s += "SYN ";
    if (f & 0x04) s += "RST ";
    if (f & 0x08) s += "PSH ";
    if (f & 0x10) s += "ACK ";
    if (f & 0x20) s += "URG ";
    if (f & 0x40) s += "ECE ";
    if (f & 0x80) s += "CWR ";
    if (s.empty()) s = "--- ";
    s.pop_back();
    return s;
}

/* ========================= HTTP Tespiti ========================== */
static bool looks_like_http(const uint8_t* d, size_t n, std::string& method) {
    static const char* kw[] = {"GET ", "POST ", "PUT ", "DELETE ", "HEAD ", "OPTIONS ", "PATCH ", "HTTP/"};
    for (const char* k : kw)
        if (n >= strlen(k) && memcmp(d, k, strlen(k)) == 0) { method = k; return true; }
    return false;
}

/* ========================= Dissektorlar ========================== */
static void dissect_tcp(const uint8_t* p, size_t len, const std::string& src, const std::string& dst,
                        bool v6, const Config& cfg) {
    if (len < sizeof(TCPHeader)) return;
    TCPHeader* t = (TCPHeader*)p;
    int sport = ntohs(t->src_port), dport = ntohs(t->dst_port);
    if (!port_match(cfg.port, sport, dport)) return;
    size_t hlen = ((t->data_off_res >> 4) & 0xF) * 4;
    if (hlen < 20 || hlen > len) hlen = 20;
    const uint8_t* payload = p + hlen;
    size_t plen = (len > hlen) ? len - hlen : 0;

    bool dns_pkt = (sport == 53 || dport == 53);
    std::string method;
    bool is_http = plen > 0 && looks_like_http(payload, plen, method);

    if (!proto_match(cfg.proto, "tcp")) return;
    g_stats.tcp++;
    if (dns_pkt) g_stats.dns++;
    if (is_http) g_stats.http++;
    g_stats.talkers[src]++;

    std::cout << C_GREEN << "[TCP] " << src << ":" << sport << " -> " << dst << ":" << dport << C_RESET
              << " [" << C_YELLOW << tcp_flags_str(t->flags) << C_RESET << "]"
              << " Seq=" << std::hex << ntohl(t->seq) << " Ack=" << ntohl(t->ack) << std::dec
              << " Win=" << ntohs(t->window) << C_DIM
              << " | " << plen << "B payload" << C_RESET << std::endl;

    if (dns_pkt && plen >= sizeof(DNSHeader)) {
        DNSHeader* dh = (DNSHeader*)payload;
        size_t end = 0;
        std::string qname = dns_read_name(payload, plen, sizeof(DNSHeader), end);
        uint16_t qtype = 0;
        if (end + 4 <= plen) memcpy(&qtype, payload + end, 2);
        std::cout << "    " << C_CYAN << "[DNS] id=0x" << std::hex << std::setw(4) << std::setfill('0')
                  << ntohs(dh->id) << std::dec << " QD=" << ntohs(dh->qdcount) << " AN=" << ntohs(dh->ancount)
                  << " | " << (qname.empty() ? "?" : qname) << " " << dns_type_name(ntohs(qtype)) << C_RESET << std::endl;
    }
    if (is_http) {
        std::string first((const char*)payload, std::min(plen, (size_t)60));
        std::cout << "    " << C_MAGENTA << "[HTTP] " << first << C_RESET << std::endl;
    }
    if (cfg.hex && plen > 0) hexdump(payload, plen);
}

static void dissect_udp(const uint8_t* p, size_t len, const std::string& src, const std::string& dst,
                        bool v6, const Config& cfg) {
    (void)v6;
    if (len < sizeof(UDPHeader)) return;
    UDPHeader* u = (UDPHeader*)p;
    int sport = ntohs(u->src_port), dport = ntohs(u->dst_port);
    if (!port_match(cfg.port, sport, dport)) return;
    const uint8_t* payload = p + sizeof(UDPHeader);
    size_t plen = (len > sizeof(UDPHeader)) ? len - sizeof(UDPHeader) : 0;
    bool dns_pkt = (sport == 53 || dport == 53);

    if (!proto_match(cfg.proto, "udp")) return;
    g_stats.udp++;
    if (dns_pkt) g_stats.dns++;
    g_stats.talkers[src]++;

    std::cout << C_GREEN << "[UDP] " << src << ":" << sport << " -> " << dst << ":" << dport << C_RESET
              << C_DIM << " | " << plen << "B payload" << C_RESET << std::endl;

    if (dns_pkt && plen >= sizeof(DNSHeader)) {
        DNSHeader* dh = (DNSHeader*)payload;
        size_t end = 0;
        std::string qname = dns_read_name(payload, plen, sizeof(DNSHeader), end);
        uint16_t qtype = 0;
        if (end + 4 <= plen) memcpy(&qtype, payload + end, 2);
        std::cout << "    " << C_CYAN << "[DNS] id=0x" << std::hex << std::setw(4) << std::setfill('0')
                  << ntohs(dh->id) << std::dec << " QD=" << ntohs(dh->qdcount)
                  << " | " << (qname.empty() ? "?" : qname) << " " << dns_type_name(ntohs(qtype)) << C_RESET << std::endl;
    }
    if (cfg.hex && plen > 0) hexdump(payload, plen);
}

static void dissect_icmp(const uint8_t* p, size_t len, const std::string& src, const std::string& dst,
                         bool v6, const Config& cfg) {
    if (len < sizeof(ICMPHeader)) return;
    if (!proto_match(cfg.proto, "icmp")) return;
    ICMPHeader* ic = (ICMPHeader*)p;
    const char* tname = "?";
    if (!v6) {
        switch (ic->type) {
            case 0: tname = "Echo Reply"; break;
            case 3: tname = "Destination Unreachable"; break;
            case 5: tname = "Redirect"; break;
            case 8: tname = "Echo Request"; break;
            case 11: tname = "Time Exceeded"; break;
        }
        g_stats.icmp++;
    } else {
        switch (ic->type) {
            case 128: tname = "v6 Echo Request"; break;
            case 129: tname = "v6 Echo Reply"; break;
            case 1:   tname = "v6 Dest Unreachable"; break;
            case 2:   tname = "v6 Packet Too Big"; break;
            case 3:   tname = "v6 Time Exceeded"; break;
        }
        g_stats.icmp6++;
    }
    g_stats.talkers[src]++;
    std::cout << C_YELLOW << "[ICMP" << (v6 ? "v6" : "") << "] " << src << " -> " << dst
              << " | Tip=" << (int)ic->type << " Kod=" << (int)ic->code
              << " (" << tname << ")" << C_RESET << std::endl;
}

static void dissect_ipv4(const uint8_t* p, size_t len, const Config& cfg) {
    if (len < sizeof(IPv4Header)) return;
    IPv4Header* ip = (IPv4Header*)p;
    if ((ip->ihl_ver >> 4) != 4) return;
    size_t hlen = (ip->ihl_ver & 0xF) * 4;
    if (hlen < 20 || hlen > len) return;

    std::string src = ip4_str(ip->src), dst = ip4_str(ip->dst);
    bool host_ok = cfg.host.empty() || src == cfg.host || dst == cfg.host;
    if (!host_ok) return;

    uint16_t frag = ntohs(ip->frag_off);
    bool fragmented = (frag & 0x3FFF) || (frag & 0x2000);
    const uint8_t* l4 = p + hlen;
    size_t l4len = (ntohs(ip->total_len) > hlen && ntohs(ip->total_len) <= len)
                       ? ntohs(ip->total_len) - hlen : len - hlen;

    if (cfg.verbose) {
        std::cout << C_DIM << "  [IPv4] " << src << " -> " << dst
                  << " | ID=" << std::hex << ntohs(ip->id) << std::dec
                  << " TTL=" << (int)ip->ttl
                  << " FragOff=" << (frag & 0x1FFF) << ((frag & 0x2000) ? " MF" : "")
                  << " CKSUM " << ((ip_checksum(p, hlen) == 0) ? "OK" : "BAD") << C_RESET << std::endl;
    }
    if (fragmented && (frag & 0x1FFF) != 0) {
        std::cout << C_DIM << "  [IPv4] Parcalanmis paket parcasi (MF/offset), L4 ayristirilmadi." << C_RESET << std::endl;
        return;
    }

    switch (ip->protocol) {
        case 6:  dissect_tcp(l4, l4len, src, dst, false, cfg); break;
        case 17: dissect_udp(l4, l4len, src, dst, false, cfg); break;
        case 1:  dissect_icmp(l4, l4len, src, dst, false, cfg); break;
        default:
            if (proto_match(cfg.proto, "all")) {
                g_stats.other++;
                std::cout << C_DIM << "[IPv4] " << src << " -> " << dst << " | Protokol=" << (int)ip->protocol
                          << " (" << l4len << "B)" << C_RESET << std::endl;
            }
    }
}

static void dissect_ipv6(const uint8_t* p, size_t len, const Config& cfg) {
    if (len < sizeof(IPv6Header)) return;
    IPv6Header* ip6 = (IPv6Header*)p;
    if ((ntohl(ip6->ver_tc_fl) >> 28) != 6) return;
    std::string src = ip6_str(ip6->src), dst = ip6_str(ip6->dst);
    bool host_ok = cfg.host.empty() || src == cfg.host || dst == cfg.host;
    if (!host_ok) return;

    const uint8_t* l4 = p + sizeof(IPv6Header);
    size_t l4len = (ntohs(ip6->payload_len) <= len - sizeof(IPv6Header))
                       ? ntohs(ip6->payload_len) : len - sizeof(IPv6Header);

    if (cfg.verbose)
        std::cout << C_DIM << "  [IPv6] " << src << " -> " << dst
                  << " | NH=" << (int)ip6->next_header << " HopLimit=" << (int)ip6->hop_limit << C_RESET << std::endl;

    switch (ip6->next_header) {
        case 6:  dissect_tcp(l4, l4len, src, dst, true, cfg); break;
        case 17: dissect_udp(l4, l4len, src, dst, true, cfg); break;
        case 58: dissect_icmp(l4, l4len, src, dst, true, cfg); break;
        default:
            if (proto_match(cfg.proto, "all")) {
                g_stats.other++;
                std::cout << C_DIM << "[IPv6] " << src << " -> " << dst << " | NH=" << (int)ip6->next_header
                          << " (" << l4len << "B)" << C_RESET << std::endl;
            }
    }
}

static void dissect_arp(const uint8_t* p, size_t len, const Config& cfg) {
    if (!proto_match(cfg.proto, "arp")) return;
    if (len < sizeof(ArpHeader)) return;
    ArpHeader* a = (ArpHeader*)p;
    g_stats.arp++;
    std::string op = (ntohs(a->oper) == 1) ? "REQUEST (Kim ...?)" : (ntohs(a->oper) == 2 ? "REPLY" : "OP" + std::to_string(ntohs(a->oper)));
    std::cout << C_MAGENTA << "[ARP] " << op << " | " << mac_str(a->sha) << " (" << ip4_str(*(uint32_t*)a->spa) << ")"
              << " -> " << mac_str(a->tha) << " (" << ip4_str(*(uint32_t*)a->tpa) << ")" << C_RESET << std::endl;
}

/* Ethernet (Linux AF_PACKET) ya da ham-IP (Windows) girisi */
static void dissect_frame(const uint8_t* buf, size_t len, bool with_eth, const Config& cfg) {
    g_stats.total_pkts++;
    g_stats.total_bytes += len;
    if (!with_eth) { dissect_ipv4(buf, len, cfg); return; }

    if (len < sizeof(EthHeader)) return;
    g_stats.eth++;
    EthHeader* e = (EthHeader*)buf;
    uint16_t et = ntohs(e->ethertype);
    const uint8_t* payload = buf + sizeof(EthHeader);
    size_t plen = len - sizeof(EthHeader);

    if (cfg.verbose)
        std::cout << C_DIM << "  [ETH] " << mac_str(e->src) << " -> " << mac_str(e->dst)
                  << " | EtherType=0x" << std::hex << std::setw(4) << std::setfill('0') << et << std::dec << C_RESET << std::endl;

    if (et == 0x0800)      { g_stats.ipv4++; dissect_ipv4(payload, plen, cfg); }
    else if (et == 0x86DD) { g_stats.ipv6++; dissect_ipv6(payload, plen, cfg); }
    else if (et == 0x0806) { dissect_arp(payload, plen, cfg); }
    else if (proto_match(cfg.proto, "all"))
        std::cout << C_DIM << "[ETH] EtherType=0x" << std::hex << et << std::dec << " (" << plen << "B)" << C_RESET << std::endl;
}

/* ========================= Banner & Yardim ======================= */
static void banner() {
    std::cout << C_CYAN
"=====================================================\n"
"   __  __            _  ___       _____  __ _  __\n"
"  |  \\/  | __ _ _ __| |/ / |__   / /___\\/ _\\ \\/ /\n"
"  | |\\/| |/ _` | '__| ' /| '_ \\ / //  //\\ \\ \\  / \n"
"  | |  | | (_| | |  | . \\| | | / / \\_// _\\ \\/ /  \n"
"  |_|  |_|\\__,_|_|  |_|\\_\\_| |_|\\_\\___/  \\_/_/\\_\\  \n"
"=====================================================\n" << C_RESET;
    std::cout << "  MarkOs Sniffer Pro v2.0 | Saf C++ | Mor Takim SOC\n"
              << "  Gelistirici: memetcanwq31-ship-it | Beyaz Sapka Modu\n"
              << C_CYAN << "=====================================================\n" << C_RESET;
}
static void usage(const char* av0) {
    std::cout << "Kullanim: " << av0 << " [secenekler]\n"
              << "  -i <arayuz>   Dinlenecek ag karti (Linux: eth0, wlan0...)\n"
              << "  -p <port>     Sadece bu portu goster (orn: -p 80)\n"
              << "  -proto <t>    Filtre: tcp | udp | icmp | arp | all\n"
              << "  -host <ip>    Sadece bu IP ile ilgili trafigi goster\n"
              << "  -c <N>        N paket sonra dur\n"
              << "  -o <dosya>    Trafigi .pcap dosyasina kaydet (Wireshark ile acilir)\n"
              << "  -v            Ayrintili mod (IP basliklari, checksum vs.)\n"
              << "  -x            Hex-dump'i kapat\n"
              << "  -nc           Renkleri kapat\n"
              << "  -q            Sessiz mod (sadece istatistik)\n"
              << "  -h            Bu yardimi goster\n\n"
              << "Ornek: sudo " << av0 << " -i eth0 -p 53 -v\n"
              << "       sudo " << av0 << " -i eth0 -proto tcp -c 100 -o yakalama.pcap\n";
}

/* ========================= Ana Fonksiyon ========================= */
int main(int argc, char** argv) {
    banner();
    Config cfg;
    for (int i = 1; i < argc; i++) {
        std::string a = argv[i];
        auto next = [&](const char* k) -> std::string {
            if (i + 1 >= argc) { std::cout << C_RED << "[HATA] " << k << " degeri eksik!\n" << C_RESET; exit(1); }
            return argv[++i];
        };
        if (a == "-i")       cfg.iface = next("iface");
        else if (a == "-p")      cfg.port = std::atoi(next("port").c_str());
        else if (a == "-proto")  cfg.proto = next("proto");
        else if (a == "-host")   cfg.host = next("host");
        else if (a == "-c")      cfg.max_packets = atoll(next("count").c_str());
        else if (a == "-o")      cfg.pcap = next("pcap");
        else if (a == "-v")      cfg.verbose = true;
        else if (a == "-x")      cfg.hex = false;
        else if (a == "-q")      cfg.quiet = true;
        else if (a == "-nc")     g_no_color = true;
        else if (a == "-h")      { usage(argv[0]); return 0; }
        else { std::cout << C_RED << "[HATA] Bilinmeyen secenek: " << a << "\n" << C_RESET; usage(argv[0]); return 1; }
    }
    std::transform(cfg.proto.begin(), cfg.proto.end(), cfg.proto.begin(), ::tolower);

    std::signal(SIGINT, on_signal);
#ifdef _WIN32
    SetConsoleCtrlHandler(on_console, TRUE);
    WSADATA wd;
    if (WSAStartup(MAKEWORD(2, 2), &wd)) {
        std::cout << C_RED << "[HATA] WSAStartup basarisiz!\n" << C_RESET; return 1;
    }
#endif

    /* ---- Ham soketi ac ---- */
    socket_t sock = SOCKET_INVALID;
    bool with_eth = false;
#ifdef _WIN32
    sock = socket(AF_INET, SOCK_RAW, IPPROTO_IP);
    if (sock == INVALID_SOCKET) {
        std::cout << C_RED << "[ACCESS DENIED] Ham soket acilamadi! Yonetici olarak calistirin.\n" << C_RESET;
        WSACleanup(); return 1;
    }
    DWORD in = 1, out = 0, ret = 0;
    if (WSAIoctl(sock, SIO_RCVALL, &in, sizeof(in), &out, sizeof(out), &ret, NULL, NULL) == SOCKET_ERROR) {
        std::cout << C_YELLOW << "[!] SIO_RCVALL ayarlanamadi, promiscuous kapali olabilir.\n" << C_RESET;
    }
#else
    sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (sock < 0) {
        std::cout << C_RED << "[ACCESS DENIED] Ham soket acilamadi!\n"
                  << C_YELLOW << "[i] sudo ile calistirin:  sudo " << argv[0] << " -i eth0 -v\n" << C_RESET;
        return 1;
    }
    with_eth = true;
    if (!cfg.iface.empty()) {
        struct ifreq ifr; memset(&ifr, 0, sizeof ifr);
        strncpy(ifr.ifr_name, cfg.iface.c_str(), IFNAMSIZ - 1);
        if (ioctl(sock, SIOCGIFINDEX, &ifr) < 0) {
            std::cout << C_RED << "[HATA] Arayuz bulunamadi: " << cfg.iface << "\n" << C_RESET;
            close(sock); return 1;
        }
        struct sockaddr_ll sll; memset(&sll, 0, sizeof sll);
        sll.sll_family = AF_PACKET; sll.sll_ifindex = ifr.ifr_ifindex; sll.sll_protocol = htons(ETH_P_ALL);
        if (bind(sock, (struct sockaddr*)&sll, sizeof sll) < 0) {
            std::cout << C_RED << "[HATA] Arayuze baglanamadi!\n" << C_RESET; close(sock); return 1;
        }
#ifdef PACKET_ADD_MEMBERSHIP
        struct packet_mreq mr; memset(&mr, 0, sizeof mr);
        mr.mr_ifindex = ifr.ifr_ifindex; mr.mr_type = PACKET_MR_PROMISC;
        if (setsockopt(sock, SOL_PACKET, PACKET_ADD_MEMBERSHIP, &mr, sizeof mr) == 0)
            std::cout << C_GREEN << "[+] Promiscuous mod aktif (" << cfg.iface << ")\n" << C_RESET;
#endif
    }
#endif
    std::cout << C_GREEN << "[+] Ham soket acildi. Ag dinleniyor..." << C_RESET
              << C_DIM << " (Ctrl+C ile durdurun)\n" << C_RESET;

    PcapWriter pw;
    if (!cfg.pcap.empty()) {
        if (pw.open(cfg.pcap))
            std::cout << C_CYAN << "[+] PCAP kaydi: " << cfg.pcap << " (Wireshark ile acilabilir)\n" << C_RESET;
        else
            std::cout << C_RED << "[!] PCAP dosyasi acilamadi: " << cfg.pcap << "\n" << C_RESET;
    }

    uint8_t buf[65536];
    while (!g_stop && (cfg.max_packets == 0 || (long long)g_stats.total_pkts < cfg.max_packets)) {
        fd_set rf; FD_ZERO(&rf); FD_SET((int)sock, &rf);
        struct timeval tv { 0, 100000 }; // 100ms -> Ctrl+C'ye duyarli
        int r = select((int)sock + 1, &rf, nullptr, nullptr, &tv);
        if (r <= 0) continue;

        ssize_t n;
#ifdef _WIN32
        n = recv(sock, (char*)buf, sizeof buf, 0);
        if (n == SOCKET_ERROR) { if (g_stop) break; continue; }
#else
        n = recvfrom(sock, buf, sizeof buf, 0, nullptr, nullptr);
        if (n < 0) continue;
#endif
        auto tp = std::chrono::system_clock::now();
        uint32_t sec = (uint32_t)std::chrono::duration_cast<std::chrono::seconds>(tp.time_since_epoch()).count();
        uint32_t usec = (uint32_t)(std::chrono::duration_cast<std::chrono::microseconds>(tp.time_since_epoch()).count() % 1000000);

        if (!cfg.quiet)
            std::cout << C_DIM << "[" << now_str() << "] " << C_RESET;
        dissect_frame(buf, (size_t)n, with_eth, cfg);
        pw.write_packet(buf, (size_t)n, (size_t)n, sec, usec);
    }

    /* ---- Istatistik raporu ---- */
    std::cout << "\n" << C_CYAN << "===================== ISTASTIK RAPORU =====================\n" << C_RESET
              << "  Toplam paket : " << g_stats.total_pkts << "  |  Toplam veri: " << g_stats.total_bytes << " bayt\n"
              << "  Ethernet: " << g_stats.eth << "  IPv4: " << g_stats.ipv4 << "  IPv6: " << g_stats.ipv6 << "  ARP: " << g_stats.arp << "\n"
              << "  TCP: " << g_stats.tcp << "  UDP: " << g_stats.udp
              << "  ICMP: " << g_stats.icmp << "  ICMPv6: " << g_stats.icmp6
              << "  DNS: " << g_stats.dns << "  HTTP: " << g_stats.http << "  Diger: " << g_stats.other << "\n";
    if (!g_stats.talkers.empty()) {
        std::cout << "  En aktif konusmacilar:\n";
        std::vector<std::pair<std::string, uint64_t>> v(g_stats.talkers.begin(), g_stats.talkers.end());
        std::sort(v.begin(), v.end(), [](auto& a, auto& b) { return a.second > b.second; });
        for (size_t i = 0; i < std::min<size_t>(5, v.size()); i++)
            std::cout << "    " << std::setw(15) << std::left << v[i].first << " -> " << v[i].second << " paket\n";
    }
    std::cout << C_GREEN << "[+] MarkOs Sniffer Pro analizi tamamlandi. Mor Takim onayladi.\n" << C_RESET;

    pw.close();
#ifdef _WIN32
    closesocket(sock); WSACleanup();
#else
    close(sock);
#endif
    return 0;
}
