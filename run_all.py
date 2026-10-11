import os
import sys
import time
from colorama import Fore, Style, init

# Colorama'yı başlatıyoruz (Windows/Linux/Termux tam uyumluluk)
init(autoreset=True)

def get_markos_tools():
    """Kullanıcının repolarındaki tüm Python araçlarını otomatik tarar."""
    home_dir = os.path.expanduser("~")
    # Kullanıcının profilindeki 3 ana repo klasörü
    repo_folders = ["MarkOs_osint", "MarkOs_Hack", "MarkOsXveil"]
    
    tools_list = []
    
    for repo in repo_folders:
        repo_path = os.path.join(home_dir, repo)
        if os.path.exists(repo_path):
            for root, dirs, files in os.walk(repo_path):
                for file in files:
                    # Sadece çalıştırılabilir ana Python araçlarını filtrele
                    if file.endswith(".py") and file != "run_all.py":
                        full_path = os.path.join(root, file)
                        tools_list.append({"name": file, "path": full_path, "repo": repo})
    return tools_list

def main():
    while True:
        os.system('cls' if os.name == 'nt' else 'clear')
        print(f"""{Fore.GREEN}
███╗   ███╗ █████╗ ██████╗ ██╗  ██╗ ██████╗ ███████╗
████╗ ████║██╔══██╗██╔══██╗██║ ██╔╝██╔═══██╗██╔════╝
██╔████╔██║███████║██████╔╝█████╔╝ ██║   ██║███████╗
██║╚██╔╝██║██╔══██║██╔══██╗██╔═██╗ ██║   ██║╚════██║
██║ ╚═╝ ██║██║  ██║██║  ██║██║  ██╗╚██████╔╝███████║
╚═╝     ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝ ╚══════╝
===================================================================
[+] Owner: memetcanwq31 | [+] MarkOs Tüm Repolar Çalıştırma Paneli
===================================================================""")
        
        print(f"{Fore.CYAN}[*] memetcanwq31-ship-it repolarındaki araçlar taranıyor...\n")
        tools = get_markos_tools()
        
        if not tools:
            print(f"{Fore.RED}[!] Repolar bulunamadı veya içi boş! Lütfen önce git clone yapın.")
            print(f"{Fore.GREEN}Öneri: cd ~ && git clone ile repolarınızı çekin.")
            input("\nMenüye dönmek için Enter..."); return
            
        # Bulunan tüm araçları menüye diz
        for idx, tool in enumerate(tools, 1):
            print(f"{Fore.CYAN} [{idx}] {Fore.GREEN}{tool['name']} {Fore.YELLOW}(Repo: {tool['repo']})")
            
        print(f"\n{Fore.RED} [0] Çıkış (Exit)")
        print(f"{Fore.GREEN}===================================================================")
        
        secim = input(f"{Fore.GREEN}MarkOs Paneli > Çalıştırmak istediğiniz araç no: {Style.RESET_ALL}").strip()
        
        if secim == "0":
            print(f"\n{Fore.RED}[!] Panel kapatılıyor. İyi güvenli günler kankam!"); sys.exit(0)
            
        try:
            secim_int = int(secim)
            if 1 <= secim_int <= len(tools):
                selected_tool = tools[secim_int - 1]
                print(f"\n{Fore.YELLOW}[*] {selected_tool['name']} Başlatılıyor... Lütfen bekleyin.\n")
                time.sleep(1)
                
                # Seçilen aracı dizini değiştirerek temiz bir şekilde tetikle
                tool_dir = os.path.dirname(selected_tool['path'])
                os.chdir(tool_dir)
                os.system(f"python \"{selected_tool['path']}\"")
                
                input(f"\n{Fore.GREEN}Araç sonlandı. Panele dönmek için Enter'a basın...")
            else:
                print(f"\n{Fore.RED}[!] Geçersiz numara!"); time.sleep(1)
        except ValueError:
            print(f"\n{Fore.RED}[!] Lütfen geçerli bir seçim yapın!"); time.sleep(1)

if __name__ == "__main__":
    main()
