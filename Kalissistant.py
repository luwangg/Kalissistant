#!/usr/bin/env python
# https://t.me/unk9vvn
import sys, os, time, random

try:
    from colorama import Fore, Back, Style
    r = Fore.RED
    g = Fore.GREEN
    w = Fore.WHITE
    b = Fore.BLUE
    y = Fore.YELLOW
    m = Fore.MAGENTA
    res = Style.RESET_ALL

except ImportError:
    os.system("pip install colorama")
    sys.exit()

def print_logo():
    clear = "\x1b[0m"
    colors = [36, 32, 34, 35, 31, 37]

    x = """
                             `-::///+++/+++/:-.                     
                        `-//:::.-:-`:/..:/`:--++oo/.                
                     -///:-`/.::::/`/:.:/:`o.+/:`:++oo:`            
                  `/+/--`+/-`:.::/+ooo+ooo+/:/-`o:o`+./yo.          
                `+o-/:.::`/+o+//:.+/:-:/:`+o/+os+:`/-/+`:ss.        
              `.:-.`...`.---.---. .``.``` ..:s:::--+:-//s..o/`      
             .:-`.-:`.--..-..-..::..:/:: :+/`/--+/:-oh/-.:-/-y:     
            -/``-:..//-:-.-.+o++:`  +:o-  .+osd+.+:+:.--::::--s+    
           :/`/::`:+:/:-.:+/soo::` .::/:. -:+yyh/do`:+:.yo-o// oo   
          :+`:::.++` .-+.o++:.  `+hhdddddyo. `-ssys:h`  `sy`-//`o+  
         .y`::-.+s`   /:oo+.   `oyhddmmmhmmd.  `:ydhd-`   sy`+-/.h: 
         o/.-..:y`  :o.+/o/    -ssssshhdydhh:    /mds.h`  `h+-:: /d`
        `s`::+-y/   /dsy+.o/`  `++--/ss:.-+o`   :h/yh/s`   :m.y/y`d:
        :s`::--h`  :-/s+o`.o+.  ++--++/+-.+:  `oh--yoh-+.  `m/.:-`s+
        +o`//-+h`  -o:yh-  .sy/`:+sys--ohyo:`/hy.  omydd    ho-::`+y
        +o`//-/h   `:ys/s   `/yy:` ohyshs `/hd+`  -h+ms.`   yo.o/.+y
        :y -:--m`  /s+yho`    `+hh+.-:::-+hdo.`   .mm+sh`  `m:+/o-so
        `h`/:+`h/   :hmh/y   s` `:yds//ydy/` .o- -hoNNy`   :m./:-`d:
         +:`:-.-o`  .:::/o`` :`  ::+osyyy//  :-..:so///`  `y+-/:.:y 
         .s`.:--/+`  -oso+.o. -/ooo+:``:+ysyo/`ohoNmms`   sy./::.h- 
          :+..::.oo`  `:::/yyys. `/:++o+:/` -dmmho+/.    sh./::.so  
           /o`:-:-+y-  .-+yhddmhsh/.```.:+dhmmdNmdy/`  .hs:/:-.os   
            /s./.:--so.   .//+sdmhdms-:dmhdmds++:    `od:-.//-so    
             -s::.:-/:o:. :::--:+oyy/`-oyyo+::-./+/.oh+///+.-h:     
              `+o./-:-:-+so/+//:..`  `` ```/+/so/shs::`///.ss`      
                .oo--+/--/:+osso++s-`os///./+ssso:-//./`.sy-        
                  .+o:`:+/.+`:.:++oooooosoo+::/::+.++./so-          
                     .+o/.-.:/`+/:-:/`/`+ +//-++`:-+ss:`            
                        ./+++:-/-`:/-`+`+`-/--/oos+-                
                            `.:/+++ooo+ooooo+:`                     
                                  Unk9vvN
                           https://t.me/Unk9vvN
"""
    for N, line in enumerate(x.split("\n")):
        sys.stdout.write("\x1b[1;%dm%s%s\n" % (random.choice(colors), line, clear))
        time.sleep(0.01)

def cls():
    linux = 'reset'
    windows = 'cls'
    os.system([linux, windows][os.name == 'nt'])

print_logo()


# Install Pips & Veil-Evasion & Powershell
assistant = os.system("apt update && apt -y install curl gnupg apt-transport-https && curl https://packages.microsoft.com/keys/microsoft.asc | apt-key add - && echo 'deb [arch=amd64] https://packages.microsoft.com/repos/microsoft-debian-stretch-prod stretch main' > /etc/apt/sources.list.d/powershell.list && apt update && apt-get install -y python3-pip python3-crypto python-crypto && pip install osrframework crypto virtualenvwrapper scapy env pwn pybluez pwntools pycurl shodan netifaces python-nmap && pip3 install crypto shodan scapy")

# Clear Autoremove List
assistant += os.system("apt-get install -y libbabeltrace-ctf1 libcdio17 libfile-copy-recursive-perl libisl15 libllvm5.0 liblttng-ust-ctl4 liblttng-ust0 libtcl8.5 libtk8.5 libunwind8 python-subprocess32 python-unicodecsv python3-configargparse python3-flask python3-itsdangerous python3-pyinotify python3-simplejson python3-werkzeug tk8.5 libhttp-parser2.7.1 libsynctex1 openjdk-9-jdk-headless libedataserverui-1.2-1 libqgis-core2.18.17 libedataserver-1.2-22 libx265-146 libpoppler73 libcue1 openjdk-9-jdk libqgis-networkanalysis2.18.17 openjdk-9-jre libcamel-1.2-60 libnfs8 libqgispython2.18.17 python3-jsbeautifier libqgis-gui2.18.17 && pip install osrframework crypto virtualenvwrapper env pwn pybluez pwntools pycurl shodan netifaces python-nmap && pip3 install crypto && apt-get install -y veil veil-evasion && apt-get install -y powershell exiftool")

# Upgrade Kali
assistant += os.system("apt-get upgrade -y")

# Clear Autoremove List
assistant += os.system("apt-get install libqgis-analysis2.18.17 libqgis-server2.18.17 powershell")

# Dist-Upgrade Kali & Install All Tools & Needed Gem Tools
assistant += os.system("apt-get dist-upgrade -y && apt-get install -y tor tcpxtract tesseract-ocr jd-gui rarcrack steghide cupp websploit slowhttptest dnsmasq golang upx-ucl gifsicle adb bettercap mitmf shellter remmina alacarte bleachbit haproxy vlc php-gd uget aria2 smb4k crackle pptpd cppcheck gimp xplico openvas isc-dhcp-server lighttpd php-cgi routersploit python-setuptools ftp build-essential unicorn wifiphisher cmatrix ffmpeg libreoffice nbtscan-unixwiz inspy sublist3r freerdp2-x11 rar tcpflow torsocks tcpreplay osrframework gopher qbittorrent zmap lynx tor-geoipdb privoxy hackrf python-dev python-setuptools libpcap0.8-dev libnetfilter-queue-dev libssl-dev libjpeg-dev libxml2-dev libxslt1-dev libcapstone3 libcapstone-dev libffi-dev pandoc network-manager-openvpn-gnome bluetooth libbluetooth-dev gconf-service gconf2-common apt-transport-https multiarch-support libc++1 libc++abi1 libgconf-2-4 etherape dkms && gem install bettercap && pip install --upgrade pip")

restart = raw_input("[*] Please Restart Kali for Updating Kernel?(y/N): ")
if restart == "y":
    os.system("reboot")
elif restart == "n":
    print("[-] Resume Install Process")
else:
    os.system("reboot")

# Upgrade Kernel Kali
assistant += os.system("apt-get install -y virtualbox libnotify-bin linux-compiler-gcc-7-x86 linux-headers-4.16.0-kali2-amd64 linux-headers-4.16.0-kali2-common linux-headers-amd64 linux-kbuild-4.16 virtualbox-guest-dkms virtualbox-guest-utils\napt-get install -y virtualbox-guest-x11")

# Fix Configs
assistant += os.system("wget https://github.com/unk9vvn/Kalissistant/raw/master/vlc -o /usr/bin/vlc && chmod +x /usr/bin/vlc && cp /root/vlc /usr/bin/vlc && chmod +x /usr/bin/vlc && rm /root/vlc && cd ~/Kalissistant && rm v* && wget https://github.com/unk9vvn/Kalissistant/raw/master/vlc && chmod +x *")

# Install Veil
veil = raw_input("[*] Confim Install Veil-Evasion?(y/N): ")
if veil == "y":
    os.system("veil --setup && /usr/share/veil/config/setup.sh --force --silent")
elif veil == "n":
    print("[-] Resume Install Process")
else:
    os.system("veil --setup")

# Install KDE Plasma Desktop
kde = raw_input("[*] Install KDE Plasma Desktop?(y/N): ")
if kde == "y":
    os.system("apt-get install -y kde-plasma-desktop")
elif kde == "n":
    print("[-] Resume Install Process")
else:
    os.system("apt-get install -y kde-plasma-desktop")

# Install OpenVAS
openvas = raw_input("[*] Confim Install OpenVAS?(y/N): ")
if openvas == "y":
    os.system("openvas-setup")
elif openvas == "n":
    print("[-] Resume Install Process")
else:
    os.system("openvas-setup")

if openvas == "y":
    print """
		#***Logging Openvas***#
		 Copy PASS Generated
	    Visit > https://127.0.0.1:9392
       Username:(admin) Password:(PASS Generated)
"""

# Show Security firefox Addons
okey = raw_input("[*] Are you needed Security firefox Addons?(y/N): ")
if okey == "y":
   print """
       #***Firefox-Addons***#
	  1.Tamper Data
	  2.HackBar
	  3.Live HTTP headers
	  4.User Agent Switcher
	  5.Flagfox
	  6.Cookie Manager+
	  7.HttpFox
	  8.Fireforce
	  9.Wappalyzer
	  10.Blur
	  11.Poster
	  12.NoRedirect
	  13.Copy As Plain Text
	  14.FoxyProxy Standard
	  15.Cookies Export/Import
	  16.CSRF Finder
	  17.RightClickXSS
	  18.SQL Inject Me
	  19.XSS Me
	  20.Privacy Badger
	  21.Disconnect
	  22.ipFlood
	  23.PassiveRecon
	  24.QR Code Image Generator
	  25.NoScript
  #***Successfully Installation***#

[*] https://addons.mozilla.org/en-US/firefox/addon/
"""

elif okey == "n":
    print("[-] Resume Install Process")
else:
   print """
       #***Firefox-Addons***#
	  1.Tamper Data
	  2.HackBar
	  3.Live HTTP headers
	  4.User Agent Switcher
	  5.Flagfox
	  6.Cookie Manager+
	  7.HttpFox
	  8.Fireforce
	  9.Wappalyzer
	  10.Blur
	  11.Poster
	  12.NoRedirect
	  13.Copy As Plain Text
	  14.FoxyProxy Standard
	  15.Cookies Export/Import
	  16.CSRF Finder
	  17.RightClickXSS
	  18.SQL Inject Me
	  19.XSS Me
	  20.Privacy Badger
	  21.Disconnect
	  22.ipFlood
	  23.PassiveRecon
	  24.QR Code Image Generator
	  25.NoScript
  #***Successfully Installation***#

[*] https://addons.mozilla.org/en-US/firefox/addon/
"""
