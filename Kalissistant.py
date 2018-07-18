#!/usr/bin/env python
# @a9v8i
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

os.system("service tor start")

def cls():
    linux = 'reset'
    windows = 'cls'
    os.system([linux, windows][os.name == 'nt'])

cls()

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
                              Kalissistant-v2
"""
    for N, line in enumerate(x.split("\n")):
        sys.stdout.write("\x1b[1;%dm%s%s\n" % (random.choice(colors), line, clear))
        time.sleep(0.01)



print_logo()

menu = raw_input("\t[1] Upgrade Kali & Kernel\n\t[2] Install Internal Tools\n\t[3] Install External Tools\n\t[0] Exit\n\nroot@unk9vvn: ")

if menu == "1":
    cls()
    print("\tUpdate the repository of URLs and tools and kernel modules that you install to\n\t"
          "install other tools to prepare the operating system to install other tools.\n\n")
    os.system("apt update && apt list --upgradable && apt -y install curl gnupg apt-transport-https && curl https://packages.microsoft.com/keys/microsoft.asc | apt-key add - && echo 'deb http://http.kali.org/kali kali-rolling main non-free contrib' > /etc/apt/sources.list && echo 'deb [arch=amd64] https://packages.microsoft.com/repos/microsoft-debian-stretch-prod stretch main' > /etc/apt/sources.list.d/powershell.list && apt update && apt-get upgrade -y && apt-get dist-upgrade -y && apt-get full-upgrade -y && apt-get install -y python3-pip python3-crypto python-crypto && pip install osrframework crypto virtualenvwrapper scapy env pwn pybluez pwntools pycurl shodan netifaces python-nmap && pip3 install crypto shodan scapy && gem install bettercap && pip install --upgrade pip")

    # Need to reset Kali for Upgrading Kernel
    restart = raw_input("\t\n[*] Please Restart Kali for Updating Kernel?(y/N): ")
    if restart == "y":
        os.system("reboot")
    elif restart == "n":
        print("\t\n[-] Resume Install Process")
    else:
        os.system("reboot")

if menu == "2":
    cls()
    print("\n\n\tInstall the types of tools available in the operating system\n\t"
          "tank These tools Include Powershell Exiftool Tcpxtract Uget Jd-gui\n\t"
          "Freerdp2-x11 Qbittorrent Tor Crackle Tcpflow VLC Bettercap Cupp\n\t"
          "Etherape dkms Virtualbox Cmatrix Osrframework Virtualbox Shellter\n\t"
          "Xplico Remmina RAR Sublist3r Ffmpeg Libreoffice Wifiphisher Steghide\n\t"
          "Dnsmasq Slowhttptest Routersploit Inspy Bleachbit Alacarte ADB\n\t"
          "Mitmf Xplico Unicorn Osrframework OpenVAS\n\t")

    os.system("apt-get install -y veil veil-evasion && apt-get install -y powershell exiftool && apt-get install -y tor tcpxtract tesseract-ocr jd-gui rarcrack steghide cupp websploit slowhttptest dnsmasq golang upx-ucl gifsicle adb bettercap mitmf shellter parallel remmina alacarte bleachbit haproxy vlc php-gd uget aria2 smb4k crackle pptpd cppcheck gimp xplico openvas isc-dhcp-server lighttpd php-cgi routersploit python-setuptools ftp build-essential unicorn wifiphisher cmatrix ffmpeg libreoffice nbtscan-unixwiz inspy sublist3r freerdp2-x11 rar tcpflow torsocks tcpreplay osrframework gopher qbittorrent zmap lynx tor-geoipdb privoxy hackrf python-dev python-setuptools libpcap0.8-dev libnetfilter-queue-dev libssl-dev libjpeg-dev libxml2-dev libxslt1-dev libcapstone3 libcapstone-dev libffi-dev pandoc network-manager-openvpn-gnome bluetooth libbluetooth-dev gconf-service gconf2-common bridge-utils apt-transport-https multiarch-support libc++1 libc++abi1 libgconf-2-4 etherape dkms virtualbox && wget https://github.com/unk9vvn/Kalissistant/raw/master/vlc -o /usr/bin/vlc && chmod +x /usr/bin/vlc && cp /root/vlc /usr/bin/vlc && chmod +x /usr/bin/vlc && rm /root/vlc && cd ~/Kalissistant && rm v* && wget https://github.com/unk9vvn/Kalissistant/raw/master/vlc && chmod +x *")

    # Install Veil Evasion
    veil = raw_input("\t\n[*] Confim Install Veil-Evasion?(y/N): ")
    if veil == "y":
            os.system("veil --setup && /usr/share/veil/config/setup.sh --force --silent")
    elif veil == "n":
        print("\t\n[-] Resume Install Process")
    else:
        os.system("veil --setup")

    # Install KDE Plasma Desktop
    kde = raw_input("\t\n[*] Install KDE Plasma Desktop?(y/N): ")
    if kde == "y":
        os.system("apt-get install -y kde-plasma-desktop")
    elif kde == "n":
        print("\t\n[-] Resume Install Process")
    else:
        os.system("apt-get install -y kde-plasma-desktop")

    # Install OpenVAS
    openvas = raw_input("\t\n[*] Confim Install OpenVAS?(y/N): ")
    if openvas == "y":
        os.system("openvas-setup")
    elif openvas == "n":
        print("\t\n[-] Resume Install Process")
    else:
        os.system("openvas-setup")
    if openvas == "y":
        print("\t\n\n[*] Copy (PASS Generated)\t\n"
              "[*] Visit > https://127.0.0.1:9392\t\n"
              "[*] Username:(admin) Password:(PASS Generated)\n")

if menu == "3":
    cls()
    print("\n\n\tInstall the types of tools available in the operating system\n\t"
          "tank These tools Include Firepwd Brut3k1t BruteSploit KatanaFramework\n\t"
          "Wordpress-XMLRPC-Brute-Force-Exploit Crowbar Krackattacks Credmap\n\t"
          "Pentmenu Xerxes IIS-ShortName-Scanner Ares GoldenEye Hammer Poodle\n\t"
          "Repulsive-grizzly WarChild Netstress slowloris Wreckuests Sn1per\n\t"
          "Amplification Botdr4g0n CloudFail tinfoleak BlindElephant Kadimus\n\t"
          "Slowhttptest IPGeoLocation nmap-vulners fuzzdb-project Arachni\n\t"
          "ShodanHat VBscan WPSeku DSJS Joomlavs Plecost 0d1n LFImap RCEer\n\t"
          "HTTPoxyScan RCE-Finder TBDEx DotDotpwn JexBoss D0xk1t Wig Infoga\n\t"
          "D-TECT OWASP-Nettacker ssct Scanless a2sv ReconDog Belati RED_HAWK\n\t"
          "tweets_analyzer Trape airgeddon wifiphisher WiFi-Pumpkin WPSpin\n\t"
          "Radamsa Seths slkill Xerosploit Passgen Wifresti Peanuts AtEar\n\t"
          "BlueBorne firmware-analysis-toolkit firmware-mod-kit firmwalker\n\t"
          "Unicorn DirtyCow-Exploit Empire Potato windows-privesc-check\n\t"
          "mimipenguin NetRipper BITSInject Weeman sAINT Pazuzu CredSniper\n\t"
          "Meterpreter_Paranoid_Mode-SSL FakeImageExploiter WAFNinja\n\t"
          "Pyinstaller TheFatRat Image_Injector Kerio-Client wafpass \n\t"
          "Dymerge Memcrashed-DDoS-Exploit MitmfFakeImageExploiter\n\t"
          "Impacket malicious-wordpress-plugin ARDT WPForce\n\t")

    os.system("mkdir /root/Documents/Exploits && chmod 755 /root/Documents/Exploits")
    os.system("git clone https://github.com/k4m4/dymerge.git /root/Documents/Exploits/dymerge && cd /root/Documents/Exploits/dymerge && chmod 755 *")
    os.system("git clone https://github.com/lclevy/firepwd.git /root/Documents/Exploits/firepwd && cd /root/Documents/Exploits/firepwd && chmod 755 *")
    os.system("git clone https://github.com/ex0dus-0x/brut3k1t.git /root/Documents/Exploits/brut3k1t && cd /root/Documents/Exploits/brut3k1t && chmod 755 * && python setup.py install")
    os.system("git clone https://github.com/Screetsec/BruteSploit.git /root/Documents/Exploits/BruteSploit && cd /root/Documents/Exploits/BruteSploit && chmod 755 *")
    os.system("git clone https://github.com/n00py/WPForce.git /root/Documents/Exploits/WPForce && cd /root/Documents/Exploits/WPForce && chmod 755 *")
    os.system("git clone https://github.com/PowerScript/KatanaFramework.git /root/Documents/Exploits/KatanaFramework && cd KatanaFramework && chmod 755 * && ./install && pip install -r requirements.txt")
    os.system("git clone https://github.com/1N3/Wordpress-XMLRPC-Brute-Force-Exploit.git /root/Documents/Exploits/Wordpress-XMLRPC-Brute-Force-Exploit && cd /root/Documents/Exploits/Wordpress-XMLRPC-Brute-Force-Exploit && chmod 755 *")
    os.system("git clone https://github.com/galkan/crowbar.git /root/Documents/Exploits/crowbar && cd /root/Documents/Exploits/crowbar && chmod 755 * && apt-get install -y freerdp2-x11")
    os.system("git clone https://github.com/GinjaChris/pentmenu.git /root/Documents/Exploits/pentmenu && cd /root/Documents/Exploits/pentmenu && chmod 755 *")
    os.system("git clone https://github.com/zanyarjamal/xerxes.git /root/Documents/Exploits/xerxes && cd /root/Documents/Exploits/xerxes && chmod 755 * && gcc xerxes.c -o xerxes")
    os.system("git clone https://github.com/irsdl/IIS-ShortName-Scanner.git /root/Documents/Exploits/IIS-ShortName-Scanner && cd /root/Documents/Exploits/IIS-ShortName-Scanner && chmod 755 *")
    os.system("git clone https://github.com/sweetsoftware/Ares.git /root/Documents/Exploits/Ares && cd /root/Documents/Exploits/Ares && chmod 755 * && pip install -r requirements.txt && pip install cherrypy && ./wine_setup.sh && cd server && chmod 755 * && ./ares.py initdb")
    os.system("git clone https://github.com/jseidl/GoldenEye.git /root/Documents/Exploits/GoldenEye && cd /root/Documents/Exploits/GoldenEye && chmod 755 *")
    os.system("git clone https://github.com/649/Memcrashed-DDoS-Exploit.git /root/Documents/Exploits/Memcrashed-DDoS-Exploit && cd /root/Documents/Exploits/Memcrashed-DDoS-Exploit && chmod 755 *")
    os.system("git clone https://github.com/OffensivePython/Saddam.git /root/Documents/Exploits/Saddam && cd /root/Documents/Exploits/Saddam && chmod 755 *")
    os.system("git clone https://github.com/m57/ARDT.git /root/Documents/Exploits/ARDT && cd /root/Documents/Exploits/ARDT && chmod 755 *")
    os.system("git clone https://github.com/Souhardya/WarChild.git /root/Documents/Exploits/WarChild && cd /root/Documents/Exploits/WarChild && chmod 755 * && pip3 install -r requirements.txt")
    os.system("git clone https://github.com/Netflix-Skunkworks/repulsive-grizzly.git /root/Documents/Exploits/repulsive-grizzly && cd /root/Documents/Exploits/repulsive-grizzly && chmod 755 * && pip install -r requirements.txt")
    os.system("wget https://sourceforge.net/projects/netstressng/files/latest/download/netstress-3.0.7.tar.gz && tar -xvf netstress-3.0.7.tar.gz && cd netstress-3.0.7 && make")
    os.system("git clone https://github.com/llaera/slowloris.pl.git /root/Documents/Exploits/slowloris.pl && cd /root/Documents/Exploits/slowloris.pl && chmod 755 * && apt-get install -y libwww-mechanize-shell-perl")
    os.system("git clone https://github.com/Netflix-Skunkworks/repulsive-grizzly.git /root/Documents/Exploits/repulsive-grizzly && cd /root/Documents/Exploits/repulsive-grizzly && chmod 755 * && pip install -r requirements.txt")
    os.system("git clone https://github.com/ethanwilloner/DNS-Amplification-Attack.git /root/Documents/Exploits/DNS-Amplification-Attack && cd /root/Documents/Exploits/DNS-Amplification-Attack && make")
    os.system("git clone https://github.com/mpgn/poodle-PoC.git /root/Documents/Exploits/poodle-PoC && cd /root/Documents/Exploits/poodle-PoC && chmod 755 * && python3 poodle-poc.py")
    os.system("git clone https://github.com/mh4x0f/botdr4g0n.git /root/Documents/Exploits/botdr4g0n && cd /root/Documents/Exploits/botdr4g0n && chmod 755 * && python setup.py install")
    os.system("git clone https://github.com/m0rtem/CloudFail.git /root/Documents/Exploits/CloudFail && cd /root/Documents/Exploits/CloudFail && chmod 755 * && pip3 install -r requirements.txt")
    os.system("git clone https://github.com/maldevel/IPGeoLocation.git /root/Documents/Exploits/IPGeoLocation && cd /root/Documents/Exploits/IPGeoLocation && chmod 755 * && pip3 install -r requirements.txt")
    os.system("git clone https://github.com/vaguileradiaz/tinfoleak.git /root/Documents/Exploits/tinfoleak && cd /root/Documents/Exploits/tinfoleak && chmod 755 * && apt install python-pip python-dev build-essential python2.7-dev python-pyexiv2 python-openssl && pip install --upgrade pip virtualenv tweepy pillow exifread jinja2 oauth2")
    os.system("git clone https://github.com/1N3/Sn1per.git /root/Documents/Exploits/Sn1per && cd /root/Documents/Exploits/Sn1per && chmod 755 * && ./install.sh")
    os.system("git clone https://github.com/vulnersCom/nmap-vulners.git /root/Documents/Exploits/nmap-vulners && cd /root/Documents/Exploits/nmap-vulners && chmod 755 *")
    os.system("git clone https://github.com/lokifer/BlindElephant.git /root/Documents/Exploits/BlindElephant && cd /root/Documents/Exploits/BlindElephant/src/ && chmod 755 * && python setup.py install")
    os.system("git clone https://github.com/fuzzdb-project/fuzzdb.git /root/Documents/Exploits/fuzzdb && cd /root/Documents/Exploits/fuzzdb && chmod 755 *")
    os.system("git clone https://github.com/P0cL4bs/Kadimus.git /root/Documents/Exploits/Kadimus && cd /root/Documents/Exploits/Kadimus && chmod 755 * && apt-get install -y libpcre3-dev libssh-dev libcurl4-openssl-dev && ./configure")
    os.system("git clone https://github.com/Arachni/arachni.git /root/Documents/Exploits/arachni && apt-get -y install build-essential curl libcurl3 libcurl4-openssl-dev ruby ruby-dev && cd /root/Documents/Exploits/arachni/bin && chmod 755 * && bundle install && gem install arachni")
    os.system("git clone https://github.com/HatBashBR/ShodanHat.git /root/Documents/Exploits/ShodanHat && cd /root/Documents/Exploits/ShodanHat && chmod 755 *")
    os.system("git clone https://github.com/rezasp/vbscan/vbscan.git /root/Documents/Exploits/vbscan && cd /root/Documents/Exploits/vbscan && chmod 755 *")
    os.system("git clone https://github.com/m4ll0k/WPSeku.git /root/Documents/Exploits/WPSeku && cd /root/Documents/Exploits/WPSeku && chmod 755 * && pip3 install -r requirements.txt")
    os.system("git clone https://github.com/stamparm/DSJS.git /root/Documents/Exploits/DSJS && cd /root/Documents/Exploits/DSJS && chmod 755 *")
    os.system("git clone https://github.com/rastating/joomlavs.git /root/Documents/Exploits/joomlavs && cd /root/Documents/Exploits/joomlavs && chmod 755 * && apt-get install ruby-dev zlib1g-dev liblzma-dev -y && gem install bundler && bundle install")
    os.system("git clone https://github.com/iniqua/plecost.git /root/Documents/Exploits/plecost && cd /root/Documents/Exploits/plecost && chmod 755 * && python3 setup.py install && pip3 install -r requirements.txt &&  python3 -m pip install plecost")
    os.system("git clone https://github.com/CoolerVoid/0d1n.git /root/Documents/Exploits/0d1n && cd /root/Documents/Exploits/0d1n && make")
    os.system("git clone https://github.com/sleventyeleven/lfimap.git /root/Documents/Exploits/lfimap && cd /root/Documents/Exploits/lfimap")
    os.system("git clone https://github.com/intfrr/RCEer.git /root/Documents/Exploits/RCEer && cd /root/Documents/Exploits/RCEer && chmod 755 *")
    os.system("git clone https://github.com/arbazkiraak/RCE_FINDER.git /root/Documents/Exploits/RCE_FINDER && cd /root/Documents/Exploits/RCE_FINDER && chmod 755 *")
    os.system("git clone https://github.com/dancezarp/TBDEx.git /root/Documents/Exploits/TBDEx && cd /root/Documents/Exploits/TBDEx && chmod 755 *")
    os.system("git clone https://github.com/wireghoul/dotdotpwn.git /root/Documents/Exploits/dotdotpwn && cd /root/Documents/Exploits/dotdotpwn && chmod 755 * && perl -MCPAN -e 'install dotdotpwn.pl'")
    os.system("git clone https://github.com/joaomatosf/jexboss.git /root/Documents/Exploits/jexboss && cd /root/Documents/Exploits/jexboss && chmod 755 *")
    os.system("git clone https://github.com/shawarkhanethicalhacker/D-TECT.git /root/Documents/Exploits/D-TECT && cd /root/Documents/Exploits/D-TECT && chmod 755 *")
    os.system("git clone https://github.com/viraintel/OWASP-Nettacker.git /root/Documents/Exploits/OWASP-Nettacker && cd /root/Documents/Exploits/OWASP-Nettacker && chmod 755 * && python setup.py install")
    os.system("git clone https://github.com/wanjunzh/ssct.git /root/Documents/Exploits/ssct && cd /root/Documents/Exploits/ssct && chmod 755 * && pip3 install shadowsocks requests prettytable")
    os.system("git clone https://github.com/vesche/scanless.git /root/Documents/Exploits/scanless && cd /root/Documents/Exploits/scanless && chmod 755 * && python setup.py install && pip install scanless")
    os.system("git clone https://github.com/hahwul/a2sv.git /root/Documents/Exploits/a2sv && cd /root/Documents/Exploits/a2sv && bash install.sh")
    os.system("git clone https://github.com/1N3/HTTPoxyScan.git /root/Documents/Exploits/HTTPoxyScan && cd /root/Documents/Exploits/HTTPoxyScan && chmod 755 *")
    os.system("git clone https://github.com/UltimateHackers/ReconDog.git /root/Documents/Exploits/ReconDog && cd /root/Documents/Exploits/ReconDog && chmod 755 *")
    os.system("git clone https://github.com/aancw/Belati.git /root/Documents/Exploits/Belati && cd /root/Documents/Exploits/Belati && chmod 755 * && git submodule update --init --recursive --remote && pip install -r requirements.txt")
    os.system("git clone https://github.com/Tuhinshubhra/RED_HAWK.git /root/Documents/Exploits/RED_HAWK && cd /root/Documents/Exploits/RED_HAWK && chmod 755 *")
    os.system("git clone https://github.com/m4ll0k/Infoga.git /root/Documents/Exploits/Infoga && cd /root/Documents/Exploits/Infoga && chmod 755 * && pip3 install requests")
    os.system("git clone https://github.com/jekyc/wig.git /root/Documents/Exploits/wig && cd /root/Documents/Exploits/wig && chmod 755 * && python3 setup.py install")
    os.system("git clone https://github.com/ex0dus-0x/D0xk1t.git /root/Documents/Exploits/D0xk1t && cd /root/Documents/Exploits/D0xk1t && chmod 755 * && apt-get install -y redis-server python python-pip python-virtualenv && pip install -r requirements.txt")
    os.system("git clone https://github.com/x0rz/tweets_analyzer.git /root/Documents/Exploits/tweets_analyzer && cd /root/Documents/Exploits/tweets_analyzer && chmod 755 * && pip install -r requirements.txt")
    os.system("git clone https://github.com/boxug/trape.git /root/Documents/Exploits/trape && cd /root/Documents/Exploits/trape && chmod 755 * && pip install -r requirements.txt")
    os.system("git clone https://github.com/v1s1t0r1sh3r3/airgeddon.git /root/Documents/Exploits/airgeddon && cd /root/Documents/Exploits/airgeddon && chmod 755 *")
    os.system("git clone https://github.com/P0cL4bs/WiFi-Pumpkin.git /root/Documents/Exploits/WiFi-Pumpkin && cd /root/Documents/Exploits/WiFi-Pumpkin && chmod 755 * && ./installer.sh --install")
    os.system("git clone https://github.com/wi-fi-analyzer/wpspin.git /root/Documents/Exploits/wpspin && cd /root/Documents/Exploits/wpspin && chmod 755 *")
    os.system("git clone https://github.com/blmvxer/passgen.git /root/Documents/Exploits/passgen && cd /root/Documents/Exploits/passgen && chmod 755 *")
    os.system("git clone https://github.com/LionSec/wifresti.git /root/Documents/Exploits/wifresti && cd /root/Documents/Exploits/wifresti && chmod 755 *")
    os.system("git clone https://github.com/NoobieDog/Peanuts.git /root/Documents/Exploits/Peanuts && cd /root/Documents/Exploits/Peanuts && chmod 755 * && apt-get install -y python-gps bluetooth bluez python-bluez && pip install argparse datetime gps scapy logging")
    os.system("git clone https://github.com/NORMA-Inc/AtEar.git /root/Documents/Exploits/AtEar && cd /root/Documents/Exploits/AtEar && chmod 755 * && bash install.sh")
    os.system("git clone https://github.com/vanhoefm/krackattacks-scripts.git /root/Documents/Exploits/krackattacks-scripts && cd /root/Documents/Exploits/krackattacks-scripts && chmod 755 * && apt-get install -y libnl-3-dev libnl-genl-3-dev pkg-config libssl-dev net-tools git sysfsutils python-scapy python-pycryptodome")
    os.system("git clone https://github.com/aoh/radamsa.git /root/Documents/Exploits/radamsa && cd /root/Documents/Exploits/radamsa && make && make install && apt-get install -y build-essential python-dev libnetfilter-queue-dev tshark tcpdump python3-pip wireshark mosquitto mosquitto-clients gcc make git wget && pip3 install --process-dependency-links polymorph")
    os.system("git clone https://github.com/SySS-Research/Seth.git /root/Documents/Exploits/Seth && cd /root/Documents/Exploits/Seth && chmod 755 * && pip install -r requirements.txt")
    os.system("git clone https://github.com/m4n3dw0lf/sslkill.git /root/Documents/Exploits/sslkill && cd /root/Documents/Exploits/sslkill && chmod 755 * && apt-get install -y build-essential python-dev libnetfilter-queue-dev && pip install -r requirements.txt")
    os.system("git clone https://github.com/LionSec/xerosploit.git /root/Documents/Exploits/xerosploit && cd /root/Documents/Exploits/xerosploit && chmod 755 *")
    os.system("git clone https://github.com/mailinneberg/BlueBorne.git /root/Documents/Exploits/BlueBorne && cd /root/Documents/Exploits/BlueBorne && apt-get install -y bluetooth libbluetooth-dev && pip install pybluez pwntools")
    os.system("git clone https://github.com/byt3bl33d3r/MITMf.git /root/Documents/Exploits/MITMf && cd /root/Documents/Exploits/MITMf && chmod 755 * && apt-get install -y python-dev python-setuptools libpcap0.8-dev libnetfilter-queue-dev libssl-dev libjpeg-dev libxml2-dev libxslt1-dev libcapstone3 libcapstone-dev libffi-dev file mitmf && pip install virtualenvwrapper && pip install -r requirements.txt && git submodule init && git submodule update --recursive")
    os.system("git clone https://github.com/attify/firmware-analysis-toolkit.git /root/Documents/Exploits/firmware-analysis-toolkit && cd /root/Documents/Exploits/firmware-analysis-toolkit && chmod 755 * && git clone https://github.com/firmadyne/firmadyne.git && cd firmadyne && bash download.sh")
    os.system("git clone https://github.com/brianpow/firmware-mod-kit.git /root/Documents/Exploits/firmware-mod-kit && cd /root/Documents/Exploits/firmware-mod-kit && chmod 755 *")
    os.system("git clone https://github.com/craigz28/firmwalker.git /root/Documents/Exploits/firmwalker && cd /root/Documents/Exploits/firmwalker && chmod 755 *")
    os.system("git clone https://github.com/trustedsec/unicorn.git /root/Documents/Exploits/unicorn && cd /root/Documents/Exploits/unicorn && chmod 755 *")
    os.system("git clone https://github.com/TheBlaCkCoDeR09/DirtyCow-Exploit.git /root/Documents/Exploits/DirtyCow-Exploit && cd /root/Documents/Exploits/DirtyCow-Exploit && chmod 755 * && cp DirtyCow.rb /usr/share/metasploit-framework/modules/exploits/linux/local/")
    os.system("git clone https://github.com/EmpireProject/Empire.git /root/Documents/Exploits/Empire && cd /root/Documents/Exploits/Empire/setup && chmod 755 * && bash install.sh")
    os.system("git clone https://github.com/foxglovesec/Potato.git /root/Documents/Exploits/Potato && cd /root/Documents/Exploits/Potato && chmod 755 *")
    os.system("git clone https://github.com/pentestmonkey/windows-privesc-check.git /root/Documents/Exploits/windows-privesc-check && cd /root/Documents/Exploits/windows-privesc-check && chmod 755 *")
    os.system("git clone https://github.com/huntergregal/mimipenguin.git /root/Documents/Exploits/mimipenguin && cd /root/Documents/Exploits/mimipenguin && chmod 755 *")
    os.system("git clone https://github.com/NytroRST/NetRipper.git /root/Documents/Exploits/NetRipper && cd /root/Documents/Exploits/NetRipper && chmod 755 *")
    os.system("git clone https://github.com/SafeBreach-Labs/BITSInject /root/Documents/Exploits/BITSInject && cd /root/Documents/Exploits/BITSInject && chmod 755 *")
    os.system("git clone https://github.com/evait-security/weeman.git /root/Documents/Exploits/weeman && cd /root/Documents/Exploits/weeman && chmod 755 *")
    os.system("git clone https://github.com/ustayready/CredSniper.git /root/Documents/Exploits/CredSniper && cd /root/Documents/Exploits/CredSniper && chmod 755 * && pip install -r requirements.txt")
    os.system("git clone https://github.com/r00t-3xp10it/Meterpreter_Paranoid_Mode-SSL.git /root/Documents/Exploits/Meterpreter_Paranoid_Mode-SSL && cd /root/Documents/Exploits/Meterpreter_Paranoid_Mode-SSL && chmod 755 *")
    os.system("git clone https://github.com/r00t-3xp10it/FakeImageExploiter.git /root/Documents/Exploits/FakeImageExploiter && cd /root/Documents/Exploits/FakeImageExploiter && chmod 755 *")
    os.system("git clone https://github.com/wetw0rk/malicious-wordpress-plugin.git /root/Documents/Exploits/malicious-wordpress-plugin && cd /root/Documents/Exploits/malicious-wordpress-plugin && chmod 755 *")
    os.system("git clone https://github.com/tiagorlampert/sAINT.git /root/Documents/Exploits/sAINT && cd /root/Documents/Exploits/sAINT && chmod 755 * && apt install -y maven default-jdk default-jre openjdk-8-jdk openjdk-8-jre zlib1g-dev libncurses5-dev lib32z1 lib32ncurses6 && ./configure.sh")
    os.system("git clone https://github.com/BorjaMerino/Pazuzu.git /root/Documents/Exploits/Pazuzu && cd /root/Documents/Exploits/Pazuzu && chmod 755 *")
    os.system("git clone https://github.com/pyinstaller/pyinstaller.git /root/Documents/Exploits/pyinstaller && cd /root/Documents/Exploits/pyinstaller && chmod 755 * && python setup.py install && pip install pyinstaller")
    os.system("git clone https://github.com/pyinstaller/pyinstaller.git /root/Documents/Exploits/pyinstaller && cd /root/Documents/Exploits/pyinstaller && chmod 755 * && python setup.py install && pip install pyinstaller")
    os.system("git clone https://github.com/Screetsec/TheFatRat.git /root/Documents/Exploits/TheFatRat && cd /root/Documents/Exploits/TheFatRat && chmod 755 * && bash setup.sh")
    os.system("git clone https://github.com/re4lity/Image_Injector.git /root/Documents/Exploits/Image_Injector && cd /root/Documents/Exploits/Image_Injector && chmod 755 *")
    os.system("git clone https://github.com/ethicalhackeragnidhra/viSQL.git /root/Documents/Exploits/viSQL && cd /root/Documents/Exploits/viSQL && chmod 755 * && pip install -r requirements.txt")
    os.system("git clone https://github.com/CoreSecurity/impacket.git /root/Documents/Exploits/impacket && cd /root/Documents/Exploits/impacket && chmod 755 * && python setup.py install && pip install -r requirements.txt")
    os.system("git clone https://github.com/3xp10it/bypass_waf.git /root/Documents/Exploits/bypass_waf && cd /root/Documents/Exploits/bypass_waf && chmod 755 * && pip3 install exp10it")
    os.system("wget https://gist.githubusercontent.com/MarkBaggett/49aca627205aebaa2be1811511dbc422/raw/06ff006182b254cb379bed005b6423978ed85d00/custom_caesar.py && mv custom_caesar.py /usr/share/sqlmap/tamper/")
    os.system("git clone https://github.com/wafpassproject/wafpass.git /root/Documents/Exploits/bypass_waf && cd /root/Documents/Exploits/bypass_waf && chmod 755 *")
    os.system("git clone https://github.com/khalilbijjou/WAFNinja.git /root/Documents/Exploits/WAFNinja && cd /root/Documents/Exploits/WAFNinja && chmod 755 * && pip install progressbar")

    # Kerio-client
    kde = raw_input("\t\n[*] Install Kerio-client?(y/N): ")
    if kde == "y":
        os.system("proxychains wget http://download.kerio.com/dwn/kerio-control-vpnclient-linux-amd64.deb && chmod 755 * && kerio-control-vpnclient-linux-amd64.deb")
    elif kde == "n":
        print("\t\n[-] Resume Install Process")
    else:
        os.system("proxychains wget http://download.kerio.com/dwn/kerio-control-vpnclient-linux-amd64.deb && chmod 755 * && kerio-control-vpnclient-linux-amd64.deb")

if menu == "0":
    print("\n\n\tGrayHat Hackers :)\t\n"
          "\tOur goal is to win the last battle,\t\n"
          "\tso slowly move to the end and be anonymous...\t\n"
          "\thttps://github/unk9vvn/Kalissistant\t\n")
    sys.exit()
