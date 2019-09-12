#!/bin/bash
#################################################################
#																#
#		Squid Configuration										#
#		Ver 1.0													#
#################################################################

OS=`uname -s`
DISTRIB=`cat /etc/*release* | grep -i DISTRIB_ID | cut -f2 -d=`
IP_FILE="/etc/squid/squid.IPFILE"
PxyPort="3128"
CONFIG_FILE="/etc/squid/squid.conf"
PASSWD_FILE="/etc/squid/squid.passwd"
USER_FILE="/etc/squid/userlist"
TEMP_IPFILE="temp_ipfile"
SQUIDDB="/etc/squid/squid.db"
NETWORK_FILE="/etc/network/interfaces"
INT_NAME=ens33
AVL_IP=0
SUBNET=32
touch $SQUIDDB
touch $PASSWD_FILE
touch $USER_FILE
touch $TEMP_IPFILE
>$TEMP_IPFILE
>$USER_FILE

### Run as ROOT user only ###
checkRoot()
{
	if [ `id -u` -ne 0 ]
	then 
		echo "SCRIPT must be RUN as root user"
		exit 13
	else
		echo "USER: root"
	fi
}

checkOS()
{
	if [ "$OS" == "Linux" ] && [ "$DISTRIB" == "Ubuntu" ]
	then
		echo "Operating System = $DISTRIB $OS"
	else
		echo "Please run this script on Ubuntu Linux"
		exit 12
	fi
}
restartSquid()
{
	echo
	echo "Restarting SQUID"
	systemctl reload squid.service
	#systemctl restart networking
}
copySquid()
{
	cp -p $CONFIG_FILE "/etc/squid/squid.conf_$(date +%Y%M%H%m)"
}

createBaseConf()
{
	cat >> $CONFIG_FILE <<EOB
forwarded_for off
http_port 3128
request_header_access Allow allow all
request_header_access Authorization allow all
request_header_access WWW-Authenticate allow all
request_header_access Proxy-Authorization allow all
request_header_access Proxy-Authenticate allow all
request_header_access Cache-Control allow all
request_header_access Content-Encoding allow all
request_header_access Content-Length allow all
request_header_access Content-Type allow all
request_header_access Date allow all
request_header_access Expires allow all
request_header_access Host allow all
request_header_access If-Modified-Since allow all
request_header_access Last-Modified allow all
request_header_access Location allow all
request_header_access Pragma allow all
request_header_access Accept allow all
request_header_access Accept-Charset allow all
request_header_access Accept-Encoding allow all
request_header_access Accept-Language allow all
request_header_access Content-Language allow all
request_header_access Mime-Version allow all
request_header_access Retry-After allow all
request_header_access Title all
request_header_access Connection allow all
request_header_access Proxy-Connection allow all
request_header_access User-Agent allow all
request_header_access Cookie allow all
request_header_access All deny all
#FIRST_TIME
auth_param basic program /usr/lib/squid/basic_ncsa_auth /etc/squid/squid.passwd
auth_param basic realm proxy

EOB
}
saveDB()
{
	cat $SQUIDDB | grep -w "$1" 1>/dev/null 2>/dev/null
	if [ `echo $?` -eq 0 ]
	then
		cat $SQUIDDB | grep -v -w "$1" > tempsquiddb
		cat tempsquiddb > $SQUIDDB
	else
		echo "$1:$2:$3:$4" >> $SQUIDDB
	fi
	rm -f tempsquiddb
}
getPxyInput() 
{
	#read -p "Enter Starting Range of IP Address :" SRANGE
	#read -p "Enter Ending Range of IP Address   :" ERANGE
	#read -p "Enter Proxy Port Number            :" PxyPort
	if [ $AUTH_METHOD -eq 1 ]
	then
		echo 
		echo "1. Random user"
		echo "2. Manual Entry"
		read -p "Enter Option [ 1 or 2 ]:" rndUser
		if [ "$rndUser" == "1" ]
		then
			user1="guil"
			user2=`cat /dev/urandom | tr -dc 'a-z0-9' | fold -w 5 | head -n 1`
			PxyUser="$user1$user2"
			PxyPwd=`cat /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w 10 | head -n 1`
		else
			read -p "Enter User Name for IP Range :" PxyUser
			read -p "Enter Password for $PxyUser:" PxyPwd
		fi
		createUser "$PxyUser" "$PxyPwd"
	else
		read -p "Enter IP Address to Authenticate for Block $SRANGE - $ERANGE   :" Auth_IP
		PxyUser="$Auth_IP"
		PxyPwd="NA"
	fi
}
plumbIP()
{
	ip addr add $1/${SUBNET} dev ${INT_NAME} 1>/dev/null 2>/dev/null
}
getInterface()
{
	if [ "$1" == "DEL" ]
	then
		echo >/dev/null
	else
		AUTHVALUE=1
		case "$AUTHVALUE" in
		1)
			AUTH_METHOD=1
			;;
		2)	
			AUTH_METHOD=2
			;;
		*)
			AUTH_METHOD=1
			;;
		esac
	fi
		
}
createUser()
{
		htpasswd -b $PASSWD_FILE $1 $2 1>/dev/null	
}
writeConfig()
{
	if [ $AUTH_METHOD -eq 1  ]
	then
		printf "\nacl $3_$1 proxy_auth $3\n" >> $CONFIG_FILE
		printf "acl myip_$1 myip $1\n" >> $CONFIG_FILE
		printf "tcp_outgoing_address $1 myip_$1\n" >> $CONFIG_FILE
		printf "http_access allow $3_$1 myip_$1\n" >> $CONFIG_FILE
	else
		cat $CONFIG_FILE | egrep 'acl|tcp_outgoing_address|http_access|auth_param' >temp_configb
		cat $CONFIG_FILE | egrep -v 'acl|tcp_outgoing_address|http_access|auth_param' | cat -s >temp_configa
		cat temp_configa >$CONFIG_FILE
		printf "\nacl CL_$1 src $3\n" >> $CONFIG_FILE
		printf "acl myip_$1 myip $1\n" >> $CONFIG_FILE
		printf "tcp_outgoing_address $1 myip_$1\n" >> $CONFIG_FILE
		printf "http_access allow CL_$1 myip_$1\n" >> $CONFIG_FILE
		cat temp_configb >> $CONFIG_FILE
	fi
	cat -s $SQUIDDB > temp_configa
	cat temp_configa > $SQUIDDB
	rm -f temp_configb
	rm -f temp_configa
}
installSquid()
{
	printf "installing SQUID 3"
	apt-get install squid3 -y 1>/dev/null 2>/dev/null
	if [ `echo $?` -eq 0 ] && [ -f $CONFIG_FILE ]
	then
		printf "\tOK\n"
	else
		echo "SQUID3 installation FAILED"
		exit 11
	fi
	apt-get install apache2-utils -y 1>/dev/null 2>/dev/null
	if [ ! -f /usr/lib/squid/basic_ncsa_auth ];then echo "Failed to Install APACHE2-UTILS"; exit 14;fi
}
processConfig()
{
	NEXT_IP=$(($USED_IP+1))
	read -p "How many IP: " NUMIP
	if [ $NUMIP -le 0 ]; then createMenu;fi
	if [ $NUMIP -gt $AVL_IP ]; then createMenu;fi
	COUNT=0
	for IP in `cat $IP_FILE`
	do
		cat $SQUIDDB | grep -w "$IP" 1>/dev/null 2>/dev/null
		if [ `echo $?` -eq 0 ]
		then
			echo >/dev/null
		else
			plumbIP "$IP"
			if [ $AUTH_METHOD -eq 1  ]
			then
				writeConfig "$IP" "$PxyPort" "$PxyUser" "$PxyPwd"
				echo "$IP:$PxyPort:$PxyUser:$PxyPwd" >> tempiprange
				saveDB "$IP" "$PxyPort" "$PxyUser" "$PxyPwd"
			else
				writeConfig "$IP" "$PxyPort" "$Auth_IP" "NA"
				echo "$IP":"$PxyPort":"$Auth_IP":"NA" >> tempiprange
				saveDB "$IP" "$PxyPort" "$Auth_IP" "NA"
			fi
			COUNT=$((COUNT+1))
			if [ $COUNT -eq $NUMIP ];then break;fi
		fi
	done
	echo
	echo "New Proxy Configuration"
	printf "\n================================================\n"
	cat tempiprange
	>$TEMP_IPFILE
	>tempiprange
}
displayCurrentConfig()
{
	C=1
	printf "\n================================================"
	printf "\nCurrent Configuration\nIP_Address\tUser\tPassword\n"
	for IPLIST in `cat $IP_FILE`
	do
		cat $SQUIDDB | grep -w "$IPLIST" 1> /dev/null 2>/dev/null
		if [ `echo $?` -eq 0 ]
		then
			GENPORT=`cat $SQUIDDB |  grep -w "$IPLIST" |awk -F ":" '{print $3}'`
			GENUSER=`cat $SQUIDDB |  grep -w "$IPLIST" |awk -F ":" '{print $4}'`
			GENPASS=`cat $SQUIDDB |  grep -w "$IPLIST" |awk -F ":" '{print $5}'`
		else
			GENPORT=""
			GENUSER=""
			GENPASS=""
		fi
		
		printf "$C\t$IPLIST\t$GENPORT\t$GENUSER\t$GENPASS\n" >>$TEMP_IPFILE
		C=$((C+1))
	done
	cat $SQUIDDB
	printf "\n================================================\n"
}
isFirstTime()
{
	cat $CONFIG_FILE | grep "^#FIRST_TIME" 1>/dev/null 2>/dev/null
	if [ `echo $?` -ne 0 ]
	then
		>$CONFIG_FILE
		createBaseConf
	else
		echo
	fi
}
unplumbIP()
{
	ip addr del $1/${SUBNET} dev $INT_NAME 1>/dev/null 2>/dev/null
}
deleteConfig()
{
	read -p "Enter Username to delete:" delUsername
	cat $SQUIDDB | grep -w "$delUsername"  1>/dev/null 2>/dev/null
	if [ `echo $?` -ne 0 ];then echo "Wrong Input"; read -p "Press any key to continue" ;createMenu;fi
	delIP=`cat $SQUIDDB | grep -w "$delUsername" | awk -F: '{print $1}'`
	for IP in $delIP
	do		
		unplumbIP "$IP"
		cat $CONFIG_FILE | grep -v -w "myip_${IP}" > temp_config
		cat temp_config > $CONFIG_FILE
		cat $CONFIG_FILE | grep -v -w "${delUsername}_${IP}" > temp_config
		cat temp_config > $CONFIG_FILE		
		cat $IP_FILE | grep -v -w "$IP" > t_ipfile
		echo "$IP" >> t_ipfile
		cat t_ipfile > $IP_FILE
	done
	cat $SQUIDDB | grep -v -w "$delUsername" > temp_db
	cat temp_db > $SQUIDDB
	htpasswd -D $PASSWD_FILE $delUsername

	>$TEMP_IPFILE
	>tempiprange
	>temp_config
	>temp_db
	>temp_network
}
getCurrentConfig()
{
	AVL_IP=0
	TOTAL_IP=`cat $IP_FILE | wc -l`
	USED_IP=`cat $SQUIDDB | wc -l`
	AVL_IP=$((TOTAL_IP-USED_IP))
	if [ $AVL_IP -le 0 ];then createMenu;fi
	echo
	echo "Used IPs: $USED_IP"
	echo "Available IP$: $AVL_IP [ $USED_IP to $TOTAL_IP ]"
}
displaywithSL()
{
C=1
	printf "\n================================================"
	printf "\nCurrent Configuration\nSLNo\tIP_Address\tUser\n"
	for IPLIST in `cat $IP_FILE`
	do
		cat $SQUIDDB | grep -w "$IPLIST" 1> /dev/null 2>/dev/null
		if [ `echo $?` -eq 0 ]
		then
			GENPORT=`cat $SQUIDDB |  grep -w "$IPLIST" |awk -F ":" '{print $3}'`
			GENUSER=`cat $SQUIDDB |  grep -w "$IPLIST" |awk -F ":" '{print $4}'`
			GENPASS=`cat $SQUIDDB |  grep -w "$IPLIST" |awk -F ":" '{print $5}'`
		else
			GENPORT=""
			GENUSER=""
			GENPASS=""
		fi
		printf "$C\t$IPLIST\t$GENPORT\t$GENUSER\t$GENPASS\n"
		printf "$C\t$IPLIST\t$GENPORT\t$GENUSER\t$GENPASS\n" >>$TEMP_IPFILE
		C=$((C+1))
	done
	printf "\n================================================\n"
}
getPxyInputSL() 
{
	read -p "Enter Starting Range of IP Address :" SRANGE
	read -p "Enter Ending Range of IP Address   :" ERANGE
	if [ $SRANGE -gt $ERANGE ];then createMenu;fi
	if [ $AUTH_METHOD -eq 1 ]
	then
		read -p "Enter User Name for Block $SRANGE - $ERANGE   :" PxyUser
		read -p "Enter Password for $PxyUser:" PxyPwd
		createUser "$PxyUser" "$PxyPwd"
	else
		read -p "Enter IP Address to Authenticate for Block $SRANGE - $ERANGE   :" Auth_IP
		PxyUser="$Auth_IP"
		PxyPwd="NA"
	fi
}
processConfigSL()
{
	for (( C=$SRANGE; C<=$ERANGE; C++ ))
	do
		IP=`cat $TEMP_IPFILE | grep -w "^$C" | awk '{print $2}'`
		plumbIP "$IP"
		if [ $AUTH_METHOD -eq 1  ]
		then
			writeConfig "$IP" "$PxyPort" "$PxyUser" "$PxyPwd"
			echo "$IP:$PxyPort:$PxyUser:$PxyPwd" >> tempiprange
			saveDB "$IP" "$PxyPort" "$PxyUser" "$PxyPwd"
		else
			writeConfig "$IP" "$PxyPort" "$Auth_IP" "NA"
			echo "$IP":"$PxyPort":"$Auth_IP":"NA" >> tempiprange
			saveDB "$IP" "$PxyPort" "$Auth_IP" "NA"
		fi
	done
	echo
	echo "New Proxy Configuration"
	printf "\n================================================\n"
	cat tempiprange
	>$TEMP_IPFILE
	>tempiprange
}
deleteConfigSL()
{
	for (( C=$SRANGE; C<=$ERANGE; C++ ))
	do
		IP=`cat $TEMP_IPFILE | grep -w "^$C" | awk '{print $2}'`
		cat $CONFIG_FILE | grep -v $IP > temp_config
		cat temp_config > $CONFIG_FILE
		cat $SQUIDDB | grep -v -w "^$IP" > temp_db
		cat temp_db > $SQUIDDB
		unplumbIP "$IP"
		#cat $NETWORK_FILE | grep -v -B1 $IP > temp_network
		#cat temp_network > $NETWORK_FILE
	done
	cat -s $CONFIG_FILE > /tmp/squid.temp
	cat /tmp/squid.temp > $CONFIG_FILE
	>$TEMP_IPFILE
	>tempiprange
	>temp_config
	>temp_db
	>temp_network
	>/tmp/squid.temp
}
createMenu()
{
	clear
	printf "1. Install Squid\n2. Create Proxy by Username\n3. Delete Proxy \n4. Reset Configuration & Proxies\n5. View Configuration\n6. Plumb IP's\n7. Create Proxy by Range\n8. Delete Proxy by Range\n9. Exit\nEnter Your Option []: "
	read REPLY
	case "$REPLY" in
		1)
			installSquid
			systemctl start squid
			systemctl enable squid
			;;
		2)	
			if [ ! -f $CONFIG_FILE ];then echo "Squid Not Installed";exit 7;fi
			if [ ! -f /usr/bin/htpasswd ];then echo "Apache2 Utils Not Installed";exit 8;fi
			if [ ! -f $IP_FILE ];then echo "IP FILE not exist. Please create a file name squid.IPFILE in /etc/squid directory ";exit 8;fi
			copySquid
			isFirstTime
			getInterface
			getPxyInput
			getCurrentConfig
			processConfig
			restartSquid
			;;
		3)
			if [ ! -f $IP_FILE ];then echo "IP FILE not exist. Please create a file name squid.IPFILE in /etc/squid directory ";exit 8;fi
			copySquid
			displayCurrentConfig
			getInterface "DEL"
			deleteConfig
			restartSquid
			;;
		4)
			copySquid
			for ADDR in `cat $SQUIDDB|awk -F: '{print $1}'`	
			do
				unplumbIP "$ADDR"
			done
			>$SQUIDDB
			>$CONFIG_FILE
			restartSquid
			;;
		5)
			displayCurrentConfig
			>$TEMP_IPFILE
			;;
		6) 
			read -n 1 -p "Do this only after reboot of system. Are you sure (Y/N):" REP
			if [ "$REP" == "Y" ] || [ "$REP" == "y" ] 
			then
				for ADDR in `cat $SQUIDDB|awk -F: '{print $1}'`	
				do
					plumbIP "$ADDR"
				done
			else
				createMenu
			fi
			;;
		7)	
			if [ ! -f $CONFIG_FILE ];then echo "Squid Not Installed";exit 7;fi
			if [ ! -f /usr/bin/htpasswd ];then echo "Apache2 Utils Not Installed";exit 8;fi
			if [ ! -f $IP_FILE ];then echo "IP FILE not exist. Please create a file name squid.IPFILE in /etc/squid directory ";exit 8;fi
			copySquid
			isFirstTime
			displaywithSL
			getInterface
			getPxyInputSL
			processConfigSL
			restartSquid
			;;
		8)
			if [ ! -f $IP_FILE ];then echo "IP FILE not exist. Please create a file name squid.IPFILE in /etc/squid directory ";exit 8;fi
			copySquid
			displaywithSL
			getInterface "DEL"
			read -p "Enter Starting Range of IP Address :" SRANGE
			read -p "Enter Ending Range of IP Address   :" ERANGE
			if [ $SRANGE -gt $ERANGE ];then createMenu;fi
			deleteConfigSL
			restartSquid
			;;
		9) 
			rm -f temp_config
			rm -f temp_db
			rm -f temp_ipfile
			rm -f tempiprange
			exit 0
			;;
		*)	createMenu
			;;
	esac	
}
clear
checkRoot
checkOS
while true
do
	createMenu
	read -p "Press any key to continue. Q to Quit" input
	if [[ $input = "q" ]] || [[ $input = "Q" ]]
			then
				break
			fi
done
echo

echo