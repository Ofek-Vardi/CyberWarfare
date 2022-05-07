#!/bin/bash

function anon()
{
	nipePath=$(jq '.nipe' .settings.json | sed 's/\"//g')
	curr=$(pwd)
	cd ${nipePath%/*}
	./nipe.pl $operation
	cd $curr
}

function helpMsg()
{
	# display help message
	# No tabs next for syntax reasons
	cat << EOF
This program should be executed using root account!

Available modules:
1. Scan - Scans all IPv4 addresses of Iran.
2. Brute Force - Attempts to brute force login services found on targets.
3. Enumeration - Attempts to enumerate all services found on targets (Also captures banners).
4. Exploitation - Attempts to exploit all services found on targets.

-Each module's results can be viewed from the main menu.
-Scan logs can be viewed via any browser.
-Certain data can be extracted for each of the scanned IPs (Assuming open ports found).
-This script maximizes randomness in order to avoid detection.

That's it, you are on your own now..

GOOD LUCK!
EOF
}

function ipList()
{
	# Make sure target file doesn't exist (Avoid dupes)
	if [ ! -f irTargets.lst ]
	then
		# Loop over each line in the NirSoft address table, and create a range of IPs from the given starting + final addresses of each range
		# I.E: if starting IP is "1.3.5.7", and final IP is "2.4.6.8", then the resulting range will be "1-2.3-4.5-6.7-8"
		for line in $(cat ir.csv)
		do
			if [ "$line" != "" ]
			then
				start=$(echo $line | awk -F ',' '{print $1}') # Starting address
				end=$(echo $line | awk -F ',' '{print $2}') # Final address
				range=""
				# Loop over all 4 octats of both addresses simultaneously
				for i in {1..4}
				do
					soct=$(echo $start | cut -d '.' -f$i) # Octat of starting adress
					eoct=$(echo $end | cut -d '.' -f$i) # Octat of final adress
					# Create a new octat for the range of IPs
					if [ "$soct" == "$eoct" ]
					then
						noct="$soct" # Case when octats are identical in starting and final addresses
					else
						noct="$soct-$eoct" # Case when octats are different in starting and final addresses
					fi
					range="$range.$noct" # Append the new octat to IP range
				done
				# Remove the leading '.', extract all hosts in range and append to the targets file
				nmap -n -sL ${range:1} | awk '/Nmap scan report/{print $NF}' >> irTargets.lst
			fi
		done
	fi
}

function resetSettings()
{
	# Reset all settings to default values
	echo '{"user_list": ".usr.lst", "pass_list": ".pass.lst", "start_port": "1", "end_port": "65535", "nipe": "nipe/nipe.pl"}' > .settings.json
}

function clearLogs()
{
	# Clear all log files
	for fname in $(find logTemplates -type f | awk -F '/' '{print $NF}')
	{
		cat logTemplates/$fname > logs/$fname
	}
}

function defaultFiles()
{
	# Create dependency files
	# Default services list
	if [ ! -f .services.lst ]
	then
	echo "ssh" >> .services.lst
	echo "ftp" >> .services.lst
	echo "smb" >> .services.lst
	echo "smtp" >> .services.lst
	echo "irc" >> .services.lst
	fi

	# Default usernames list
	if [ ! -f .usr.lst ]
	then
		echo -e "Admin\nadmin\nAdministrator\nadministrator\nroot\nguest\nusername\ndemo\nuser1\nIEUser\nmsfadmin" > .usr.lst
	fi

	# Default passwords list
	if [ ! -f .pass.lst ]
	then
		echo -e "p@ssword\nPassw0rd!\ntoor\npassword\nadmin\nadministrator\nst@rt123\n123456\n1234567890\n123456aA\nmsfadmin" > .pass.lst
	fi

	# Default bash dependencies list
	echo "nmap" > .bashDependencies.lst
	echo "dos2unix" >> .bashDependencies.lst
	echo "figlet" >> .bashDependencies.lst
	echo "hydra" >> .bashDependencies.lst
	echo "bc" >> .bashDependencies.lst
	echo "tee" >> .bashDependencies.lst
	echo "nohup" >> .bashDependencies.lst
	echo "jq" >> .bashDependencies.lst
	echo "python3" >> .bashDependencies.lst

	# Default git dependencies list
	echo "nipe.pl|.initNipe.sh" > .gitDependencies.lst

	# Create init file for - nipe
	if [ ! -f .initNipe.sh ]
	then
		echo "git clone https://github.com/htrgouvea/nipe && cd nipe" > .initNipe.sh
		echo "cpan install Try::Tiny Config::Simple JSON" >> .initNipe.sh
		echo "perl nipe.pl install" >> .initNipe.sh
		chmod 777 .initNipe.sh
	fi

	# Set default settings
	# Default settings can be changed in the 'displaySettings()' function
	if [ ! -f .settings.json ]
	then
		resetSettings
	fi

	# Create sensitive IPs bank
	if [ ! -f .sensitive.lst ]
	then
		# Iran APT related IPs taken from - https://publicintelligence.net/fbi-iranian-apt/
		sensitiveIps="104.200.128.126,104.200.128.161,104.200.128.173,104.200.128.183,104.200.128.184,104.200.128.185,104.200.128.187,104.200.128.195,104.200.128.196,104.200.128.198,104.200.128.205,104.200.128.206,104.200.128.208,104.200.128.209,104.200.128.48,104.200.128.58,104.200.128.64,104.200.128.71,107.181.160.138,107.181.160.178,107.181.160.179,107.181.160.194,107.181.160.195,107.181.161.141,107.181.174.21,107.181.174.232,107.181.174.241,141.105.70.235,141.105.70.236,141.105.70.237,141.105.70.238,141.105.70.239,141.105.70.240,141.105.70.241,141.105.70.242,141.105.70.243,141.105.70.244,141.105.70.245,141.105.70.246,141.105.70.247,141.105.70.248,141.105.70.249,141.105.70.250,144.168.45.126,146.0.73.107,146.0.73.108,146.0.73.109,146.0.73.110,146.0.73.111,146.0.73.112,146.0.73.113,146.0.73.114,173.244.173.10,173.244.173.11,173.244.173.12,173.244.173.13,173.244.173.14,206.221.181.253,209.51.199.112,209.51.199.113,209.51.199.114,209.51.199.115,209.51.199.116,209.51.199.117,209.51.199.118,31.192.105.15,31.192.105.16,31.192.105.17,38.130.75.20,66.55.152.164,68.232.180.122,91.218.247.157,91.218.247.158,91.218.247.160,91.218.247.161,91.218.247.162,91.218.247.165,91.218.247.166,91.218.247.167,91.218.247.168,91.218.247.169,91.218.247.170,91.218.247.173,91.218.247.180,91.218.247.181,91.218.247.182,91.218.247.183"
		echo "$sensitiveIps" | awk -F ',' '{for(i=1;i<=NF;i++) print $i}' > .sensitive.lst
	fi

	# Create empty logs
	if [ ! -d logs ]
	then
		mkdir logs
	fi
	# Add log files
	clearLogs
}

function initStatus()
{
	# Status message displayed while downloading dependencies
	clear
	logo=$(figlet CYBER WARFARE -f block -t)
	printf "${orange}"
	echo "$logo"
	echo
	echo "Initializing..."
}

function checkDependencies()
{
	# Make sure all init files exist
	defaultFiles

	# Verify all bash packages used
	updated=0
	initStatus
	for package in $(cat .bashDependencies.lst)
	do
		if [ "$(which $package 1>/dev/null; echo $?)" == "0" ]
		then
			echo "$package is installed"
		else
			echo "Did not find $package, installing.."
			if [ $updated -eq 0 ]
			then
				apt-get update --fix-missing 1>/dev/null
				apt-et install -f
				updated=1
			fi
			apt-get --yes --force-yes install -f $package 1>/dev/null
			echo "$package was installed"
		fi
	done

	# Verify all git packages used
	for gitp in $(cat .gitDependencies.lst)
	do
		# Each line in the .gitDependencies files contains the following - "file_name|init_file"
		pname=$(echo $gitp | awk -F "|" '{print $1}')
		ppath=$(find / -type f -name $pname 2>/dev/null)
		initFile=$(echo $gitp | awk -F "|" '{print $2}')
		if [ "$ppath" == "" ]
		then
			echo "Did not find $pname, cloning from git repo..."
			bash "$initFile"
			echo "$pname was initialized"
		else
			echo "$pname is already installed at - $ppath"
			# Change the nipe executable path in settings
			if [ "$pname" == "nipe.pl" ]
			then
				jq '.nipe = $x' --arg x $ppath .settings.json > tmp.$$.json && mv tmp.$$.json .settings.json
			fi

		fi
	done

	# The next 2 sections of this function are executed here instead of inside the 'defaultFiles()' function
	# This is because they require the use of dos2unix and thus need to be executed only after verifying all dependencies
	# Create a targets list from the NirSoft table, if it doesn't exist already
	if [ ! -f irTargets.lst ]
	then
		# Download Iran's IP adress blocks from the NirSoft webpage into a file, if the file doesn't exist already
		if [ ! -f ir.csv ]
		then
			echo "Downloading address ranges from NirSoft..."
			wget https://www.nirsoft.net/countryip/ir.csv -q
			dos2unix -q ir.csv # Convert the file to unix format (Chnage newlines from '^M' in DOS to '\n' in Unix amongst other formatting changes)
		fi
		echo "Creating targets list..."
		ipList
	fi

	# Clear stdout color (Was changed inside the function initStatus)
	printf "${clear}"
	# Grant current user RWX permissions for all files
	chmod 777 *.sh
}

function listAddresses()
{
	# List all unique addresses found with open ports
	logo=$(figlet IP DB -f block -t)
	clear
	printf "${orange}"
	echo "$logo"
	echo "=========="
	printf "${clear}"
	data=$(cat irEnumeration.csv 2>/dev/null | awk -F ',' '{print $1}' | sort | uniq)
	if [ "$data" != "" ]
	then
		echo "$data"
	else
		# Display a message if no addresses with open ports were found so far
		echo
		echo "No addresses found so far..."
		echo
	fi
	printf "${orange}Press '9' to exit${clear}"
	# Wait for the user to press '9', then quit back to the relevant menu
	while true
	do
		read -rsn1 keyPress
		if [ "$keyPress" == "9" ]
		then
			break
		fi
	done
	sleep 2 # For demonstration purposes
}

function displaySettings()
{
	# Disclaimer: I only included 4 settings for demo purposes, but this can be extended in multiple ways for mudularity reasons
	# For example - Choosing which country to scan, which tool to use for scanning, etc
	while true
	do
		# Get current settings
		USRLST=$(jq '.user_list' .settings.json | sed 's/\"//g')
		PASSLST=$(jq '.pass_list' .settings.json | sed 's/\"//g')
		SPORT=$(jq '.start_port' .settings.json | sed 's/\"//g')
		EPORT=$(jq '.end_port' .settings.json | sed 's/\"//g')
		# Display currently configured settings for the user
		clear
		printf "${orange}"
		echo "$logo"
		echo "=========="
		echo "1. Users List => $USRLST"
		echo "2. Passwords List => $PASSLST"
		echo "3. Start Port => $SPORT"
		echo "4. End port => $EPORT"
		echo "D. Factory Settings (Reset)"
		echo "9. Back"
		echo
		printf "To modify a setting, please choose its number: ${clear}"
		# Wait for the user to choose an action
		read -sn1 action
		echo
		case $action in
		"1" )
			# Update users list path
			printf "${orange}Choose a new user list: ${clear}"
			read USRLIST
			jq '.user_list = $x' --arg x $USRLIST .settings.json > tmp.$$.json && mv tmp.$$.json .settings.json
			rm -f tmp.$$.json;;
		"2" )
			# Update passwords list path
			printf "${orange}Choose a new password list: ${clear}"
			read PASSLIST
			jq '.pass_list = $x' --arg x $PASSLIST .settings.json > tmp.$$.json && mv tmp.$$.json .settings.json
			rm -f tmp.$$.json;;
		"3" )
			# Update start port for scanning
			printf "${orange}On which port should scans start? ${clear}"
			read SPORT
			jq '.start_port = $x' --arg x $SPORT .settings.json > tmp.$$.json && mv tmp.$$.json .settings.json
			rm -f tmp.$$.json;;
		"4" )
			# Update end port for scanning
			printf "${orange}On which port should scans stop? ${clear}"
			read EPORT
			jq '.end_port = $x' --arg x $EPORT .settings.json > tmp.$$.json && mv tmp.$$.json .settings.json
			rm -f tmp.$$.json;;
		"d" | "D" )
			# Reset all settings to default values
			printf "${orange}Are you sure? y/N ${clear}"
			read -sn1 ok
			if [ "$ok" == "y" -o "$ok" == "Y" ]
			then
				resetSettings
			fi;;
		"9" )
			# Go back to main menu
			break;;
		esac
	done
}

function findNseData()
{
	# Extract nse results for the currently chosen IP from the respective nse result file (safe  / exploit)
	# Each nse results starts with a lign containing the scanned IP followed by '::', and ends with a line containing 'END'
	# Extract starting line numbers for all results related to the currently chosen IP
	startLines=$(cat $nseResFile | grep -n "$ip::" | awk -F ':' '{print $1}')
	# For each stating line, return all lines until 'END' is reached (All echoed data is returned into a variable in the function subMenu8)
	for start in $startLines
	do
		for line in $(tail -n +$start $nseResFile)
		do
			if [ "$line" != "END" ]
			then
				echo "$line"
			else
				echo "END"
				break
			fi
		done
	done
}

function queryRes()
{
	# Display relevant results for the currently chosen IP address
	clear
	printf "${orange}"
	echo "$logo"
	echo "=========="
	printf "${clear}"
	if [ "$data" != "" ]
	then
		echo "$data"
	else
		echo
		echo "No data was collected for the address provided..."
		echo
	fi
	printf "${orange}Press '9' to exit${clear}"
	# Wait for a suer input and quit back to actions menu (sunMenu8 function) once the user chooses '9'
	while true
	do
		read -sn1 keyPress
		if [ "$keyPress" == "9" ]
		then
			break
		fi
	done
}

function verifyAddress()
{
	# Check the returned value of the function 'getAddress()', and trigger it again if it is empty, until the user inputs a valid IPv4 address
	while [ "$ip" == "" ]
	do
		echo "Invalid IP"
		printf "${orange}> Choose an IP: ${clear}"
		ip=$(getAddress)
	done
}

function getAddress()
{
	# Wait for the user to choose an IPv4 address
	read -r input
	# FVerify the input is a valid IPv4 address
	pattern=$(echo $input | grep -E -o "(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)")
	if [ "$pattern" == "$input" ]
	then
		# return the user input if it is a valid IPv4 address
		echo "$input"
	else
		# return nothing if the input is not a valid IPv4 address
		echo
	fi
}

function subMenu8()
{
	# Display actions menu, as well as the specific IP chosen by the user
	printf "${orange}> Choose an IP: ${clear}"
	# Get initial IP address from user, and save the returned value in '$ip'
	ip=$(getAddress)
	# Check the retunred value saved in '$ip'
	verifyAddress
	# Display options for the user, keep displaying the menu until the user quits back to the main menu
	while true
	do
		clear
		logo=$(figlet QUERY DB -f block -t)
		printf "${orange}"
		echo "$logo"
		echo "=========="
		echo "Current IP: $ip"
		echo "=========="
		echo
		echo "1. 'whois' Command Information"
		echo "2. Ports & Services"
		echo "3. Cracked Login Services"
		echo "4. Potential Exploits"
		echo "5. NSE Enumeration"
		echo "6. Change Address"
		echo "L. List IPs From DB"
		echo "9. Exit"
		printf "${clear}"
		echo
		printf "${orange}> Choose an action: ${clear}"
		# Wait for a valid user action, and show the respective data for the chosen IP
		read -sn1 action
		case $action in
		"1" )
			# Show 'whois' info
			logo=$(figlet "WHOIS INFO" -f block -t)
			data=$(whois $ip)
			queryRes;;
		"2" )
			# Show all open ports and running services
			logo=$(figlet "PORTS & SERVICES" -f block -t)
			data=$(cat irEnumeration.csv | grep "$ip" | awk -F "," '{print $2" ---> "$3"("$4")"}' | sort -n) # Syntax for each port - "port service version"
			queryRes;;
		"3" )
			# Show all login services which were successfully cracked
			logo=$(figlet "LOGIN SERVICES" -f block -t)
			data=$(cat irCreds.csv | grep "$ip")
			queryRes;;
		"4" )
			# Show all potential exploits found
			logo=$(figlet "NSE EXPLOIT DATA" -f block -t)
			nseResFile="nseExploit.txt"
			data=$(findNnseData)
			queryRes;;
		"5" )
			# Show all data found with safe NSE scripts
			logo=$(figlet "NSE ENUM DATA" -f block -t)
			nseResFile="nseEnum.txt"
			data=$(findNseData)
			queryRes;;
		"6" )
			# Choose a new IP address
			printf "${orange}> Choose an IP: ${clear}"
			ip=$(getAddress)
			verifyAddress;;
		"l" | "L" )
			# List all scanned IPs found to have open ports
			listAddresses;;
		"9" )
			# Go back to main menu
			break;;
		esac
	done
}

function Res()
{
	# Display the all results collected so far for a certain module
	clear
	printf "${orange}"
	echo "$logo"
	echo "=========="
	printf "${clear}"
	data=$(cat $resFile 2>/dev/null)
	if [ "$data" != "" ]
	then
		echo "$data"
	else
		# If no results were collected yet
		echo
		echo "No data collected so far..."
		echo
	fi
	printf "${orange}Press '9' to exit${clear}"
	# Go back to main menu when the user presses '9'
	# The results will update every time the user comes back to this page (Rather than refreshing the display in real time), thus enabling the user to scroll through results without interruptions
	while true
	do
		read -sn1 keyPress
		if [ "$keyPress" == "9" ]
		then
			break
		fi
	done
}

function procMenu()
{
	# Action menu - Enables the user to stop / start a module
	# Keep displaying the menu until the user goes back to the modules menu
	while true
	do
		# Find the PIDs of all running instances
		ps=$(ps aux | grep "$mod" | grep "bash" | awk '{print $2}')
		psNum=$(ps aux | grep "$mod" | grep "bash" | wc -l)
		psList=$(echo "$ps" | xargs | sed 's/ /, /g')
		# Display options for the user
		clear
		logo=$(figlet AVAILABLE ACTIONS: "$mod" -f block -t)
		printf "${orange}"
		echo "$logo"
		echo "=========="
		echo "Running Instances: ($psNum)"
		echo "PIDs: $psList"
		echo "=========="
		echo
		echo "1. Start"
		echo "2. Stop (All Running Instances)"
		echo "9. Back"
		echo
		printf "> Choose an action: ${clear}"

		# Refresh the menu, which contains data about the running instances of a certain module, every 0.25 seconds
		read -t 0.25 -sn1 action
		case $action in
		"1" )
			# Run the relevant module
			bash $mod 2>/dev/null &;;
		"2" )
			# Kill all instances of a relevant module
			while [ "$ps" != "" ]
			do
				for id in $(echo "$ps"); do kill -9 $id 2>/dev/null; done
				# Kill the respective toll used, i.e. hydra / nmap
				pkill -9 $tool 2>/dev/null
				# Verify all instances were killed
				ps=$(ps aux | grep "$mod" | grep "bash" | awk '{print $2}')
			done;;
		"9" )
			# Go back to modules menu
			break;;
		esac
	done
}

function subMenu1()
{
	# Display all available modules
	# Keep displaying this menu until the user goes back to the main menu
	while true
	do
		clear
		logo=$(figlet AVAILABLE MODULES -f block -t)
		printf "${orange}"
		echo "$logo"
		echo
		echo "1. Scan"
		echo "2. Brute Force"
		echo "3. NSE Enum"
		echo "4. NSE Exploit"
		echo "9. Back"
		echo
		printf "> Choose an action: ${clear}"

		# Wait for a valid user action
		read -sn1 action
		# Display action menu for each module respectively
		case $action in
		"1" )
			mod="scan.sh"
			tool="nmap"
			procMenu 2>/dev/null;;
		"2" )
			# Include currently configured user & password lists as input for 'brute.sh'
			mod="brute.sh"
			tool="hydra"
			procMenu 2>/dev/null;;
		"3" )
			mod="nseEnum.sh"
			tool="nmap"
			procMenu 2>/dev/null;;
		"4" )
			mod="nseExploit.sh"
			tool="nmap"
			procMenu 2>/dev/null;;
		"9" )
			# Go back to main menu
			break;;
		esac
	done
}

function menu()
{
	# Main user interface
	currAddress=$(curl -s ifconfig.me)
	# Keep updating the menu until a valid action is tyoed by the user
	while true
	do
		# Count the number of ports / IPs / Exploits scanned via the log file
		numTargets=$(cat logs/*Ports.html 2>/dev/null | grep -E -o "([0-9]{1,3}[\.]){3}[0-9]{1,3}" | sort | uniq | wc -l)
		numPorts=$(cat logs/*Ports.html 2>/dev/null | grep -e "Open" -e "Closed" | wc -l)
		numExploited=$(cat nseExploit.txt 2>/dev/null | grep -E -o "([0-9]{1,3}[\.]){3}[0-9]{1,3}" | sort | uniq | wc -l)
		# Verify BF module is running, all BF attempts are piped into '.hydra.res', while successful attempts are also copied to 'irCreds.csv'
		# Run this on another terminal (inside the interface script's folder) when activating the BF module to validate the BF rate calculation - for i in {1..1000}; do clear; echo "Attempts -"; cat .hydra.res | wc -l; echo "Time Passed: $i"; sleep 1; done
		if [ -f .hydra.res -a -f .bftime -a "$(ps aux | grep "brute.sh" | grep "bash")" != "" ]
		then
			# If BF is running, calculate BF speed (pass / sec)
			passNum=$(cat .hydra.res 2>/dev/null| sort | uniq | wc -l)
			startTime=$(cat .bftime)
			currTime=$(date +%s)
			dur=$((currTime-startTime))
			if [ $dur -eq 0 ]
			then
				pps=0
			else
				pps=$(echo "scale=2; $passNum/$dur" | bc -l)
			fi
			bfMsg="Currently running BF (Speed: $pps pass/sec)\n"
		else
			# If BF is not running
			bfMsg=""
			# Remove temp files related to BF speed calculation when the BF module isn't running
			rm -f .hydra.res .bftime
		fi

		# Interface
		clear
		logo=$(figlet CYBER WARFARE -f block -t)
		printf "${orange}"
		echo "$logo"
		echo "=========="
		echo "Current IP: $currAddress"
		echo "Number of targets scanned: $numTargets (Vulnerable: $numExploited)"
		echo "Number of ports scanned: $numPorts"
		printf "$bfMsg"
		echo "=========="
		echo
		echo "1. Start / Stop Processes"
		echo "2. Scan Results"
		echo "3. Brute Force Results"
		echo "4. NSE Enum Results"
		echo "5. NSE Exploit Results"
		echo "6. Install Dependencies"
		echo "7. Settings"
		echo "8. Query DB"
		echo "L. List IPs From DB"
		echo "H. Toggle Help Message"
		echo "C. Clear All Logs"
		echo "9. Exit"
		echo
		# Display help message if toggled by the user
		if [ $showHelp -eq 1 ]
		then
			echo "=========="
			helpMsg
			echo "=========="
			echo
		fi
		printf "> Choose an action: ${clear}"

		# Wait for user action, timeout every 0.25 seconds (In order to update the interface, which contains bf and scan data in real time)
		read -t 0.25 -sn1 action
		case $action in
		"1" )
			# Available modules menu
			subMenu1;;
		"2" )
			# Show open ports scanned
			logo=$(figlet "NMAP SCAN RESULTS" -f block -t)
			resFile=irEnumeration.csv
			Res;;
		"3" )
			# Show BF successful results
			logo=$(figlet "HYDRA BF RESULTS" -f block -t)
			resFile=irCreds.csv
			Res;;
		"4" )
			# Show results found using safe NSE scripts
			logo=$(figlet "NSE ENUM RESULTS" -f block -t)
			resFile=nseEnum.txt
			Res;;
		"5" )
			# Show potential exploits found
			logo=$(figlet "NSE EXPLOIT RESULTS" -f block -t)
			resFile=nseExploit.txt
			Res;;
		"6" )
			# Install all missing dependencies
			checkDependencies;;
		"7" )
			# Change script settings, i.e. default users / passwords lists.
			logo=$(figlet "SETTINGS" -f block -t)
			displaySettings;;
		"8" )
			# Extract data from results for specific IP
			subMenu8;;
		"l" | "L" )
			# Show all scanned addresses with open ports
			listAddresses;;
		"h" | "H" )
			# Show help message
			if [ $showHelp -eq 0 ]
			then
				showHelp=1
			else
				showHelp=0
			fi;;
		"c" | "C" )
			printf "${orange}If you continue, all logs will be lost! Are you sure? (y/N)${clear}"
			read -sn1 ok
			if [ "$ok" == "y" -o "$ok" == "Y" ]
			then
				clearLogs
			fi;;
		"9" )
			# Stop anonimity & Python http server, then close interface
			pkill -9 python3
			operation="stop"
			anon
			break;;
		esac
	done
}

orange='\033[0;33m'
clear='\033[0m'
ORG=$IFS
IFS=$'\n'

# Install all missing dependencies
checkDependencies

# Start web service for viewing logs
# Disclaimer: Core html & css code for 'index.html' & 'style.css' were copied from: https://codepen.io/jhancock532/pen/GRZrLwY
# With that said, a few modifications were made (Such as importing 'style.css' into 'index.html' and changing links)
webPid=$(ps aux | grep "python3 -m http.server" | awk '{print $2}')
if [ $(echo "$webPid" | wc -l) -lt 2 ]
then
	nohup python3 -m http.server --directory logs 80 &>/dev/null &
fi

# Become anonymous
operation="start"
anon

# Start scan if not already started
pids=$(ps aux | grep scan.sh | awk '{print $2}')
if [ $(echo "$pids" | wc -l) -lt 2 ]
then
	bash scan.sh &
fi

# Help message toggle
showHelp=0
# Display user interface
menu 2>/dev/null
IFS=$ORG
