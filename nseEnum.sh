#!/bin/bash

function nseEnum()
{
	# Iterate over each pair (target, port) found
	# Loop over all targets found with open ports
	for line in $(cat irEnumeration.csv 2>/dev/null)
	do
		if [ "$line" != "" ]
		then
			ip=$(echo "$line" | awk -F"," '{print $1}')
			port=$(echo "$line" | awk -F"," '{print $2}')
			service=$(echo "$line" | awk -F"," '{print $3}')
			# Loop over all scripts relevant for the scanned service
			for script in $(find /usr/share/nmap/scripts -name *$service* -type f)
			do
				# Extract the categories of each script
				categories=$(nmap --script-help $script | grep Categories)
				# Only run safe scripts, which are not related to any intrusive category (See specified categories below)
				if [ "$(echo "$categories" | grep safe)" != "" -a "$(echo "$categories" | grep -e vuln -e brute -e dos -e exploit -e fuzzer -e malware)" == "" ]
				then
					# Extract script name into "$scriptName" (Full name), and "$name" (without the '.nse' suffix)
					scriptName=$(echo "$script" | awk -F "/" '{print $6}')
					name=${scriptName:0: -4}
					# Run the script
					scriptRes=$(nmap -PO -sV $ip -p $port --script=$script 2>/dev/null | grep -E "^\|")
					# Create tile to print at the start of result
					title="$ip::$port"
					# Only save unique results which are not empty
					if [ "$scriptRes" != "" -a  "$(cat nseEnum.txt | grep "$title::$name")" == "" ]
					then
						# Starting line (Used for searching through results)
						echo "$title::$name" >> nseEnum.txt
						# Script result
						echo "$scriptRes" >> nseEnum.txt
						# Final line (Used for searching through results)
						echo "END" >> nseEnum.txt
					fi
				fi
			done
			# Same methodology with the banner script
			bannerRes=$(nmap -PO -sV $ip -p $port --script=banner 2>/dev/null | grep -E "^\|")
			if [ "$bannerRes" != "" -a  "$(cat nseEnum.txt | grep "$title::banner")" == "" ]
			then
				echo "$title::banner" >> nseEnum.txt
				echo "$bannerRes" >> nseEnum.txt
				echo "END" >> nseEnum.txt
			fi
		fi
	done
}

orange='\033[0;33m'
clear='\033[0m'
ORG=$IFS
IFS=$'\n'
# Run NSE safe scripts on all targets found with open ports
nseEnum
IFS=$ORG
