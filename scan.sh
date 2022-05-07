#!/bin/bash

function nmapScan()
{
	# Scan horizontally to avoid detection (Port-by-port rather than target-by-target)
	for port in $(seq $startPort $endPort | shuf) # Shuffle ports for increased randomization, thus avoiding detection
	do
		for target in $(cat irTargets.lst | shuf) # Shuffle targets anew for each port scanned for increased randomization, thus avoiding detection (Remove "| suf" if testing a specific IP or just modify the targets file to include only 1 address)
		do
			# Using '-Pn' to skip pings, as TOR does not allow ICMP traffic
			scan=$(nmap -Pn -sV $target -p $port) # Nmap scan result for a single port on a single target
			status=$(echo "$scan" | grep open | awk '{print $2}') # Port status
			prefix=$(date +'%d/%m/%Y %H:%M:%S(%Z)') # Log prefix
			if [ "$status" == "open" ] # Skip to the next target if the port scanned isn't open
			then
				# Extract result details
				service=$(echo "$scan" | grep open | awk '{print $3}')
				version=$(echo "$scan" | grep open | awk '{$1=$2=$3="";print}' | sed 's/^ *//g')
				if [ "$version" == "" ]
				then
					version="none"
				fi
				data="$target,$port,$service,$version"
				# Avoid duplicate results
				# The command 'echo $?' returns '1' if either '$data' is not already in the result file or the result file doesn't exist
				# The only case in which 'echo $?' returns a different output ('0'), is when '$data' is already inside the result file
				statCode=$(cat irEnumeration.csv 2>/dev/null | grep -q "$data"; echo $?)
				if [ "$statCode" == "1" ]
				then
					echo "$data" >> irEnumeration.csv
				fi
				# Log open port found
				# The log body ends on the 6th line, therefore:
				# Insert each new line as the new 6th line, meaning new lines in the log will be shown first
				if [ "$(cat .sensitive.lst | grep -o "$target")" != "" ]
				then
					outFile="logs/sensitive.html"
				else
					outFile="logs/openPorts.html"
				fi
				sed -i "6i\\$TAB$TAB<div style='color: green'>$prefix INFO Open port: $target:$port, Service: $service, Version: $version</div>\\" $outFile
			else
				# Log closed port found (By closed I'm referring to both closed and filtered ports)
				# The log body ends on the 6th line, therefore: Insert each new line as the new 6th line, meaning new lines in the log will be shown first
				sed -i "6i\\$TAB$TAB<div style='color: red'>$prefix INFO Closed port: $target:$port</div>\\" logs/closedPorts.html
			fi
		done
	done
}

orange='\033[0;33m'
clear='\033[0m'
TAB=$'\t'
ORG=$IFS
IFS=$'\n'
# Get currently configured port range
startPort=$(jq '.start_port' .settings.json | sed 's/\"//g')
endPort=$(jq '.end_port' .settings.json | sed 's/\"//g')
# Scan 24/7
while true
do
	nmapScan
done
IFS=$ORG
