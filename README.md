# Red Team Course: Bash Project

## Description

This project is able to scan a list of targets 24/7.\
In addition, it has an interactive UI which enables the user to:

    1. Start BF attacks on scanned services.
    2. Run NSE scripts for enumaration / exploitation purposes.
    3. View results for each scanned IP.
    4. View scan logs through the web.
    5. Highlight sensitive IPs.

First initialization will take considerably longer due to the following reasons:

1. Dependencies being downloaded.
2. Initial target list creation.

## Modifications

`Note: Both of the below files contain a single IP address on each line.`

*To modify the targets list, either:*

1. Create an `irTargets.lst` file before running the program for the first time.
2. Edit the `irTargets.lst` file at any given time, then restart the scan module.

*To modify the sensitive IPs list, either:*

1. Create a `sensitive.lst` file before running the program for the first time.
2. Edit the `sensitive.lst` file at any given time.

## Requirements

Please run the `interface.sh` file using `root privileges`, otherwise some functionalities may not work properly.\
The program will automatically download all required dependencies upon first intialization:

    - dos2unix
    - figlet
    - bc
    - tee
    - jq
    - nohup
    - Nmap
    - hydra
    - python3
    - nipe

## Disclaimer

- All functionalities are executed anonymously using [Nipe](https://github.com/htrgouvea/nipe).
- The initial targets list is created using IP ranges from the [NirSoft](https://www.nirsoft.net/countryip/ir.html) website.
- The initial list of sensitive IP addresses can be found in the following [Article](https://publicintelligence.net/fbi-iranian-apt/).
