# Red Team Course: Bash Project

## Description
This project is able to scan a list of targets 24/7.\
In addition, it has an interactive UI which enables the user to:

    1. Start BF attacks on scanned services.
    2. Run NSE scripts for enumaration / exploitation purposes.
    3. View results for each scanned IP.
    4. View scan logs through the web.

First initialization will take considerably longer due to the following reasons:
1. Dependencies being downloaded.
2. Initial target list creation.

## Requirements
Please run the `interface.sh` file using `root privileges`, otherwise some functionalities may not work properly.\
The program will automatically download all required dependencies upon first intialization:

    - dos2unix
    - figlet
    - bc
    - tee
    - jq
    - nohup
    - nmap
    - hydra
    - python3

## Disclaimer:
- All functionalities are executed anonymously using [Nipe](https://github.com/htrgouvea/nipe).
- The initial targets list is created using IP ranges from the [NirSoft](https://www.nirsoft.net/countryip/ir.html) website.

