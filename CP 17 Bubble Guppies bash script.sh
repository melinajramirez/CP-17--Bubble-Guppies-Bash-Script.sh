#!/usr/bin/bash 
#Updates
apt-get update
apt-get upgrade
#Installing and cofiguring UFW
apt-get install ufw
ufw enable
ufw status
#Looking for unwanted files types
find /home -type f | grep -if extensions.txt
#Look for and remove any extensions that are found in our text file
while IFS= read -r extension; do
    find /home -type f -name "$extension" -exec rm -f {} +
done < extensions.txt
