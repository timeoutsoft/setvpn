#/bin/bash
apt update
apt upgrade -y

apt install python3 -y
apt install mc -y
apt install libtss2-tcti-tabrmd0 -y
apt install strongswan strongswan-pki libcharon-extra-plugins libcharon-extauth-plugins libstrongswan-standard-plugins libstrongswan-extra-plugins -y
python3 main.py