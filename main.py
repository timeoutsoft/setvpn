import os
import random

ipsec_conf_text="""
config setup
    charondebug="ike 1, knl 1, cfg 0"
    uniqueids=no

conn ikev2-vpn
    auto=add
    compress=no
    type=tunnel
    keyexchange=ikev2
    fragmentation=yes
    forceencaps=yes
    dpdaction=clear
    dpddelay=300s
    rekey=no
    left=%any
    leftid=@server_domain_or_IP
    leftcert=server-cert.pem
    leftsendcert=always
    leftsubnet=0.0.0.0/0
    right=%any
    rightid=%any
    rightauth=eap-mschapv2
    rightsourceip=$$$rightsourceip$$$
    rightdns=8.8.8.8,8.8.4.4
    rightsendcert=never
    eap_identity=%identity
    ike=chacha20poly1305-sha512-curve25519-prfsha512,aes256gcm16-sha384-prfsha384-ecp384,aes256-sha1-modp1024,aes128-sha1-modp1024,3des-sha1-modp1024!
    esp=chacha20poly1305-sha512,aes256gcm16-ecp384,aes256-sha256,aes256-sha1,3des-sha1!
"""

def get_random_subnet():
    octet3=random.randint(201, 240)
    return "192.168."+str(octet3)+".0/24"


ufw_rule1="""

#added by vpnset
*nat
-A POSTROUTING -s 10.10.10.0/24 -o eth0 -m policy --pol ipsec --dir out -j ACCEPT
-A POSTROUTING -s 10.10.10.0/24 -o eth0 -j MASQUERADE
COMMIT

*mangle
-A FORWARD --match policy --pol ipsec --dir in -s 10.10.10.0/24 -o eth0 -p tcp -m tcp --tcp-flags SYN,RST SYN -m tcpmss --mss 1361:1536 -j TCPMSS --set-mss 1360
COMMIT


"""

ufw_rule2=""" 

#added by vpnset
-A ufw-before-forward --match policy --pol ipsec --dir in --proto esp -s 10.10.10.0/24 -j ACCEPT
-A ufw-before-forward --match policy --pol ipsec --dir out --proto esp -d 10.10.10.0/24 -j ACCEPT

"""

def find_ip ():
    import urllib.request
    external_ip = urllib.request.urlopen('https://ident.me').read().decode('utf8')
    return external_ip

def set_before_rules():
    print("Starting to modify before.rules.")
    path = r"before.rules"

    # Each line of the file is read, and
    # stored in a list variable
    data = open(path, 'r').readlines()

    text=""
    # The loop iterates over each line of the file
    for x in data:
        if (x=="#added by vpnset\n"):
            print("File before.rules already modified by vpnset. Operation canceled!")
            return


        if x=='# Don\'t delete these required lines, otherwise there will be errors\n':
            text = text+ ufw_rule1 +x
        elif  x=='# allow all on loopback\n':
            text = text+ ufw_rule2 +x
        else:
            text = text+ x

    os.rename('before.rules', 'before.rules.orig')
    with open('before.rules', 'a') as f:
        f.write(text)
    print("File before.rules modified.")

def set_sysctl_conf():
    print("Starting to modify sysctl.conf.")
    path = r"sysctl.conf"

    data = open(path, 'r').readlines()

    text=""
    # The loop iterates over each line of the file
    for x in data:
        if (x=="#added by vpnset\n"):
            print("File sysctl.conf already modified by vpnset. Operation canceled!")
            return

        if x=='#net/ipv4/ip_forward=1\n':
            text = text+ "\n#added by vpnset\nnet/ipv4/ip_forward=1\n"

        else:
            text = text+ x

    text=text+"\n#added by vpnset\nnet/ipv4/ip_no_pmtu_disc=1\n"
    os.rename('sysctl.conf', 'sysctl.conf.orig')
    with open('sysctl.conf', 'a') as f:
        f.write(text)
    print("File sysctl.conf modified.")

if __name__ == '__main__':
    server_ip=find_ip()
    server_ip=str(input("Server IP (discovered) = "+ server_ip) or server_ip)
    print ("IP used in scripts: "+server_ip)
    print ("Subnet for clients: "+get_random_subnet())
    set_before_rules()
    set_sysctl_conf()