import os
import random
import secrets
import string


author_info="""
*****
Disclaimer:
***** 

******
It's test script for our "GreatIdea" 'bout free VPN for BDO guild 'TimeOut' mmbrz
******
"""
print(author_info)
ipsec_secrets_text="""
: RSA "server-key.pem"
"""

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
    leftid=$$$leftip$$$
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
-A POSTROUTING -s 192.168.0.0/16 -o eth0 -m policy --pol ipsec --dir out -j ACCEPT
-A POSTROUTING -s 192.168.0.0/16 -o eth0 -j MASQUERADE
COMMIT

*mangle
-A FORWARD --match policy --pol ipsec --dir in -s 192.168.0.0/16 -o eth0 -p tcp -m tcp --tcp-flags SYN,RST SYN -m tcpmss --mss 1361:1536 -j TCPMSS --set-mss 1360
COMMIT

"""

ufw_rule2="""

#added by vpnset
-A ufw-before-forward --match policy --pol ipsec --dir in --proto esp -s 192.168.0.0/16 -j ACCEPT
-A ufw-before-forward --match policy --pol ipsec --dir out --proto esp -d 192.168.0.0/16 -j ACCEPT

"""

def find_ip ():
    import urllib.request
    external_ip = urllib.request.urlopen('https://v4.ident.me').read().decode('utf8')
    return external_ip

def generate_username():
    alphabet = string.ascii_letters
    username = ''.join(secrets.choice(alphabet) for i in range(3))
    return username.lower()


def generate_password():
    alphabet = string.ascii_letters + string.digits
    password = ''.join(secrets.choice(alphabet) for i in range(10))
    return password


def set_before_rules():
    print("Starting to modify before.rules")
    path = r"./before.rules"

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

    #os.rename('before.rules', 'before.rules.orig')
    with open('./before.rules', 'w') as f:
        f.write(text)
    print("File before.rules modified.")

def set_sysctl_conf():
    print("Starting to modify sysctl.conf.")
    path = r"./sysctl.conf"

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
    #os.rename('sysctl.conf', 'sysctl.conf.orig')
    with open('./sysctl.conf', 'w') as f:
        f.write(text)
    print("File sysctl.conf modified.")

def set_ipsec_conf(srv_ip, clnt_subn):
    print("Starting to modify ipsec.conf.")

    text=ipsec_conf_text.replace('$$$rightsourceip$$$',clnt_subn).replace('$$$leftip$$$',srv_ip)
    #os.rename('ipsec.conf', 'ipsec.conf.orig')
    with open('ipsec.conf', 'w') as f:
        f.write(text)
    print("File ipsec.conf modified.")


def set_ipsec_secrets(u1n, u1p, u2n, u2p, u3n, u3p, u4n, u4p, u5n, u5p):
    print("Starting to modify ipsec.secrets")

    text=ipsec_secrets_text+"\n"+u1n+' : EAP "'+u1p+'"\n'
    text = text+ u2n + ' : EAP "' + u2p + '"\n'
    text = text + u3n + ' : EAP "' + u3p + '"\n'
    text = text + u4n + ' : EAP "' + u4p + '"\n'
    text = text + u5n + ' : EAP "' + u5p + '"\n'

    with open('./ipsec.secrets', 'w') as f:
        f.write(text)
    #print (text)
    print("File ipsec.secrets created.")

def copy_source_files():
    os.system('cp -f /etc/ipsec.conf ./')
    os.system('cp -f /etc/ipsec.secrets ./')
    os.system('cp -f /etc/ufw/before.rules ./')
    os.system('cp -f /etc/ufw/sysctl.conf ./')

def back_copy_source_files():
    os.system('cp -f ./ipsec.conf /etc/ipsec.conf')
    os.system('cp -f ./ipsec.secrets /etc/ipsec.secrets ')
    os.system('cp -f ./before.rules /etc/ufw/before.rules ')
    os.system('cp -f ./sysctl.conf  /etc/ufw/sysctl.conf ')


def os_pre_operations(root_ca_name='TimeOutSoft CA', server_dn_ip='127.0.0.1'):
    #mkdir -p ~/pki/{cacerts,certs,private}
    #chmod 700 ~/pki
    #pki --gen --type rsa --size 4096 --outform pem > ~/pki/private/ca-key.pem
    #pki --self --ca --lifetime 3650 --in ~/pki/private/ca-key.pem --type rsa --dn "CN=Poland VPN root CA" --outform pem > ~/pki/cacerts/ca-cert.pem
    #pki --gen --type rsa --size 4096 --outform pem > ~/pki/private/server-key.pem
    #pki --pub --in ~/pki/private/server-key.pem --type rsa | pki --issue --lifetime 1825  --cacert ~/pki/cacerts/ca-cert.pem  --cakey ~/pki/private/ca-key.pem --dn "CN=91.149.253.28" --san 91.149.253.28  --flag serverAuth --flag ikeIntermediate --outform pem  > ~/pki/certs/server-cert.pem
    #cp -r ~/pki/* /etc/ipsec.d/
    print("Creating Certs")
    os.system('mkdir -p ./pki/cacerts')
    os.system('mkdir -p ./pki/certs')
    os.system('mkdir -p ./pki/private')
    os.system('chmod 700 ./pki')
    print("Creating CA Key")
    os.system('pki --gen --type rsa --size 4096 --outform pem > ./pki/private/ca-key.pem')
    os.system('pki --self --ca --lifetime 3650 --in ./pki/private/ca-key.pem --type rsa --dn "CN='+root_ca_name.strip()+'" --outform pem > ./pki/cacerts/ca-cert.pem')
    print("Creating Server Key")
    os.system('pki --gen --type rsa --size 4096 --outform pem > ./pki/private/server-key.pem')
    os.system('pki --pub --in ./pki/private/server-key.pem --type rsa | pki --issue --lifetime 1825  --cacert ./pki/cacerts/ca-cert.pem  --cakey ./pki/private/ca-key.pem --dn "CN='+server_dn_ip+'" --san '+server_dn_ip+'  --flag serverAuth --flag ikeIntermediate --outform pem  > ./pki/certs/server-cert.pem')
    print("Copyng keys into /etc")
    os.system('cp -r ./pki/* /etc/ipsec.d/')
    os.system('cat /etc/ipsec.d/cacerts/ca-cert.pem >yourCAroot.crt')
    print("It's your cert:")
    os.system('cat /etc/ipsec.d/cacerts/ca-cert.pem ')

    return True



if __name__ == '__main__':
    copy_source_files()
    server_ip=find_ip()
    #server_ip=str(input("Enter Server IP (autodiscovered by default) = "+ server_ip) or server_ip)
    print ("IP used in scripts: "+server_ip)
    clients_subnet=get_random_subnet()
    print ("Subnet for clients: "+clients_subnet)

    print("\n********\nUsers for VPN:")
    print("User  Password")
    un1=generate_username()
    pw1=generate_password()
    print(str(un1)+"    "+str(pw1))

    un2 = generate_username()
    pw2 = generate_password()
    print(str(un2) + "    " + str(pw2))

    un3 = generate_username()
    pw3 = generate_password()
    print(str(un3) + "    " + str(pw3))

    un4 = generate_username()
    pw4 = generate_password()
    print(str(un4) + "    " + str(pw4))

    un5 = generate_username()
    pw5 = generate_password()
    print(str(un5) + "    " + str(pw5)+"\n********\n")


    #input("Press a key to continue")
    ca_uniq = generate_password()
    root_ca_name_main="TimeOutSoft CA "+ca_uniq
    server_dn_ip_main = server_ip

    os_pre_operations(root_ca_name=root_ca_name_main, server_dn_ip=server_dn_ip_main)
    print ("Cert Data: " +root_ca_name_main + "   "+ server_dn_ip_main)
    print("Copying config files")
    copy_source_files()
    print("Starting changes")
    set_before_rules()
    set_sysctl_conf()
    set_ipsec_conf(srv_ip=server_ip, clnt_subn=clients_subnet)
    set_ipsec_secrets(un1, pw1, un2, pw2, un3, pw3, un4, pw4, un5, pw5)
    back_copy_source_files()