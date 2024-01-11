#!/usr/bin/env python3

import dns.name
import dns.query
import dns.dnssec
import dns.message
import dns.resolver
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import base64

NAMSERVER = "127.0.0.1" 
DOMAIN = "bksec.com."
def encrypt_data(data):
    #Creating dicti
    enc_infos = {"IV":"", "enc_key":"","data":"","text_padded":""}
    enc_infos_return = {"IV":"", "enc_key":"","cipher_text":""}
    
    enc_key = get_random_bytes(32)
    enc_infos["enc_key"] = enc_key
    enc_infos_return["enc_key"] = enc_key

    enc_infos["data"] = data.encode()
    enc_infos["text_padded"] = enc_infos["data"] + (AES.block_size - (len(enc_infos["data"]) % AES.block_size)) * b'\x00'
    
    iv = get_random_bytes(16)
    enc_infos["IV"] = iv
    enc_infos_return["IV"] = iv
    cipher = AES.new(enc_infos["enc_key"], AES.MODE_CBC, iv)
    cipher_enc = cipher.encrypt(enc_infos["text_padded"])
    enc_infos_return["cipher_text"] = cipher_enc
    
    return enc_infos_return

def decrypt_data(data):
    cipher2 = AES.new(data["enc_key"], AES.MODE_CBC, data["IV"])
    clear_text = cipher2.decrypt(data["cipher_text"])
    return clear_text

def create_conf_file(data,filename):
    f = open(filename, "w")
    config_file = """
    [A]
    *.google.com=192.0.2.1
    thesprawl.org=192.0.2.2
    *.wordpress.*=192.0.2.3
    bksec.com = 192.23.23.23

[TXT]
    bksec.com = "PwCpTxt"
    pwd.bksec.com = "PwKey"
    iv.bksec.com = "PwIV"
    """

    print(data["cipher_text"], "\n")
    print(data["enc_key"], "\n")
    print(data["IV"], "\n")
    ##Replacing the 
    config_file= config_file.replace("PwCpTxt","w00t"+base64.b64encode(data["cipher_text"]).decode('utf-8')+"woot")
    config_file= config_file.replace("PwKey","w00d"+base64.b64encode(data["enc_key"]).decode('utf-8')+"wood")
    config_file= config_file.replace("PwIV","w00b"+base64.b64encode(data["IV"]).decode('utf-8')+"woob")
    #We're using eggs for finding the data's easily while writing the parser

    f.write(config_file)
    f.close()
    return True

def parse_data_from_config(file):
    
    data_from_config={"IV":"", "enc_key":"","cipher_text":""}
    f = open(file, "r")
    file_text = f.read()
    print(file_text + "\n")

    print(base64.b64decode(file_text[file_text.find("w00t")+4:file_text.find("woot")].strip()))
    print(base64.b64decode(file_text[file_text.find("w00d")+4:file_text.find("wood")].strip()))
    print(base64.b64decode(file_text[file_text.find("w00b")+4:file_text.find("woob")].strip()))
    data_from_config["IV"] = base64.b64decode(file_text[file_text.find("w00b")+4:file_text.find("woob")].strip())
    data_from_config["enc_key"] = base64.b64decode(file_text[file_text.find("w00d")+4:file_text.find("wood")].strip())
    data_from_config["cipher_text"] = base64.b64decode(file_text[file_text.find("w00t")+4:file_text.find("woot")].strip())
    print("\nINSIDE OF parse_data_from_config\n")
    print(type(base64.b64decode(file_text[file_text.find("w00b")+4:file_text.find("woob")].strip())),type(data_from_config["IV"]), type(data_from_config["enc_key"]), type(data_from_config["cipher_text"]))
    return data_from_config


def parse_data_from_dns_response():
    print("Parsing Data from DNS Response")
    data_from_dns={"IV":"", "enc_key":"","cipher_text":""}
    print(type(data_from_dns))

    #Create DNS Queries and get the Response from DNS for all subdomains
    #Getting Cipher Text from DNS TXT
    label = "*"
    request = dns.message.make_query(f'{label}.{DOMAIN}', dns.rdatatype.TXT, want_dnssec=True)
    response = dns.query.udp(request, NAMSERVER, port=53)
    response = str(response)
    response = response[response.find("w00t")+4:response.find("woot")]
    print(response + "\n")
    print("Type: ", type(base64.b64decode(response)), " Res: ", base64.b64decode(response))
    data_from_dns["cipher_text"] = base64.b64decode(response)


    #Getting IV from DNS TXT
    label = "iv"
    request = dns.message.make_query(f'{label}.{DOMAIN}', dns.rdatatype.TXT, want_dnssec=True)
    response = dns.query.udp(request, NAMSERVER, port=53)
    response = str(response)
    response = response[response.find("w00b")+4:response.find("woob")]
    print(response + "\n")
    print("Type: ", type(base64.b64decode(response)), " Res: ", base64.b64decode(response))
    data_from_dns["IV"] = base64.b64decode(response)

    #Getting Key from DNS TXT
    label = "pwd"
    request = dns.message.make_query(f'{label}.{DOMAIN}', dns.rdatatype.TXT, want_dnssec=True)
    response = dns.query.udp(request, NAMSERVER, port=53)
    response = str(response)
    response = response[response.find("w00d")+4:response.find("wood")]
    print(response + "\n")
    print("Type: ", type(base64.b64decode(response)), " Res: ", base64.b64decode(response))
    data_from_dns["enc_key"] = base64.b64decode(response)


    print(data_from_dns)
    return data_from_dns






def main():

     test = encrypt_data("Hacking is so cool!")
     print("\n",test)

     create_conf_file(test,"/home/user/Desktop/BKSec/config.ini")
     data = parse_data_from_config("/home/user/Desktop/BKSec/config.ini")
     print("\nDATA: \n")
     print(data["enc_key"])
     print("\nDecryption Result: \n")
     print(decrypt_data(data))
     data = parse_data_from_dns_response()
     print(decrypt_data(data))



if __name__ == '__main__':
    main()
