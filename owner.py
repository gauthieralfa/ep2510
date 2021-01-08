
#!/usr/bin/env python3
import random
import socket
import base64
import sys
import threading
import time
import hashlib
import os
import openSSL
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP

server_reference_path = "keys/"
HOST = '127.0.0.1'  # The server's hostname or IP address
PORT = 63082     # The port used by the server


def generate_keys():
    key=crypto.PKey()
    key.generate_key(crypto.TYPE_RSA, 1024)
    file1 = open("owner1/priv_o.txt", 'wb')
    file1.write(crypto.dump_privatekey(crypto.FILETYPE_PEM,key))
    file1.close()
    file2 = open("owner1/pub_s.txt", 'wb')
    file2.write(crypto.dump_publickey(crypto.FILETYPE_PEM,key))
    file2.close()
    return key

def create_certificate(key):
    cert=crypto.X509()
    cert.set_pubkey(key)
    cert.get_subject().ST = "Sweden"
    cert.get_subject().L = "Stockholm"
    cert.get_subject().O = "owner1"
    cert.get_subject().OU = "SharingCarOwner"
    cert.set_serial_number(1000)
    cert.gmtime_adj_notBefore(0)
    cert.gmtime_adj_notAfter(10*365*24*60*60)
    cert.set_issuer(cert.get_subject())
    cert.get_subject().CN = "test"
    cert.sign(key,"sha256")
    file1=open("certs/cert_o.txt",'wb')
    file1.write(crypto.dump_certificate(crypto.FILETYPE_PEM, cert))
    file1.close()
    return cert

def get_certificate(certif_file):
    file= open("certs/"+certif_file, "r")
    certificate_str = file.read()
    file.close()
    certificate=crypto.load_certificate(crypto.FILETYPE_PEM,certificate_str)
    return certificate

def sign(message,key):
    signature=crypto.sign(key,message,"sha256")
    return signature

def encrypt(certificat,message):
    pub = crypto.dump_publickey(crypto.FILETYPE_PEM, certificat.get_pubkey())
    pubkey = rsa.PublicKey.load_pkcs1_openssl_pem(pub)
    data = rsa.encrypt(message.encode(), pubkey)
    data = base64.b64encode(data)
    return data

def decrypt():

    return data


# Key Generation
key = RSA.generate(1024)
file1 = open(server_reference_path+'PrivateKeyOwner.pem', 'wb')
file1.write(key.exportKey('PEM'))
file1.close()
pubkey=key.publickey()
f = open(server_reference_path+'PublicKeyOwner.pem', "wb")
f.write(pubkey.exportKey('PEM'))
f.close()
# END Key Generation

def registration(ip, port, message):
    key=generate_keys() #Generation of the keys
    cert=create_certificate(key) #Creattion of the certificate for public keys
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((ip, port)) #Connection with the Service Provider
    Name="owner1"
    Service="provider1"
    RNG1=str(random.randrange(1000))
    m=Name+Service+RNG1
    signature=sign(m,key)
    message=m+signature
    message_encrypted=encrypt(cert,message)
    fichier = open(server_reference_path+"registration.txt", "a")
    fichier.write(message)
    fichier.close()
    certificate=get_certificate("cert_s")

    lenght=os.path.getsize(server_reference_path+"registration.txt")
    print(lenght)
    sock.send(str(lenght).encode())
    ACK=sock.recv(1024)
    with open(server_reference_path+"registration.txt", 'rb') as file_to_send:
        for data in file_to_send:
            sock.sendall(data)
    print("O,S,N1,C_O sent")
    result = sock.recv(1024)
    print("we have received")
    print (result)
    sock.close()

if __name__ == "__main__":
    thread_list = []
    client_thread = threading.Thread(
        target=registration, args=(HOST, PORT, m))
    thread_list.append(client_thread)
    client_thread.start()

    waiting = time.time()
    [x.join() for x in thread_list]
    done = time.time()
    print ('DONE {}. Waiting for {} seconds'.format(done, done-waiting))
