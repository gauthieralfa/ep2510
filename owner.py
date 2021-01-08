
#!/usr/bin/env python3
import random
import socket
import base64
import rsa
import sys
import threading
import time
import hashlib
import os
from OpenSSL import crypto,SSL
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP

server_reference_path = "owner1/"
HOST = '127.0.0.1'  # The server's hostname or IP address
PORT = 63092     # The port used by the server


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
    file1=open("certs/cert_o",'wb')
    file1.write(crypto.dump_certificate(crypto.FILETYPE_PEM, cert))
    file1.close()
    return cert

def get_certificate(certif_file):
    file= open("certs/"+certif_file, "r")
    certificate_str = file.read()
    file.close()
    certificate=crypto.load_certificate(crypto.FILETYPE_PEM,certificate_str)
    #print("certificat is "+certificate_str)
    return certificate

def sign(message,key):
    signature=crypto.sign(key,message,"sha256")
    return signature

def verifsign(certificate,signature,data):
    verif=crypto.verify(certificate,signature,data,"sha256")
    return verif

def encrypt(certificat,message):
    pub = crypto.dump_publickey(crypto.FILETYPE_PEM, certificat.get_pubkey())
    pubkey = rsa.PublicKey.load_pkcs1_openssl_pem(pub)
    data = rsa.encrypt(message.encode(), pubkey)
    data = base64.b64encode(data)
    return data

def decrypt(key,message):
    pri = crypto.dump_privatekey(crypto.FILETYPE_ASN1, key)
    prikey = rsa.PrivateKey.load_pkcs1(pri, 'DER')
    data0 = rsa.decrypt(base64.b64decode(message), prikey)
    return data0

def registration(ip, port):
    key=generate_keys() #Generation of the keys
    cert=create_certificate(key) #Creattion of the certificate for public keys
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((ip, port)) #Connection with the Service Provider
    Name="owner1"
    Service="provider1"
    rng=random.randrange(1000)
    RNG1=str(rng)
    m=Name+Service+RNG1
    print("m is "+m)
    signature=sign(m,key)
    print("signature is "+str(signature))
    message=Name+"\n"+Service+"\n"+RNG1
    certificate_serviceprovider=get_certificate("cert_s")
    message_encrypted=encrypt(certificate_serviceprovider,message)

    fichier = open(server_reference_path+"registration.txt", "a")
    fichier.write(str(message_encrypted))
    fichier.write("\n"+str(signature))
    fichier.close()
    #lenght=os.path.getsize(server_reference_path+"registration.txt")
    #sock.send(str(lenght).encode())
    #ACK=sock.recv(1024)
    #with open(server_reference_path+"registration.txt", 'rb') as file_to_send:
    #    for data in file_to_send:
    #        sock.sendall(data)
    sock.sendall(message_encrypted)
    ACK=sock.recv(1024)
    sock.sendall(signature)
    print("O,S,N1,Signature")
    result = sock.recv(1024)
    print("we have received")
    print (result)
    sock.close()

if __name__ == "__main__":
    thread_list = []
    client_thread = threading.Thread(
        target=registration, args=(HOST, PORT))
    thread_list.append(client_thread)
    client_thread.start()

    waiting = time.time()
    [x.join() for x in thread_list]
    done = time.time()
    print ('DONE {}. Waiting for {} seconds'.format(done, done-waiting))
