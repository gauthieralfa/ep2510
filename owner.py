
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
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

server_reference_path = "owner1/"
HOST = '127.0.0.1'  # The server's hostname or IP address
PORT = 63093     # The port used by the server
Name="owner1"
Service="provider1"
rng=random.randrange(1000)
RNG1=str(rng)


def generate_keys():
    key=crypto.PKey()
    key.generate_key(crypto.TYPE_RSA, 2048)
    file1 = open("owner1/priv_o.txt", 'wb')
    file1.write(crypto.dump_privatekey(crypto.FILETYPE_PEM,key))
    file1.close()
    file2 = open("owner1/pub_s.txt", 'wb')
    file2.write(crypto.dump_publickey(crypto.FILETYPE_PEM,key))
    file2.close()
    return key

def get_keys():
    file1 = open("owner1/priv_o.txt", 'r')
    priv=file1.read()
    file1.close()
    file2 = open("owner1/pub_s.txt", 'r')
    pub=file2.read()
    file2.close()
    key=crypto.load_privatekey(crypto.FILETYPE_PEM, priv)
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

    # Generation of the keys
    key=generate_keys() #Generation of the keys
    cert=create_certificate(key) #Creattion of the certificate for public keys

    ## Connection to the Service provider
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((ip, port)) #Connection with the Service Provider
    sock.send("registration".encode())
    ACK=sock.recv(1024)

    ## Creation of the Signature of O,S,RNG1
    m=Name+Service+RNG1
    print("m is "+m)
    signature=sign(m,key)
    print("signature is "+str(signature))

    ## Creation of the encrypted message O,S,RNG1
    message=Name+"\n"+Service+"\n"+RNG1
    certificate_serviceprovider=get_certificate("cert_s")
    message_encrypted=encrypt(certificate_serviceprovider,message)
    #fichier = open(server_reference_path+"registration.txt", "a")
    #fichier.write(str(message_encrypted))
    #fichier.write("\n"+str(signature))
    #fichier.close()
    #lenght=os.path.getsize(server_reference_path+"registration.txt")
    #sock.send(str(lenght).encode())
    #ACK=sock.recv(1024)
    #with open(server_reference_path+"registration.txt", 'rb') as file_to_send:
    #    for data in file_to_send:
    #        sock.sendall(data)

    ## Send of the encrypted message and signature
    sock.sendall(message_encrypted)
    ACK=sock.recv(1024)
    sock.sendall(signature)
    print("O,S,N1,Signature")

    ## Receives the response
    message=sock.recv(1024)
    sock.sendall("ok".encode())
    signature2=sock.recv(1024)

    ## Decrypt and stock in a file text
    decrypted_message=decrypt(key,message)
    dec=str(decrypted_message)
    result=open(server_reference_path+"message_decrypted.txt","wb")
    result.write(decrypted_message)
    result.write(("\n"+str(signature)).encode())
    result.close()

    #Read the file text
    result=open(server_reference_path+"message_decrypted.txt","r")
    lines=result.readlines()
    result.close()

    #Check the signature with the message decrypted
    print("vérification de la signature")
    m=lines[0].rstrip()+lines[1].rstrip()+lines[2].rstrip()+lines[3].rstrip()
    print("m of signature is: "+m)
    res=verifsign(certificate_serviceprovider,signature2,m)
    sock.sendall("OK".encode())

    #Check if RNG1 is still the right Nonce
    if RNG1==lines[3].rstrip():
        print("Success")
    else:
        print("FAIL")

    # Send of the Booking Information, and Id_Car
    BookingInformation="price=100.time=2h.location=KTH"
    IdCar="206"
    signature=sign(Name+Service+BookingInformation+IdCar,key)
    message=Name+"\n"+Service+"\n"+BookingInformation+"\n"+IdCar
    certificate_serviceprovider=get_certificate("cert_s")
    message_encrypted=encrypt(certificate_serviceprovider,message)
    sock.sendall(message_encrypted)
    ACK=sock.recv(1024)
    sock.sendall(signature)
    sock.close()

def receives_session_key(ip,port):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((ip, port)) #Connection with the Service Provider
    sock.send("session_key".encode())
    ACK=sock.recv(1024)
    sock.send(Name.encode())

    message=sock.recv(1024)
    sock.sendall("ok".encode())
    signature=sock.recv(1024)

    key=get_keys()
    decrypted_message=decrypt(key,message)
    dec=str(decrypted_message)
    result=open(server_reference_path+"session_key_decrypted.txt","wb")
    result.write(decrypted_message)
    result.write(("\n"+str(signature)).encode())
    result.close()

    #Read the file text
    result=open(server_reference_path+"session_key_decrypted.txt","r")
    lines=result.readlines()
    result.close()

    #Check the signature with the message decrypted
    certificate_serviceprovider=get_certificate("cert_s")
    print("vérification de la signature")
    m=lines[0].rstrip()+lines[1].rstrip()
    print("m of signature is: "+m)
    res=verifsign(certificate_serviceprovider,signature,m)
    session_key=lines[0].rstrip()
    print("session key is: "+session_key)
    IdCar=lines[1].rstrip()

    #Creation of the MAC
    str2hash=session_key+IdCar
    print("str2hash: "+str(str2hash.encode()))
    file=open("car1/masterkeycar1.txt",'rb')
    masterkey=file.read()

    cipher = Cipher(algorithms.AES(masterkey), modes.ECB())
    encryptor = cipher.encryptor()
    str2hash_encrypted = encryptor.update(str2hash.encode())

    MAC=hashlib.sha256((str2hash_encrypted)).hexdigest()
    print("MAC is: "+MAC)

    #Send to the SP
    MAC_encrypted=encrypt(certificate_serviceprovider,MAC)
    sock.sendall(MAC_encrypted)
    sock.close()


if __name__ == "__main__":
    thread_list = []
    inp = input("Enter Text: ")
    if inp=="registration":
        client_thread = threading.Thread(
            target=registration, args=(HOST, PORT))
    else :
        client_thread = threading.Thread(
            target=receives_session_key, args=(HOST, PORT))
    thread_list.append(client_thread)
    client_thread.start()

    waiting = time.time()
    [x.join() for x in thread_list]
    done = time.time()
    print ('DONE {}. Waiting for {} seconds'.format(done, done-waiting))
