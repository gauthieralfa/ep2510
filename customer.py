
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

server_reference_path = "customer1/"
HOST = '127.0.0.1'  # The server's hostname or IP address
PORT = 63093     # The port used by the server
Name="customer1"
Service="provider1"
rng=random.randrange(1000)
RNG3=str(rng)


def get_keys():
    file1 = open("customer1/priv_o.txt", 'r')
    priv=file1.read()
    file1.close()
    file2 = open("customer1/pub_s.txt", 'r')
    pub=file2.read()
    file2.close()
    key=crypto.load_privatekey(crypto.FILETYPE_PEM, priv)
    return key


def generate_keys():
    key=crypto.PKey()
    key.generate_key(crypto.TYPE_RSA, 2048)
    file1 = open("customer1/priv_o.txt", 'wb')
    file1.write(crypto.dump_privatekey(crypto.FILETYPE_PEM,key))
    file1.close()
    file2 = open("customer1/pub_s.txt", 'wb')
    file2.write(crypto.dump_publickey(crypto.FILETYPE_PEM,key))
    file2.close()
    return key

def create_certificate(key):
    cert=crypto.X509()
    cert.set_pubkey(key)
    cert.get_subject().ST = "Sweden"
    cert.get_subject().L = "Stockholm"
    cert.get_subject().O = "customer1"
    cert.get_subject().OU = "SharingCarOwner"
    cert.set_serial_number(1000)
    cert.gmtime_adj_notBefore(0)
    cert.gmtime_adj_notAfter(10*365*24*60*60)
    cert.set_issuer(cert.get_subject())
    cert.get_subject().CN = "test"
    cert.sign(key,"sha256")
    file1=open("certs/cert_c",'wb')
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
    data = rsa.decrypt(base64.b64decode(message), prikey)
    return data

def reservation(ip, port):
    # Generation of the keys
    key=generate_keys() #Generation of the keys
    cert=create_certificate(key) #Creattion of the certificate for public keys

    ## Connection to the Service provider
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((ip, port)) #Connection with the Service Provider
    sock.send("reservation".encode())
    ACK=sock.recv(1024)

    ## Creation of the Signature of O,S,RNG1
    m=Name+Service+RNG3
    print("m is "+m)
    signature=sign(m,key)
    print("signature is "+str(signature))

    ## Creation of the encrypted message O,S,RNG1
    message=Name+"\n"+Service+"\n"+RNG3
    certificate_serviceprovider=get_certificate("cert_s")
    message_encrypted=encrypt(certificate_serviceprovider,message)
    sock.sendall(message_encrypted)
    ACK=sock.recv(1024)
    sock.sendall(signature)
    print("O,S,N3,Signature")

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

    #Check if RNG3 is still the right Nonce
    if RNG3==lines[3].rstrip():
        print("Success")
    else:
        print("FAIL")

    # Send of the Booking Information, and Id_Car
    BookingDetails="time=2h.location=KTH"
    signature=sign(Name+Service+BookingDetails,key)
    message=Name+"\n"+Service+"\n"+BookingDetails
    certificate_serviceprovider=get_certificate("cert_s")
    message_encrypted=encrypt(certificate_serviceprovider,message)
    sock.sendall(message_encrypted)
    ACK=sock.recv(1024)
    sock.sendall(signature)
    sock.close()



def recuperation(ip, port):
    key=get_keys()
    ## Connection to the Service provider
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((ip, port)) #Connection with the Service Provider
    sock.send("recuperation".encode())
    ACK=sock.recv(1024)
    sock.sendall("ok".encode())
    message_encrypted=sock.recv(1024)
    decrypted_message=decrypt(key,message_encrypted)
    #dec=str(decrypted_message)
    result=open(server_reference_path+"digitalkey.txt","wb")
    result.write(decrypted_message)
    result.close()


def open_the_car():
    sock2 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock2.connect(('127.0.0.1',63094))
    sock2.send("open".encode())
    ACK=sock2.recv(1024)
    result=open(server_reference_path+"digitalkey.txt","r")
    lines=result.readlines()
    result.close()
    message=lines[0]+lines[1].rstrip()
    sock2.send(message.encode())
    chall=sock2.recv(1024)
    result=open(server_reference_path+"digitalkey.txt","rb")
    lines=result.readlines()
    result.close()
    session_key=lines[2]
    f=Fernet(session_key)
    resp=f.encrypt(chall)
    sock2.send(resp)




if __name__ == "__main__":
    thread_list = []
    inp = input("Enter Text: ")
    if inp=="reservation":
        client_thread = threading.Thread(
            target=reservation, args=(HOST, PORT))
    elif inp=="recuperation":
        client_thread = threading.Thread(
            target=recuperation, args=(HOST, PORT))
    else:
        client_thread = threading.Thread(
            target=open_the_car)
    thread_list.append(client_thread)
    client_thread.start()

    waiting = time.time()
    [x.join() for x in thread_list]
    done = time.time()
    print ('DONE {}. Waiting for {} seconds'.format(done, done-waiting))
