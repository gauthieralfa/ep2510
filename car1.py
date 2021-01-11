import multiprocessing
import socket
import time
import threading
import os
import random
import hashlib
import rsa
import base64
from OpenSSL import crypto,SSL
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from cryptography.fernet import Fernet

HOST = '127.0.0.1'  # Standard loopback interface address (localhost)
PORT = 63094    # Port to listen on (non-privileged ports are > 1023)
server_reference_path = "car1/"
key = Fernet.generate_key()
masterkey=Fernet.generate_key()
print(masterkey)
file=open(server_reference_path+"keycar1.txt",'wb')
file.write(key)
file.close()
file=open(server_reference_path+"masterkeycar1.txt",'wb')
file.write(masterkey)
file.close()
IdCar="206"

def generate_keys():
    key=crypto.PKey()
    key.generate_key(crypto.TYPE_RSA, 1024)
    file1 = open("car1/priv_s.txt", 'wb')
    file1.write(crypto.dump_privatekey(crypto.FILETYPE_PEM,key))
    file1.close()
    file2 = open("car1/pub_s.txt", 'wb')
    file2.write(crypto.dump_publickey(crypto.FILETYPE_PEM,key))
    file2.close()
    return key

def create_certificate(key):
    cert=crypto.X509()
    cert.set_pubkey(key)
    cert.get_subject().ST = "Sweden"
    cert.get_subject().L = "Stockholm"
    cert.get_subject().O = "Service Provider"
    cert.get_subject().OU = "SharingCar"
    cert.set_serial_number(1000)
    cert.gmtime_adj_notBefore(0)
    cert.gmtime_adj_notAfter(10*365*24*60*60)
    cert.set_issuer(cert.get_subject())
    cert.get_subject().CN = "test"
    cert.sign(key,"sha256")
    file1=open("certs/cert_s",'wb')
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


class server(object):

    def __init__(self, hostname, port):
        self.hostname = hostname
        self.port = port
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.bind((self.hostname, self.port))
        self.socket.listen()
        print("Car ready")
        while True:
            clientsocket, (ip,port) = self.socket.accept()
            newthread = ClientThread(ip ,port , clientsocket,self)
            newthread.start()


class ClientThread(threading.Thread):

    def __init__(self, ip, port, clientsocket,server):

        print("connection from",ip)
        self.ip = ip
        self.port = port
        self.clientsocket = clientsocket
        self.server = server
        threading.Thread.__init__(self)

    def close(self):

        self.clientsocket.close()
        print("Thread",threading.get_ident(),":connection from",self.ip,"ended\n")

    def receive_file2(self,m):
        size=self.clientsocket.recv(1024)
        self.clientsocket.send("OK".encode())
        print("Thread",threading.get_ident(),":receiving file:",m)
        recv=self.clientsocket.recv(1024*1024)
        while (len(recv)!=int(size)):
            recv+=self.clientsocket.recv(1024*1024)
        file = open(server_reference_path+"m",'wb')
        file.write(recv)
        file.close()
        print("Thread",threading.get_ident(),":file received")
        #self.close()
        #return m

    def receive_file(self):
        #size=self.clientsocket.recv(1024)
        #self.clientsocket.send("OK".encode())
        recv=self.clientsocket.recv(1024)
        print("Thread",threading.get_ident(),":receiving file:",recv.decode())
        #self.close()
        return recv

    def send_file(self,datas):
        print("Thread",threading.get_ident(),":sending file:",datas)
        self.clientsocket.send(datas.encode())
        print("Thread",threading.get_ident(),":file sent")
        #self.close()

    def send_object(self,datas):
        print("Thread",threading.get_ident(),":sending object")
        self.clientsocket.sendall(datas)
        print("Thread",threading.get_ident(),":object sent")
        #self.close()

    def run(self):
        time.sleep(10**-3)
        print("Thread",threading.get_ident(),"started")
        MAC=self.receive_file()
        self.send_file("OK ?")
        key_file=open("car1/keycar1.txt",'r')
        key_car=key_file.read()
        key_file.close()
        f = Fernet(key_car)
        MAC_received=f.decrypt(MAC)
        MAC=MAC_received.decode().splitlines()[1]
        print("mac is: "+MAC)
        session_key=MAC_received.splitlines()[0].decode()
        print("session key is :"+session_key)


        str2hash=session_key+IdCar
        print(str2hash)
        Masterkey=masterkey.decode()
        masterkey2=Fernet(Masterkey)
        str2hash_encrypted=masterkey2.encrypt(str2hash.encode())
        print("WLLH: "+str(str2hash_encrypted))
        print("stp encry : "+Masterkey)
        MAC2=hashlib.md5((str2hash_encrypted)).hexdigest()
        print("MAC2 is: "+MAC2)


 #SEVER IS NOW READY
server(HOST,PORT)
