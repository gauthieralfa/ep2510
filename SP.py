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

HOST = '127.0.0.1'  # Standard loopback interface address (localhost)
PORT = 63093    # Port to listen on (non-privileged ports are > 1023)
server_reference_path = "keys/"
m=""


def generate_keys():
    key=crypto.PKey()
    key.generate_key(crypto.TYPE_RSA, 1024)
    file1 = open("service_provider/priv_s.txt", 'wb')
    file1.write(crypto.dump_privatekey(crypto.FILETYPE_PEM,key))
    file1.close()
    file2 = open("service_provider/pub_s.txt", 'wb')
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
        print("Service provider ready")
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
        #print("Thread",threading.get_ident(),":receiving file:",m)
        recv=self.clientsocket.recv(1024*1024)
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

    def registration(self):
        message=self.receive_file()
        self.send_file("ok")
        signature=self.receive_file()
        certificate_o=get_certificate("cert_o")
        decrypted_message=decrypt(key,message)
        dec=str(decrypted_message)
        print("the decrypted message is"+dec)
        result=open(server_reference_path+"message_decrypted.txt","wb")
        result.write(decrypted_message)
        result.write(("\n"+str(signature)).encode())
        #lines=result.readlines()
        result.close()
        result=open(server_reference_path+"message_decrypted.txt","r")
        lines=result.readlines()
        result.close()
        print("vérification de la signature")
        m=lines[0].rstrip()+lines[1].rstrip()+lines[2].rstrip()
        print("m is "+m)
        #print("signature is "+lines[3])
        res=verifsign(certificate_o,signature,m)
        #res=decrypt_public_key(lines[3],"owner1_public_key")
        #if hash==res:
        #    valid="true"
        #else :
        #    valid="false"
        Name="provider1"
        Owner="owner1"
        rng=random.randrange(1000)
        RNG2=str(rng)
        RNG1=lines[2].rstrip()
        m=Name+Owner+RNG1+RNG2
        print("m of signature is: "+m)
        signature2=sign(m,key)
        message=Name+"\n"+Owner+"\n"+RNG1+"\n"+RNG2
        message_encrypted=encrypt(certificate_o,message)
        self.send_object(message_encrypted)
        ACK=self.receive_file()
        self.send_object(signature2)
        print("S,O,N1,N2,Signature")
        ACK=self.receive_file()
        print(str(ACK))

        #Receives BookingInformation and IdCar
        message=self.receive_file()
        self.send_file("ok")
        signature=self.receive_file()
        decrypted_message=decrypt(key,message)
        dec=str(decrypted_message)
        print("the decrypted message is"+dec)
        result=open(server_reference_path+"message_decrypted.txt","wb")
        result.write(decrypted_message)
        result.write(("\n"+str(signature)).encode())
        result.close()
        result=open(server_reference_path+"message_decrypted.txt","r")
        lines=result.readlines()
        result.close()
        print("vérification de la signature")
        m=lines[0].rstrip()+lines[1].rstrip()+lines[2].rstrip()+lines[3].rstrip()
        res=verifsign(certificate_o,signature,m)
        BookingInformation=lines[2].rstrip()
        IdCar=lines[3].rstrip()
        print("Booking Information are : "+BookingInformation)
        self.close()


    def run(self):
        time.sleep(10**-3)
        print("Thread",threading.get_ident(),"started")
        self.registration()



key=generate_keys() #Generation of the keys
cert=create_certificate(key) #Creattion of the certificate for public keys
print("Keys generated ready") #SEVER IS NOW READY
server(HOST,PORT)
