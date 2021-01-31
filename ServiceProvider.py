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
PORT = 63093    # Port to listen on (non-privileged ports are > 1023)
server_reference_path = "keys/"



def generate_keys():
    key=crypto.PKey()
    key.generate_key(crypto.TYPE_RSA, 2048)
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

    def receive2(self,m):
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

    def receive(self):
        recv=self.clientsocket.recv(1024*1024)

        return recv

    def send_text(self,datas):
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
        #Reception of O,S,RNG1 and Signature
        message=self.receive()
        self.send_text("ok")
        signature=self.receive()

        #Certificate is owned from the beginning (public key of Owner)
        certificate_o=get_certificate("cert_o")

        #decryption of the message
        decrypted_message=decrypt(key,message)
        dec=str(decrypted_message)
        print("the message received is: "+dec)
        result=open(server_reference_path+"message_decrypted.txt","wb")
        result.write(decrypted_message)
        result.write(("\n"+str(signature)).encode())
        result.close()
        result=open(server_reference_path+"message_decrypted.txt","r")
        lines=result.readlines()
        result.close()

        #Verification of the signature
        print("vérification de la signature")
        m=lines[0].rstrip()+lines[1].rstrip()+lines[2].rstrip()
        print("m decrypted is "+m)
        res=verifsign(certificate_o,signature,m)

        #S,O,N2,N1 and signature sent
        Name="provider1"
        Owner="owner1"
        rng=random.randrange(1000)
        RNG2=str(rng)
        RNG1=lines[2].rstrip()
        m=Name+Owner+RNG2+RNG1
        print("m of signature is: "+m)
        signature2=sign(m,key)
        message=Name+"\n"+Owner+"\n"+RNG2+"\n"+RNG1
        print("S,O,N2,N1: "+message)
        message_encrypted=encrypt(certificate_o,message)
        self.send_object(message_encrypted)
        ACK=self.receive()
        self.send_object(signature2)
        print("S,O,N1,N2 encrypted and Signature sent")
        ACK=self.receive()
        print(str(ACK))

        #Receives BookingInformation and IdCar
        message=self.receive()
        self.send_text("ok")
        signature=self.receive()
        decrypted_message=decrypt(key,message)
        dec=str(decrypted_message)
        print("Booking Information and IdCar are: "+dec)
        result=open(server_reference_path+"message_decrypted.txt","wb")
        result.write(decrypted_message)
        result.write(("\n"+str(signature)).encode())
        result.close()
        result=open(server_reference_path+"message_decrypted.txt","r")
        lines=result.readlines()
        result.close()
        print("check of the signature")
        m=lines[0].rstrip()+lines[1].rstrip()+lines[2].rstrip()+lines[3].rstrip()
        res=verifsign(certificate_o,signature,m)
        BookingInformation=lines[2].rstrip()
        IdCar=lines[3].rstrip() #IdCar saved
        print("Booking Information saved: "+BookingInformation)
        print("Id Car saved: "+IdCar)
        message=self.receive()
        time.sleep(5)
        #print((message))
        return certificate_o
        self.close()

    def reservation(self):
        ##
        global session_key
        message=self.receive()
        self.send_text("ok")
        signature=self.receive()
        certificate_c=get_certificate("cert_c")
        decrypted_message=decrypt(key,message)
        dec=str(decrypted_message)
        print("C,S,N3 received: "+dec)
        result=open(server_reference_path+"message_decrypted.txt","wb")
        result.write(decrypted_message)
        result.write(("\n"+str(signature)).encode())

        result.close()
        result=open(server_reference_path+"message_decrypted.txt","r")
        lines=result.readlines()
        result.close()
        print("vérification de la signature...")
        m=lines[0].rstrip()+lines[1].rstrip()+lines[2].rstrip()
        print("m is "+m)

        res=verifsign(certificate_c,signature,m)

        Name="provider1"
        Customer="customer1"
        rng=random.randrange(1000)
        RNG4=str(rng)
        RNG3=lines[2].rstrip()
        m=Name+Customer+RNG4+RNG3
        #print("m of signature is: "+m)
        signature2=sign(m,key)
        message=Name+"\n"+Customer+"\n"+RNG4+"\n"+RNG3
        print("S,C,N4,N3 send: "+message)
        message_encrypted=encrypt(certificate_c,message)
        self.send_object(message_encrypted)
        ACK=self.receive()
        self.send_object(signature2)
        print("S,C,N4,N3 encrypted and Signature sent")
        ACK=self.receive()
        print(str(ACK))

        #Receives BookingInformation and IdCar
        message=self.receive()
        self.send_text("ok")
        signature=self.receive()
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
        m=lines[0].rstrip()+lines[1].rstrip()+lines[2].rstrip()
        print("signature data are "+m)
        res=verifsign(certificate_c,signature,m)
        BookingDetails=lines[2].rstrip()
        IdCar="206" #We assume it has searched it in the database after a match
        print("Booking Details are : "+BookingDetails)
        self.close()
        ts="1"
        te="120"
        m=BookingDetails+IdCar+ts+te
        print("Access Token to create and encrypted with: "+m)
        key_file=open("car1/keycar1.txt",'r')
        key_car=key_file.read()
        key_file.close()
        f = Fernet(key_car)
        access_token=f.encrypt(m.encode())
        print("Access Token: "+str(access_token))
        session_key=Fernet.generate_key()
        print("Session Key created: "+str(session_key))
        file=open(server_reference_path+"session_key.txt",'wb')
        file.write(session_key)
        file.close()
        file=open("service_provider/"+lines[0].rstrip(),'wt')
        file.write(IdCar)
        file.close()
        file=open("service_provider/"+lines[0].rstrip(),'ab')
        file.write(("\n".encode()+access_token))
        file.write(("\n".encode()+session_key))
        file.close()
        self.close()

    def send_session_key(self):
        name_owner=self.receive()
        print("Sent the session key to the Owner to get the o_check")
        file=open("service_provider/customer1",'r')
        lines=file.readlines()
        session_key=lines[2].rstrip()
        IdCar=lines[0].rstrip()
        #BookingDetails=lines[3].rstrip()
        certificate_o=get_certificate("cert_o")
        message=session_key+IdCar
        signature=sign(message,key)
        message=session_key+"\n"+IdCar
        message_encrypted=encrypt(certificate_o,message)
        self.send_object(message_encrypted)
        print("session and IdCar encrypted and signature sent")
        ACK=self.receive()
        self.send_object(signature)
        print("Remind: SESSION KEY IS "+session_key)

        #Receives o_check
        o_check_encrypted=self.receive()
        o_check=decrypt(key,o_check_encrypted).decode()
        print("o_check received decrypted is: "+o_check)
        file=open("service_provider/customer1",'a')
        file.write("\n"+o_check)
        file.close()


        #Send To the car
        sock2 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock2.connect(('127.0.0.1',63094))
        sock2.send("session_key".encode())
        ACK=sock2.recv(1024)
        key_file=open("car1/keycar1.txt",'r')
        key_car=key_file.read()
        key_file.close()
        f = Fernet(key_car)
        message=session_key+"\n"+o_check
        message_encrypted=f.encrypt(message.encode())
        sock2.send(message_encrypted)
        print("Session_key and o_check encrypted by keycar and sent to the car")
        ack=sock2.recv(1024)


    def send_to_customer(self):
        message=self.receive()
        certificate_c=get_certificate("cert_c")
        file=open("service_provider/customer1",'r')
        lines=file.readlines()
        session_key=lines[2].rstrip()
        access_token=lines[1].rstrip()
        o_check=lines[3]
        #print("Access token is: "+access_token)
        message=access_token+"\n"+o_check+"\n"+session_key
        encrypted_message=encrypt(certificate_c,message)
        print("Access Token, o_check and Session_key encrypted by keycar sent to the customer !")
        self.send_object(encrypted_message)




    def run(self):
        time.sleep(10**-3)
        print("Thread",threading.get_ident(),"started")
        step=self.receive()
        self.send_text("OK")
        if step=="registration".encode():
            self.registration()
        elif step=="reservation".encode():
            self.reservation()
            print(session_key)
        elif step=="session_key".encode():
            self.send_session_key()
        elif step=="reception".encode():
            self.send_to_customer()



key=generate_keys() #Generation of the keys
cert=create_certificate(key) #Creattion of the certificate for public keys
print("Keys generated ready") #SEVER IS NOW READY
server(HOST,PORT)
