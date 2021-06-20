import multiprocessing
import socket
import time
import threading
import os
import random
import hashlib
import rsa
import base64
import jpysocket
from OpenSSL import crypto,SSL
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from cryptography.fernet import Fernet
from Crypto.Signature import PKCS1_v1_5
from datetime import datetime
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Hash import SHA512
import hmac

HOST = '192.168.66.56'  # Standard loopback interface address (localhost)
PORT = 50000    # Port to listen on (non-privileged ports are > 1023)
server_reference_path = "keys/"



def generate_keys():
    #USE FOR SIGNATURE WITH PYTHON
    file1 = open("all_keys/priv_sp.pem")
    priv_key=file1.read()
    private_key_sp_pem=crypto.load_privatekey(crypto.FILETYPE_PEM, priv_key)
    file1.close()

    #NEVER USE, Certificate is used instead of public key in python
    file2 = open("all_keys/pub_spPKCS1.pem")
    pub_key=file2.read()
    public_key=rsa.PublicKey.load_pkcs1(pub_key)
    file2.close()

    #USE FOR DECRYPT WITH PYTHON
    file3 = open("all_keys/priv_sp.txt","rb")
    priv_key=file3.read()
    private_key_sp=rsa.PrivateKey.load_pkcs1(priv_key,'DER')
    file3.close()

    return private_key_sp,public_key,private_key_sp_pem

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
    file= open("all_keys/"+certif_file, "r")
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
    #pri = crypto.dump_privatekey(crypto.FILETYPE_ASN1, key)
    #prikey = rsa.PrivateKey.load_pkcs1(pri, 'DER')
    data = rsa.decrypt(base64.b64decode(message), key)
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
        recv=self.clientsocket.recv(1024)

        return recv

    def send_text(self,datas):
        print("Thread",threading.get_ident(),":sending file:",datas)
        self.clientsocket.sendall(datas.encode())
        print("Thread",threading.get_ident(),":file sent")
        #self.close()


    def send_text_java(self,datas):
        print("Thread",threading.get_ident(),":sending text java:",datas)
        msg=jpysocket.jpyencode(datas)
        self.clientsocket.sendall(msg)
        print("Thread",threading.get_ident(),":sending msg java:",msg)
        #self.close()

    def send_object(self,datas):
        print("Thread",threading.get_ident(),":sending object")
        self.clientsocket.sendall(datas)
        print("Thread",threading.get_ident(),":object sent")
        #self.close()

    def registration(self):
        #Reception of Mauth (ID_uo, ID_sp, N_Mauth,Timestamp) and Sigma_Mauth
        print("REGISTRATION")
        message=self.receive()
        print("this is the message"+str(message))
        self.send_text_java("OK")
        sigma_Mauth64=self.receive()
        #Certificate is owned from the beginning (public key of Owner)
        certificate_customer=get_certificate("cert_customer")
        certificate_sp=get_certificate("cert_sp")

        #decryption of the message
        decrypted_message=decrypt(private_key_sp,message)
        dec=str(decrypted_message)
        print("the message received is: "+dec)
        result=open(server_reference_path+"message_decrypted.txt","wb")
        result.write(decrypted_message)
        result.write(("\n"+str(sigma_Mauth64)).encode())
        result.close()
        result=open(server_reference_path+"message_decrypted.txt","r")
        lines=result.readlines()
        result.close()

        #Verification of the signature
        print("vérification de la signature")
        #print("signature:"+str(signature))
        #print("signature2:"+signature.decode())
        Mauth=lines[0]+lines[1]+lines[2]+lines[3].rstrip()
        print("Mauth decrypted is :"+Mauth)
        print("decrypted_message.decode() is :"+decrypted_message.decode()+"\n")
        sigma_Mauth=base64.b64decode(sigma_Mauth64)
        #print("Voici le sigma_Mauth"+str(sigma_Mauth))
        print("Voici le sigma_Mauth64"+str(sigma_Mauth64)+"\n")
        res=verifsign(certificate_customer,sigma_Mauth,Mauth)

        #S,O,N2,N1 and signature sent
        #rng=random.randrange(1000)
        ID_uo=lines[0].rstrip()
        ID_sp=2;
        N_Mauth=lines[2].rstrip()
        N_Mauth_prime=int(N_Mauth)+1;
        dateTimeObj = datetime.now()
        TS_Mauth_prime = dateTimeObj.strftime("%d-%b-%Y (%H:%M:%S.%f)")
        Mauth_Prime=str(ID_uo)+"\n"+str(ID_sp)+"\n"+str(N_Mauth)+"\n"+str(N_Mauth_prime)+"\n"+TS_Mauth_prime+"\n"
        #Mauth_Prime64=base64.b64encode(Mauth_Prime)
        #m=Name+Owner+RNG2+RNG1
        print("Mauth_Prime is: "+Mauth_Prime+"\n")
        sigma_Mauth_prime=sign(Mauth_Prime,private_key_sp_pem)
        sigma_Mauth_prime64=base64.b64encode(sigma_Mauth_prime)
        print("sigma_Mauth_prime64 is: "+str(sigma_Mauth_prime64)+"\n")



        signature = hmac.new(certificate_customer, digestmod=hashlib.sha256).digest()
        print(signature)


        #message=Name+"\n"+Owner+"\n"+RNG2+"\n"+RNG1
        #print("S,O,N2,N1: "+message)
        Mauth_Prime_encrypted=encrypt(certificate_customer,Mauth_Prime+"\n"+str(sigma_Mauth_prime64))
        print("Mauth_Prime+Signature ENCRYPTED:"+Mauth_Prime_encrypted)
        #self.send_text_java(Mauth_Prime_encrypted.decode())

        size = len(Mauth_Prime_encrypted)
        print("File bytes:", size)

        self.clientsocket.sendall(size.to_bytes(4, byteorder='big')) #Taille des bytes
        ACK=self.receive()
        self.clientsocket.sendall(Mauth_Prime_encrypted) #Envoi de la signature en Byte

        ACK=self.receive()

        #self.send_text_java(sigma_Mauth_prime64.decode())
        size = len(sigma_Mauth_prime64)
        print("File bytes:", size)
        self.clientsocket.sendall(size.to_bytes(4, byteorder='big'))
        ACK=self.receive()
        self.clientsocket.sendall(sigma_Mauth_prime64)

        print("S,O,N1,N2 encrypted and Signature sent")
        ACK=self.receive()
        print(str(ACK))

        #Receives BookingInformation and IdCar
        CMBAvail=self.receive()
        self.send_text_java("ok")
        sigma_MBAvail64=self.receive()
        MBAvail=decrypt(private_key_sp,CMBAvail)
        MBAvail_str=str(MBAvail)
        result=open(server_reference_path+"MBAvail.txt","wb")
        result.write(MBAvail)
        result.write(("\n"+str(sigma_MBAvail64)).encode())
        result.close()
        result=open(server_reference_path+"MBAvail.txt","r")
        lines=result.readlines()
        result.close()
        print("check of the signature")
        MBAvail=lines[0]+lines[1]+lines[2]+lines[3]+lines[4].rstrip()
        MBAvail_test=lines[0].rstrip()+lines[1].rstrip()+lines[2].rstrip()+lines[3].rstrip()+lines[4].rstrip()
        print("MBavail is: "+MBAvail)
        print("MBavail is: "+MBAvail_test)


        sigma_MBAvail=base64.b64decode(sigma_MBAvail64)
        res=verifsign(certificate_customer,sigma_MBAvail,MBAvail)
        BookingInformation=lines[2].rstrip()
        ID_veh=lines[3].rstrip() #IdCar saved
        print("Booking Information saved: "+BookingInformation)
        print("Id Car saved: "+ID_veh)
        # FINISH ? message=self.receive()
        time.sleep(5)
        #print((message))
        return certificate_sp
        self.close()

    def reservation(self):
        ##
        ##global session_key

        #Reception of Mauth (ID_uc, ID_sp, N_Mauth,Timestamp) and Sigma_Mauth
        print("RESERVATION")
        message=self.receive()
        self.send_text_java("ok")
        sigma_Mauth64=self.receive()
        certificate_customer=get_certificate("cert_customer")

        #decryption of the message Mauth
        decrypted_message=decrypt(private_key_sp,message)
        dec=str(decrypted_message)
        print("C,S,N3 received: "+dec)
        result=open(server_reference_path+"message_decrypted.txt","wb")
        result.write(decrypted_message)
        result.write(("\n"+str(sigma_Mauth64)).encode())
        result.close()
        result=open(server_reference_path+"message_decrypted.txt","r")
        lines=result.readlines()
        result.close()

        #Verification of the Signature
        print("Checking the sigma_Mauth...\n")
        Mauth=lines[0]+lines[1]+lines[2]+lines[3].rstrip()
        print("Mauth decrypted is :"+Mauth)
        sigma_Mauth=base64.b64decode(sigma_Mauth64)
        res=verifsign(certificate_customer,sigma_Mauth,Mauth)

        #S,C,N2,N1 and Sigma_Mauth_Prime sent
        ID_uc=lines[0].rstrip()
        ID_sp=2;
        N_Mauth=lines[2].rstrip()
        N_Mauth_prime=int(N_Mauth)+1;
        dateTimeObj = datetime.now()
        TS_Mauth_prime = dateTimeObj.strftime("%d-%b-%Y (%H:%M:%S.%f)")
        Mauth_Prime=str(ID_uc)+"\n"+str(ID_sp)+"\n"+str(N_Mauth)+"\n"+str(N_Mauth_prime)+"\n"+TS_Mauth_prime+"\n"
        sigma_Mauth_prime=sign(Mauth_Prime,private_key_sp_pem)
        sigma_Mauth_prime64=base64.b64encode(sigma_Mauth_prime)
        Mauth_Prime_encrypted=encrypt(certificate_customer,Mauth_Prime)

        #Send of the encrypted message
        size = len(Mauth_Prime_encrypted)
        print("File bytes:", size)

        self.clientsocket.sendall(size.to_bytes(4, byteorder='big')) #Taille des bytes
        ACK=self.receive()
        self.clientsocket.sendall(Mauth_Prime_encrypted) #Envoi de la signature en Byte

        ACK=self.receive()

        #Send of the Sigma_Mauth_Prime64
        size = len(sigma_Mauth_prime64)
        print("File bytes:", size)
        self.clientsocket.sendall(size.to_bytes(4, byteorder='big'))
        ACK=self.receive()
        self.clientsocket.sendall(sigma_Mauth_prime64)

        print("S,C,N1,N2 and Sigma_Mauth_Prime sent")
        ACK=self.receive()
        print(str(ACK))

        #Receives BookingDetails and IdCar
        CMBReq=self.receive()
        self.send_text_java("ok")
        Sigma_MBReq64=self.receive()
        MBReq=decrypt(private_key_sp,CMBReq)
        MBReq_str=str(MBReq)
        result=open(server_reference_path+"MBReq.txt","wb")
        result.write(MBReq)
        result.write(("\n"+str(Sigma_MBReq64)).encode())
        result.close()
        result=open(server_reference_path+"MBReq.txt","r")
        lines=result.readlines()
        result.close()
        print("check of the signature")
        MBReq=lines[0]+lines[1]+lines[2]+lines[3]+lines[4].rstrip()
        print("MBReq is: "+MBReq)
        Sigma_MBReq=base64.b64decode(Sigma_MBReq64)
        res=verifsign(certificate_customer,Sigma_MBReq,MBReq)

        BookingDetails=lines[2].rstrip()
        IdCar="206\n" #We assume it has searched it in the database after a match
        print("Booking Details are : "+BookingDetails)
        self.close()
        ts="1\n"
        te="120\n"
        BD=IdCar+ts+te;
        dateTimeObj = datetime.now()
        TS_BD = dateTimeObj.strftime("%d-%b-%Y (%H:%M:%S.%f)")
        BD=BD+TS_BD;
        print("Access Token to create and encrypted with: "+BD)
        key_file=open("car1/keycar1.txt",'r')
        key_car=key_file.read()
        key_file.close()
        f = Fernet(key_car)
        AT=f.encrypt(BD.encode())
        print("Access Token: "+str(AT))
        session_key=Fernet.generate_key()
        #key=PBKDF2(str(session_key), "df1f2d3f4d77ac66e9c5a6c3d8f921b6", 1024, "sha256", 256)
        print("Session Key created: "+str(session_key))
        file=open(server_reference_path+"session_key.txt",'wb')
        file.write(session_key)
        file.close()
        file=open("service_provider/customer1",'wt')
        file.write(IdCar)
        file.close()
        file=open("service_provider/customer1",'ab')
        file.write((AT))
        file.write(("\n".encode()+session_key))
        file.close()
        self.close()

    def send_session_key(self):
        #name_owner=self.receive()
        print("Sent the session key to the Owner to get the o_check")
        file=open("service_provider/customer1",'r')
        lines=file.readlines()
        session_key=lines[2].rstrip()
        IdCar=lines[0].rstrip()
        #BookingDetails=lines[3].rstrip()
        certificate_o=get_certificate("cert_customer")
        MSes=session_key+"\n"+IdCar+"\n"

        Sigma_MSes=sign(MSes,private_key_sp_pem)
        Sigma_MSes64=base64.b64encode(Sigma_MSes)

        #message=session_key+"\n"+IdCar
        CMSes=encrypt(certificate_o,MSes)

        #Send of the encrypted message
        size = len(CMSes)
        print("File bytes:", size)

        self.clientsocket.sendall(size.to_bytes(4, byteorder='big')) #Taille des bytes
        ACK=self.receive()
        print("received: "+str(ACK))
        self.clientsocket.sendall(CMSes) #Envoi de la signature en Byte
        print("CMSes is: "+str(CMSes))

        ACK=self.receive()

        #Send of the Sigma_M_MSes
        size = len(Sigma_MSes64)
        print("File bytes:", size)
        self.clientsocket.sendall(size.to_bytes(4, byteorder='big'))
        ACK=self.receive()
        self.clientsocket.sendall(Sigma_MSes64)
        print("CMSes is: "+str(Sigma_MSes64))

        print("S,C,N1,N2 and Sigma_Mauth_Prime sent")
        ACK=self.receive()
        print(str(ACK))

        print("Remind: SESSION KEY IS "+session_key)

        #Receives o_check
        CO_check=self.receive()
        O_check=decrypt(private_key_sp,CO_check).decode()

        Sigma_Check=base64.b64decode(Sigma_Check64)
        res=verifsign(certificate_customer,Sigma_Check,O_check)
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
        print(step)
        print("registration".encode())
        self.send_text_java("OK")
        if step=="registration".encode():
            self.registration()
        elif step=="reservation".encode():
            self.reservation()
            #print(session_key)
        elif step=="session_key".encode():
            self.send_session_key()
        elif step=="reception".encode():
            self.send_to_customer()



private_key_sp,public_key, private_key_sp_pem=generate_keys() #Generation of the keys
#cert=create_certificate(key) #Creattion of the certificate for public keys
print("Keys generated ready") #SEVER IS NOW READY
server(HOST,PORT)
