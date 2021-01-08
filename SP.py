import multiprocessing
import socket
import time
import threading
import os
import hashlib
import OpenSSL
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP

HOST = '127.0.0.1'  # Standard loopback interface address (localhost)
PORT = 63082    # Port to listen on (non-privileged ports are > 1023)
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
    file1=open("certs/cert_s.txt",'wb')
    file1.write(crypto.dump_certificate(crypto.FILETYPE_PEM, cert))
    file1.close()
    return cert

class server(object):

    def __init__(self, hostname, port):
        self.hostname = hostname
        self.port = port
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.bind((self.hostname, self.port))
        self.socket.listen()
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

    def receive_file(self,m):
        size=self.clientsocket.recv(1024)
        print(size)
        self.clientsocket.send("OK".encode())
        print("Thread",threading.get_ident(),":receiving file:",m)
        recv=self.clientsocket.recv(1024*1024)
        while (len(recv)!=int(size)):
            recv+=self.clientsocket.recv(1024*1024)
            print(recv)
            print(len(recv))
        file = open(server_reference_path+"m",'wb')
        file.write(recv)
        file.close()
        print("Thread",threading.get_ident(),":file received")
        #self.close()
        #return m

    def send_file(self,datas):
        print("Thread",threading.get_ident(),":sending file:",datas)
        self.clientsocket.send(datas.encode())
        print("Thread",threading.get_ident(),":file sent")
        #self.close()

    def run(self):

        time.sleep(10**-3)
        print("Thread",threading.get_ident(),"started")
        key=generate_keys() #Generation of the keys
        cert=create_certificate(key) #Creattion of the certificate for public keys
        print("Server ready") #SEVER IS NOW READY
        data=self.receive_file(m)
        result=open(server_reference_path+"m","r")
        lines=result.readlines()
        result.close()
        str2hash=lines[0].rstrip()+lines[1].rstrip()+lines[2].rstrip()
        hash=hashlib.md5(str2hash.encode()).hexdigest()
        print(hash)
        print("A DECRYPTER: "+lines[3])
        res=decrypt_public_key(lines[3],"owner1_public_key")
        if hash==res:
            valid="true"
        else :
            valid="false"
        self.send_file(valid)

server(HOST,PORT)
