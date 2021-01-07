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

def decrypt_public_key(encoded_encrypted_msg, public_key):
    f = open(server_reference_path+'PublicKeyOwner.pem', "rb")
    key = RSA.importKey(f.read())
    encryptor = PKCS1_OAEP.new(key)
    decoded_decrypted_msg = encryptor.decrypt(encoded_encrypted_msg)
    return decoded_decrypted_msg

class server(object):

    def __init__(self, hostname, port):
        self.hostname = hostname
        self.port = port
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.bind((self.hostname, self.port))
        self.socket.listen()
        print("Server ready")
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
