
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
Name="owner1"
Service="provider1"


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


RNG1=random.randrange(1000)
RNG1=str(RNG1)
m=Name+Service+RNG1

def encrypt_private_key(a_message, private_key):
    key_file = open(server_reference_path+'PrivateKeyOwner.pem', 'rb')
    key = RSA.importKey(key_file.read())
    encryptor = PKCS1_OAEP.new(key)
    encrypted_msg = encryptor.encrypt(a_message.encode())
    print("length de encrypted"+str(len(encrypted_msg)))
    return encrypted_msg

def registration(ip, port, message):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((ip, port))
    fichier = open(server_reference_path+"registration.txt", "a")
    fichier.write(Name)
    fichier.write("\n"+Service)
    fichier.write("\n"+RNG1)
    str2hash=Name+Service+RNG1
    hash=hashlib.md5(str2hash.encode()).hexdigest()
    c_o=encrypt_private_key(hash,key)
    print(c_o)
    fichier.write("\n"+str(c_o))
    fichier.close()
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
