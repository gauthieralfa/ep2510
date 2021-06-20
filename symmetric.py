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
from Crypto.Cipher import AES
from Crypto.Cipher import PKCS1_OAEP
from cryptography.fernet import Fernet
from Crypto.Signature import PKCS1_v1_5
from datetime import datetime
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Hash import SHA512
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from Crypto.Random import get_random_bytes
import hmac

masterkey64 =b'HEaV63ebUEAjib07VBqK3/HRq0q/u4y1mLNULYzZgI0='
salt=get_random_bytes(16)
print("salt: "+str(base64.b64encode(salt)));

salut="stockholm+2h+kth+02-05june"
salut=salut.encode();
print("salt: "+str(base64.b64encode(salut)));

keys=PBKDF2(masterkey64,salut,64,count=1000)
key1=keys[:32]
print(str(key1))
key = base64.b64encode(key1)
print(str(key))





#HMAC VALUE WITH STRING NOT BYTES !
#masterkey = base64.b64decode(masterkey64)
#my="test"
#my=my.encode()
#h = hmac.new( masterkey, my, hashlib.sha256 )
#print(h.hexdigest())


#print(masterkey)
#cipher = Cipher(algorithms.AES(masterkey), modes.ECB())
#encryptor = cipher.encryptor()

#str2hash_encrypted = encryptor.update(str2hash.encode())
#str2hash_encrypted64=base64.b64encode(str2hash_encrypted)
#print(str2hash_encrypted64)
