from OpenSSL import crypto,SSL
import hashlib
import rsa
import base64

from OpenSSL.crypto import TYPE_RSA, FILETYPE_PEM, FILETYPE_ASN1

Name="owner1"
Service="provider1"
RNG1="100"

str2hash=Name+Service+RNG1
hash=hashlib.md5(str2hash.encode()).hexdigest()
print("HASH is: "+hash)
# Generation of the Key
key=crypto.PKey()
key.generate_key(crypto.TYPE_RSA, 1024)
file1 = open("Priv.txt", 'wb')
file1.write(crypto.dump_privatekey(crypto.FILETYPE_PEM,key))
file1.close()
file1 = open("Pub.txt", 'wb')
file1.write(crypto.dump_publickey(crypto.FILETYPE_PEM,key))
file1.close()
plaintext="hello"
pub = crypto.dump_publickey(crypto.FILETYPE_PEM, key)
pri = crypto.dump_privatekey(crypto.FILETYPE_ASN1, key)
pubkey = rsa.PublicKey.load_pkcs1_openssl_pem(pub)
prikey = rsa.PrivateKey.load_pkcs1(pri, 'DER')
print(pubkey.save_pkcs1())
print(prikey.save_pkcs1())
data = rsa.encrypt("hello".encode(), pubkey)
data = base64.b64encode(data)
print(data)

data0 = rsa.decrypt(base64.b64decode(data), prikey)
print(data0)
