from OpenSSL import crypto,SSL
import hashlib
import rsa
import base64

from OpenSSL.crypto import TYPE_RSA, FILETYPE_PEM, FILETYPE_ASN1, X509

#PACKET TO SEND
Name="owner1"
Service="provider1"
RNG1="100"
str2hash=Name+Service+RNG1

#HASH of the MESSAGE (PAS A UTILISER NORMALEMENT)
hash=hashlib.md5(str2hash.encode()).hexdigest()
print("HASH is: "+hash)
##End Of the HASH

# Generation of the Key
key=crypto.PKey()
key.generate_key(crypto.TYPE_RSA, 1024)
file1 = open("Priv.txt", 'wb')
file1.write(crypto.dump_privatekey(crypto.FILETYPE_PEM,key))
file1.close()
file2 = open("Pub.txt", 'wb')
file2.write(crypto.dump_publickey(crypto.FILETYPE_PEM,key))
file2.close()

#SIGNATURE DU MESSAGE CRÉÉ et HASHE EN SHA256
sign=crypto.sign(key,str2hash,"sha256")

#CREATION DU CERTIFICAT
cert=crypto.X509()
cert.set_pubkey(key)
cert.get_subject().ST = "Minnesota"
cert.get_subject().L = "Minnetonka"
cert.get_subject().O = "my company"
cert.get_subject().OU = "my organization"
cert.set_serial_number(1000)
cert.gmtime_adj_notBefore(0)
cert.gmtime_adj_notAfter(10*365*24*60*60)
cert.set_issuer(cert.get_subject())
cert.get_subject().CN = "test"
cert.sign(key,"sha1")
file1=open("cert.txt",'wb')
file1.write(crypto.dump_certificate(crypto.FILETYPE_PEM, cert))
file1.close()

#RECUPERATION DU CERTIFICAT !
file= open("cert.txt", "r")
certificate = file.read()
file.close()
print(certificate)
certificat=crypto.load_certificate(crypto.FILETYPE_PEM,certificate)

##Verifiation de la SIGNATURE :
verif=crypto.verify(certificat,sign,str2hash,"sha256")
print(verif)

##encryption
pub = crypto.dump_publickey(crypto.FILETYPE_PEM, certificat.get_pubkey())
pubkey = rsa.PublicKey.load_pkcs1_openssl_pem(pub)
data = rsa.encrypt("hello".encode(), pubkey)
data = base64.b64encode(data)
print(data)
pri = crypto.dump_privatekey(crypto.FILETYPE_ASN1, key)
prikey = rsa.PrivateKey.load_pkcs1(pri, 'DER')
data0 = rsa.decrypt(base64.b64decode(data), prikey)
print("OUI!: "+str(data0))
