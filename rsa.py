from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA256

def createPEM():
  private_key = RSA.generate(1024)
  h = open('privatekey.pem', 'wb+')
  h.write(private_key.exportKey('PEM'))
  h.close()
  public_key = private_key.publickey()
  h = open('publickey.pem', 'wb')
  h.write(public_key.exportKey('PEM'))
  h.close()

def readPEM(pemfile):
  h = open(pemfile, 'r')
  key = RSA.importKey(h.read())
  h.close()
  return key

def rsa_enc(msg):
  public_key = readPEM('publickey.pem')
  cipher = PKCS1_OAEP.new(public_key)
  encdata = cipher.encrypt(msg)
  return encdata

def rsa_dec(encdata):
  private_key = readPEM('privatekey.pem')
  cipher = PKCS1_OAEP.new(private_key)
  decdata = cipher.decrypt(encdata)
  return decdata

def main():
  createPEM() # if you have key files, you don't need to run this line.
  msg = 'samsjang loves python'
  ciphered = rsa_enc(msg.encode('utf-8'))
  print(ciphered)
  deciphered = rsa_dec(ciphered)
  print(deciphered)

if __name__ == '__main__':
  main()