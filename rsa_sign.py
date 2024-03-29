from Crypto.Signature import pkcs1_15
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

def rsa_sign(msg):
  private_key = readPEM('privatekey.pem')
  public_key = private_key.publickey()
  h = SHA256.new(msg)
  signature = pkcs1_15.new(private_key).sign(h)
  return public_key, signature

def rsa_verify(msg, public_key, signature):
  h = SHA256.new(msg)
  try:
    pkcs1_15.new(public_key).verify(h, signature)
    print('Authentic')
  except Exception as e:
    print(e)
    print('Not Authentic')

def main():
  createPEM() # if you have key files, you don't need to run this line.
  msg = 'My name is minjae'
  public_key, signature = rsa_sign(msg.encode('utf-8'))
  rsa_verify(msg.encode('utf-8'), public_key, signature)

if __name__ == '__main__':
  main()