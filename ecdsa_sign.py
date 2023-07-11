from Crypto.PublicKey import ECC
from Crypto.Signature import DSS
from Crypto.Hash import SHA256

def createPEM_ECDSA():
  key = ECC.generate(curve='P-256')
  with open('privkey_ecdsa.pem', 'w') as h:
    h.write(key.export_key(format='PEM'))
  key = key.public_key()
  with open('pubkey_ecdsa.pem', 'w') as h:
    h.write(key.export_key(format='PEM'))

def readPEM_ECC(pemfile):
  with open(pemfile, 'r') as h:
    key = ECC.import_key(h.read())
  return key

def ecdsa_sign(msg):
  privateKey = readPEM_ECC('privkey_ecdsa.pem')
  sha = SHA256.new(msg)
  signer = DSS.new(privateKey, 'fips-186-3')
  signature = signer.sign(sha)
  return signature

def ecdsa_verify(msg, signature):
  publicKey = readPEM_ECC('pubkey_ecdsa.pem')
  sha = SHA256.new(msg)
  verifier = DSS.new(publicKey, 'fips-186-3')
  try:
    verifier.verify(sha, signature)
    print('Authentic')
  except ValueError:
    print('Not Authentic')

def main():
  createPEM_ECDSA() # if you have key files, you don't need to run this line.
  msg = 'My name is minjae'
  signature = ecdsa_sign(msg.encode('utf-8'))
  ecdsa_verify(msg.encode('utf-8'), signature)

if __name__ == '__main__':
  main()