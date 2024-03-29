from Crypto.Cipher import DES3
from Crypto.Hash import SHA256

class MyDES():
  def __init__(self, keytext, ivtext):
    hash = SHA256.new()
    hash.update(keytext.encode('utf-8'))
    key = hash.digest()
    self.key = key[:24]
    hash.update(ivtext.encode('utf-8'))
    iv = hash.digest()
    self.iv = iv[:8]

  def enc(self, plaintext):
    plaintext = make8String(plaintext)
    des3 = DES3.new(self.key, DES3.MODE_CBC, self.iv)
    encmsg = des3.encrypt(plaintext.encode())
    return encmsg
  
  def dec(self, ciphertext):
    des3 = DES3.new(self.key, DES3.MODE_CBC, self.iv)
    decmsg = des3.decrypt(ciphertext)
    return decmsg

def make8String(msg):
  msglen = len(msg)
  filler = ''
  if msglen % 8 != 0:
    filler = '0'*(8-msglen%8)
  msg += filler
  return msg

def main():
  keytext = 'samsjang'
  ivtext = '1234'
  msg = 'python3xab'
  myCipher = MyDES(keytext, ivtext)
  ciphered = myCipher.enc(msg)
  deciphered = myCipher.dec(ciphered)
  print('ORIGINAL:\t%s' % msg)
  print('CIPHERED:\t%s' % ciphered)
  print('DECIPHERED:\t%s' % deciphered.decode())

if __name__ == '__main__':
  main()