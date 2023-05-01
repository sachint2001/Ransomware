from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import base64

with open('publicKey.pem', 'r') as f:
    public_key = RSA.import_key(f.read())

cipher = PKCS1_OAEP.new(public_key)
encrypted_text = cipher.encrypt("Hello World".encode('utf-8'))
encrypted_text_b64 = base64.b64encode(encrypted_text).decode('utf-8')

print("HELLO: ", encrypted_text_b64)