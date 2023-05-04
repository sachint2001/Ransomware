from flask import Flask, jsonify, request
import base64
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, AES
  
app = Flask(__name__)
  
# to get the public key of the server
@app.route('/public-key', methods = ['GET'])
def home():
    with open('publicKey.pem', 'rb') as f:
        public_key = f.read()
    public_key_utf_8 = public_key.decode('utf-8')
    return jsonify({'publicKey': public_key_utf_8})
  
# to decrypt the private key of the client
@app.route('/decrypt', methods = ['POST'])
def disp():
    data = request.get_json()
    private_key_enc = data['private_key_enc']

    with open('privateKey.pem', 'rb') as f:
        private_key = RSA.import_key(f.read())

    cipher = PKCS1_OAEP.new(private_key)
    ciphertext = base64.b64decode(private_key_enc)
    decrypted_chunks = []
    for i in range(0, len(ciphertext), 256):
        chunk = ciphertext[i:i+256]
        decrypted_chunk = cipher.decrypt(chunk)
        decrypted_chunks.append(decrypted_chunk)
    client_private_key_str = b''.join(decrypted_chunks)

    return jsonify({'private_key': client_private_key_str.decode()})

  
if __name__ == '__main__':
    app.run(debug = True)