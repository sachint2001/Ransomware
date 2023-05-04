from Crypto.PublicKey import RSA

key = RSA.generate(2048)
privateKey = key.export_key()
publicKey = key.publickey().export_key()

# save private key to file
with open('privateKey.pem', 'wb') as f:
    f.write(privateKey)

# save public key to file
with open('publicKey.pem', 'wb') as f:
    f.write(publicKey)

print('Private key saved to privateKey.pem')
print('Public key saved to publicKey.pem')
print('Done')