import base64
import os
from pathlib import Path
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, AES

directory = '../' # CHANGE THIS
print("current directory is: " + directory)
directory = os.getcwd() + '/files'

print("current directory is: " + directory)

def scanRecurse(baseDir):
    '''
    Scan a directory and return a list of all files
    return: list of files
    '''
    for entry in os.scandir(baseDir):
        if entry.is_file():
            yield entry
        else:
            yield from scanRecurse(entry.path)

def decrypt(dataFile):

    # save the decrypted data to file
    dataFile=str(dataFile)
    print("full file: " + dataFile)
    #[ fileName, fileExtension ] = dataFile.split('.l0v3')
    size=len(dataFile)
    fileName=dataFile[:size-8]
    # print("filename: " + fileName)
    # print("fileexte: " + fileExtension)
    print("full file: " + fileName)



includeExtension = ['.l0v3sh3'] # CHANGE THIS
for item in scanRecurse(directory): 
    filePath = Path(item)
    fileType = filePath.suffix.lower()

    if fileType in includeExtension:
        decrypt(filePath)
    continue