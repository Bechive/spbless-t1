import os

#Required PyCytro libraries...
from Crypto.Cipher import AES
from Crypto.Util import Counter
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto import Random

#Private Key Filename
FN_PRIVATE_KEY = "private_key.pem"

def decrypt_valuables(f):
    #0. Get private key from local file
    private_key = open(FN_PRIVATE_KEY, "rb").read()

    #1. Setup private RSA key stuff
    #   1.1 Create a new RSA key instance with the imported
    #   private key
    rsa_private_key = RSA.importKey(private_key)
    
    #   1.2 Find the size of the RSA/PKCS1 cipher text
    #   (It should be 512, or 4096 bits)
    pksc1_length = int((rsa_private_key.size()+1)*0.125)

    #2. Split up the received data 'f' to retrieve the various
    #   blocks of data we need to use in the decryption process...

    #   PKCS1 ciphertext 
    #   - The first set of bytes til the length PKCS1 ciphertext
    pkcs1_ciphertext = f[:pksc1_length]
    #   IV
    #   - The next 8 bytes
    iv = f[pksc1_length:pksc1_length+8]
    #   AES Ciphertext
    #   - Arbitrary length, AES ciphertext are the remaining bytes
    aes_ciphertext = f[pksc1_length+8:]

    #3. Decrypt the PKCS1 ciphertext with RSA private key
    #   to recover the symmetric key within...
    pkcs1_cipher = PKCS1_OAEP.new(rsa_private_key)
    symmetric_key = pkcs1_cipher.decrypt(pkcs1_ciphertext)

    #4. Decrypt the AES ciphertext to recover encrypted data
    #   now that we have got the symmetric key

    #   4.1 Setup
    #   Instantiate a 128bit counter object for CTR mode of operation.
    #   (64bits of counter, 64bits of prefix)
    counter = Counter.new(64, prefix=iv)
    #   Create a new AES/CTR cipher instance
    aes_cipher = AES.new(symmetric_key, AES.MODE_CTR, counter=counter)

    #   4.2 Decrypt AES ciphertext...
    decoded_text = aes_cipher.decrypt(aes_ciphertext)

    #5. The master now views the data, as per program specification...
    print(decoded_text)


if __name__ == "__main__":
    fn = input("Which file in pastebot.net does the botnet master want to view? ")
    if not os.path.exists(os.path.join("pastebot.net", fn)):
        print("The given file doesn't exist on pastebot.net")
        os.exit(1)
    f = open(os.path.join("pastebot.net", fn), "rb").read()
    decrypt_valuables(f)
