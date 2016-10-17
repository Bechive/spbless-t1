import os

#Required PyCytro libraries...
from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_PSS
from Crypto.Hash import SHA512

#Private Key Filename
FN_PRIVATE_KEY = "private_key.pem"

def sign_file(f):
    #0. Get private key from local file
    private_key = open(FN_PRIVATE_KEY, "rb").read()

    #1. Setup RSA stuff
    #   Create a new RSA key instance with the imported
    #   or generated private key
    rsa_private_key = RSA.importKey(private_key)

    #2. Setup PKCS1 signature stuff
    #   Digital Signature with private key
    #   A PKCS1_PSS object is created
    signer = PKCS1_PSS.new(rsa_private_key)

    #3. Make signature of the data (hash first)
    #   Hash the data to size of 512
    h = SHA512.new(f)
    #   Sign the hash of the message
    #   (which takes the SHA512 object rather than its digest)
    signature = signer.sign(h)

    #4. Signed data => signature + data
    #   Prefix digital/RSA signature to the data
    #   Which 'Alice' sends to 'Bob' (or master 'sends' to bot)
    return signature + f


if __name__ == "__main__":
    fn = input("Which file in pastebot.net should be signed? ")
    if not os.path.exists(os.path.join("pastebot.net", fn)):
        print("The given file doesn't exist on pastebot.net")
        os.exit(1)
    f = open(os.path.join("pastebot.net", fn), "rb").read()
    signed_f = sign_file(f)
    signed_fn = os.path.join("pastebot.net", fn + ".signed")
    out = open(signed_fn, "wb")
    out.write(signed_f)
    out.close()
    print("Signed file written to", signed_fn)
