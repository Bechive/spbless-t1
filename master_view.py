import os

#Import for RSA-AES Hybrid Encryption
from Crypto.Cipher import AES
from Crypto.Util import Counter
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP

from Crypto import Random

FN_PRIVATE_KEY = "private_key.pem"

def decrypt_valuables(f):
    # TODO: For Part 2, you'll need to decrypt the contents of this file
    # The existing scheme uploads in plaintext
#################################################
#    private_key_text = """-----BEGIN RSA PRIVATE KEY-----
#MIIEowIBAAKCAQEApIxHCL6eEHrpH9fkwHnm+wgSmqQ3TCUo54doPGMjagDH933K
#eNtFbRepEJ8BvhscJxFKSuBaCWw6DymiYbPTB2uffJOzdfGS4N3ob5CP6efjiZ1u
#VE7qli4Ajt5huBXJq7Y742Px/qpxg6T3lQeJOM01eIbhF5vrtSu1mNhdZ4pbDH+q
#VZMbo60KPdcnaoG9Kxuz5aLcqy2MeaDVBeeWiSNiDcebkJLzyc34faAwOoPEYIlX
#jU6TQSjnfj+zkEkSsGE0MB4ockYGB0YTXwR0Y6lZJ7Ayk+vtjOlDeZdEqcpdkt3d
#CrKMCN4v19ppg2pHZuYiBfM7K3BNlT3RsMr+QQIDAQABAoIBAGPQG764MhV5GTSR
#t1byGySnTvGzLz/nQpq/ToFi+bZxZts/2LPa/pAgTBOjAGGa/EbOfCxTTwpsNgPA
#k5mEhTv5ErN0vOWMdjYlJbuXC1Utrp5peuV1QWN74CbJyqjpvn2Ee2uB0udR6K2c
#QfqKqbhk8kx8NMoncKFjNDLU/EOzdlze3pbnvsQHnS3U7gKMV5FwfwFiDWJtQhXk
#dP+KEYrcoGVWqROyNSAl5xal7kq85yMJ6QqpsT/NYJAxSGp9lKU8hI0R5Lzuen7d
#ngvU4wYcu3729dfsYE4mV/XXrS2GVv2MFKBMukSxrCTlON+623CX4xGvI7vitj1T
#lATbfYECgYEAyNrqPc2QdQs7mNBfZx5lQD1t4W5WG67iDuGJleHItALYNg7Z2gqC
#IYehs0DmYQiYRcuaAdohGgjOJsRucLG4vADtD1Ct0EIVnl3iNsPSTG2qLADO3Sz8
#cj6eTZsbhTLKyow8swp+rL4f41TG5wuoe0yr8eUk0Gk/EuK2t3Y9N8kCgYEA0bmE
#Cl4PhOr1MIhpDpfnNLqgGlh8Zue/l+YfV4jKYJ5w6ae+GadgPfpWxtmZ0wDAlO11
#t0TjZJP5IEeKjOnVSVzt2pngGT4Ddc6pap2s9C4ZpUqDl/F5xvEoug6NCcHa+y5H
#GUFgJbTRH3T29Tpw21eTRpEFgVD7L/SzyN4zPrkCgYAbGs+5f2AbK2Tjflshg0yO
#mruVTFp6aeM/ttfmTg3TnP6obOChOAHPnIoJspxkQ9Couo0R6unEpaOMP73Xn2Qa
#mtVi17RdAk4AjRLV6R8cCUCJp6JC3qtCj4i1WFUiaHRNWRdn4eauUQnkl7Avxbb6
#zKH3hsCtD0bfuZCGuYIRYQKBgQC1BEC5ihIvEXVr3HGBDQ+cbXB/DNzjHSg7fX6T
#2ReEaXzfz86+6b6iAA8iNvMUMlQGtyahdq4mQ6oFeHpXwgQ7/B+4TJQmdWYbKrMD
#uPBtGdU826HVZbFMSx5x6NlHELFnl7v6SnkoUnclhZkadMSwLViK0eVEhpcn/zem
#KlNk0QKBgApFRKVHvNnIVV6mNk1VDREcdtLdosi0WIjn8I0IC4zihlxaYdbGTSMY
#/MD5dNHp8gtjgfcziM65sY6oPIvSG4MBcbWMSBU5IoeW3/0S1D2JSFCpM65xw9A9
#JLQ0LI1trS43b3n+R8HeflO1SZ3nnfWz13Ojh5S93gtAw/kHAvX2
#-----END RSA PRIVATE KEY-----"""
#################################################


#-------------------------------------------------------------------
#0. Get private key
    private_key = open(FN_PRIVATE_KEY, "rb").read()

#-------------------------------------------------------------------
#1. Setup private RSA key
#   As master, we import our stored Private Key,
#   we need to establish this first to use its size method...

    # Get stored private key
    #private_key = open('masterkey.pem', 'rb').read()
    # Create a new RSA key instance
    rsa_private_key = RSA.importKey(private_key)
    
    # Find the maximum length of data the could have been
    # encrypted with PKSC1 using a key the size of this one...

    # We convert it from bytes to bits by multiplying it by the
    # inverse of 8 for better performance.
    pksc1_length = int((rsa_private_key.size()+1)*0.125) #512


#-------------------------------------------------------------------
#2. Split up the received data 'f' to retrieve the various
#   blocks of data we need to use in the decryption process...

    # PKCS1 ciphertext - The first bytes to the max length PKCS1 can encrypt
    pkcs1_ciphertext = f[:pksc1_length]
    # IV - the next 8 bytes
    iv = f[pksc1_length:pksc1_length+8]
    # Ciphertext - of arbitrary length are the remaining bytes
    aes_ciphertext = f[pksc1_length+8:]
    print('len(f)')
    print(len(f))
    print('pkcs1_ciphertext')
    print(pkcs1_ciphertext)
    print('iv')
    print(iv)
    print(len(iv))
    print('aes_ciphertext')
    print(aes_ciphertext)

#-------------------------------------------------------------------
#3. Decrypt the PKCS1 ciphertext with RSA private key
#   to obtain the symmetric key within... 

    pkcs1_cipher = PKCS1_OAEP.new(rsa_private_key)
    symmetric_key = pkcs1_cipher.decrypt(pkcs1_ciphertext)

#-------------------------------------------------------------------
#4. Decrypt the AES ciphertext to obtain encrypted data
#   now that we have the symmetric key

    #4.1 Setup
    # Instantiate a 128bit counter object for CTR mode of operation.
    # 64bits of counter, 64bits of prefix
    counter = Counter.new(64, prefix=iv)
    # Create a new AES/CTR cipher instance
    aes_cipher = AES.new(symmetric_key, AES.MODE_CTR, counter=counter)

    #4.2 Decrypt AES ciphertext
    decoded_text = aes_cipher.decrypt(aes_ciphertext)

#-------------------------------------------------------------------
#5. View the data, as per program specification
    # print(--- decrypted message ---)
    print(decoded_text)


if __name__ == "__main__":
    fn = input("Which file in pastebot.net does the botnet master want to view? ")
    if not os.path.exists(os.path.join("pastebot.net", fn)):
        print("The given file doesn't exist on pastebot.net")
        os.exit(1)
    f = open(os.path.join("pastebot.net", fn), "rb").read()
    decrypt_valuables(f)
