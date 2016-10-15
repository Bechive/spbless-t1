import os

from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_v1_5
from Crypto.Hash import SHA256

RSA_KEYSIZE_BITS = 4096
FN_PUBLIC_KEY = "public_key.pem"
FN_PRIVATE_KEY = "private_key.pem"

def sign_file(f):
    # TODO: For Part 2, you'll use public key crypto here
    # The existing scheme just ensures the updates start with the line 'Caesar'
    # This is naive -- replace it with something better!

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

    #Digital Signatures

#-------------------------------------------------------------------
#0. First check for a local private key, if we don't have one then,
#   create a pair of private and public keys
#   Private key is stored locally.
#   Public key is uploaded to pastebot for bots, or anyone
#   who wants to encrypt data that only master can decrypt...

if not os.path.exists('private_key.pem'):
    keys = RSA.generate(RSA_KEYSIZE_BITS)
    #save private key
    private_key = keys.exportKey()
    f = open(FN_PRIVATE_KEY,'wb')
    f.write(private_key)
    f.close()
    #publish public key
    public_key = keys.publickey().exportKey()
    f = open(os.path.join("pastebot.net", FN_PUBLIC_KEY), "wb")
    f.write(public_key)
    f.close()

#-------------------------------------------------------------------
#1. Setup RSA stuff
    # Get the BotMaster's private/secret key
    #private_key = open('privatekey.pem', 'rb').read()
    # Instantiate an RSA key object
    rsa_private_key = RSA.importKey(private_key)

#-------------------------------------------------------------------
#2. Setup PKCS1 signature stuff
    # Digital Signature with private key
    signer = PKCS1_v1_5.new(rsa_private_key)

#-------------------------------------------------------------------
#3. Make signature of the data (hash first)
    # Hash the data/message/file to size of 256
    h = SHA256.new(f) # no digest as per documentation
    #Sign the hash of the message
    signature = signer.sign(h)

#-------------------------------------------------------------------
#4. Signed data => signed + data
    #Prefix digital/RSA signature to the file/message/data
    # Which 'Alice' sends to 'Bob' (or master sends to bot)
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
