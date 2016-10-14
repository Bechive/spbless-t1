import os
#Import for RSA-AES Hybrid Encryption
from Crypto.Cipher import AES
from Crypto.Util import Counter
from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_v1_5

def decrypt_valuables(f):
    # TODO: For Part 2, you'll need to decrypt the contents of this file
    # The existing scheme uploads in plaintext
#################################################
private_key_text = "-----BEGIN RSA PRIVATE KEY-----MIIEowIBAAKCAQEAw/wcO39pKTQ+ArqB0oVEouQdNW2XJxEOiTaKggwABqQMO1ux4HxJ1obSx2WRI+1XmytQiGEvUp0vSX4sP9W3gE6eiPtt7S77XRv3xkvL2UfVpoqwq9zrKRupCiSmOXzZodf1WPResWJ/0x9CIFCyN0b7UprQWz14mCNh+2+GnMfx1kAKabhMMeviuHqkeAlc34hvluQwb6ipa7lrmZnA/nbRlaflPOesIcjh/rzT0gGMNwrVV66W/aufzntjdQ8sy4EhowL4nG5LJ9cwYNTsRRlfyjLmVzM06VIsOGvwITT8C8m1NeN69YcA78dwpUc0O/ddQNbijbnws1D0bcI7CwIDAQABAoIBAE0o0syx6usoAEn+t+H0SgN/n+hLDzl4Q6rN6FYu90umBpLQFQX2qPNm/VE3sZ7dcKJMuVYYPRNfgyCCJlWzhJ1lVpFDvBGnb5tGyZQuf0E6QOlirQ/c2FDE7RZrO25isyQ+6/9rpmRcDUtHgTdLzf5pWcU54lIpr3Lma0scq3jJpxK7Ax0/at4a3UPX+L/pM8WmcJ40R40XZwNwcHN37uqTVQm2Jgdm86RV/rMvbF4gTMOE8vT8ypNp2Mt/Qj5Qe26Bagw/1WG3XygM2FfLDO8+EUmpNNzkCkvXgmivX/hNLf4woFI46FSsRkVJ4ptj7R/pqzYIy052uQRAV4cZK8ECgYEA4OpwzzV5ZQDqP/Jd6Mo6m+N8GP64pDa2TdXivs7GdRS/DSewhwif9pZ/z7bC85wY7Ct6x311c90EOI12ShNHv0HVHEBFw0ANEYys5hZg19ZgDDz6BEqdy7s2EnowZFDWHpl/248sQxs1cqsI2CASNnirKOrtGXY+LD1UsefDdfECgYEA3xIWLEyRh6uAo9ahKYiFtp4qt0Pi3RxIiWU6RSu8oavS4JO3b1+MhAq0IuDeUVen3gSZu6RKkGc7l4ofX9mlW/dv+CdKFJ+pTrmqHhzwStwwrebFSjTRL/PuR5RYZFk9NSkeoEuaM5xIMzsywp2Msa9OtqFlxhU4lS8mlovIVLsCgYAwiKZ7MDDX6NCjp+s31pu7E+WthxnU5bGFLkhVoE0W6rknX48qNGRAU82Uxv1ekCqYm/FMpvf3XpQQmAYUigCLdutDw2LKdUHcrZyJsf6H1My5F1dkIa3XTrimWBOlMgRiagE7IbQNbwujiODJsnH7qyJUHA251tgnt7xU/4wgIQKBgE0wnweZP0qpKAyJup76pPp6ZOGh1iEZJmiU5MMGzXFMWd5ofzNE5wTSB1+CXKvdHzOOd/wcb8jkUBSyMQUj9TqLtu0x+0qDrTyWtq1Q6j2dUCL9FgwFltV3HV8bkDK5RprcrcJeJu/xBnLj6z648fSSazR7SRJwSXImLL4vhJT9AoGBAKzRdUtYbN0fjie1/91qeTXUolc3YwBV7vqzhoWni194uasZ1Og02r0YBuGENhOLJH76ssW4MqdHWGmv3g+JkrH4E8YQ+pgogsW8n3ImKPLn767TgIBZfw5xEIak9DQtl1BjU7Yyy2SLsFedWVGASN4wrNx0AQ5vT5xKR83rKi8B-----END RSA PRIVATE KEY-----"
#################################################

#1. Setup private RSA key
#   As master, we import our stored Private Key,
#   we need to establish this first to use its size method...

    # Get stored private key
    private_key = open('masterkey.pem', 'rb').read()
    # Create a new RSA key instance
    rsa_private_key = RSA.importKey(private_key_text)
    
    # Find the maximum length of data the could have been
    # encrypted with PKSC1 using a key the size of this one...

    # We convert it from bytes to bits by multiplying it by the
    # inverse of 8 for better performance.
    pksc1_length = (rsa_private_key.size()+1)*0.125


#2. Split up the received data 'f' to retrieve the various
#   blocks of data we need to use in the decryption process...

    # PKCS1 ciphertext - The first bytes to the max length PKCS1 can encrypt
    pkcs1_ciphertext = f[pksc1_length:]
    # IV - the next 8 bytes
    iv = f[:pksc1_length+8:]
    # Ciphertext - of arbitrary length are the remaining bytes
    aes_ciphertext = f[pksc1_length+8:]

#3. Decrypt the PKCS1 ciphertext with RSA private key
#   to obtain the symmetric key within... 

    pkcs1_cipher = PKCS1_OAEP.new(rsa_private_key)
    symmetric_key = pkcs1_cipher.decrypt(pkcs1_ciphertext)

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
