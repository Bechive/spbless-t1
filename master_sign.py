import os


def sign_file(f):
    # TODO: For Part 2, you'll use public key crypto here
    # The existing scheme just ensures the updates start with the line 'Caesar'
    # This is naive -- replace it with something better!

#################################################
private_key_text = "-----BEGIN RSA PRIVATE KEY-----MIIEowIBAAKCAQEAw/wcO39pKTQ+ArqB0oVEouQdNW2XJxEOiTaKggwABqQMO1ux4HxJ1obSx2WRI+1XmytQiGEvUp0vSX4sP9W3gE6eiPtt7S77XRv3xkvL2UfVpoqwq9zrKRupCiSmOXzZodf1WPResWJ/0x9CIFCyN0b7UprQWz14mCNh+2+GnMfx1kAKabhMMeviuHqkeAlc34hvluQwb6ipa7lrmZnA/nbRlaflPOesIcjh/rzT0gGMNwrVV66W/aufzntjdQ8sy4EhowL4nG5LJ9cwYNTsRRlfyjLmVzM06VIsOGvwITT8C8m1NeN69YcA78dwpUc0O/ddQNbijbnws1D0bcI7CwIDAQABAoIBAE0o0syx6usoAEn+t+H0SgN/n+hLDzl4Q6rN6FYu90umBpLQFQX2qPNm/VE3sZ7dcKJMuVYYPRNfgyCCJlWzhJ1lVpFDvBGnb5tGyZQuf0E6QOlirQ/c2FDE7RZrO25isyQ+6/9rpmRcDUtHgTdLzf5pWcU54lIpr3Lma0scq3jJpxK7Ax0/at4a3UPX+L/pM8WmcJ40R40XZwNwcHN37uqTVQm2Jgdm86RV/rMvbF4gTMOE8vT8ypNp2Mt/Qj5Qe26Bagw/1WG3XygM2FfLDO8+EUmpNNzkCkvXgmivX/hNLf4woFI46FSsRkVJ4ptj7R/pqzYIy052uQRAV4cZK8ECgYEA4OpwzzV5ZQDqP/Jd6Mo6m+N8GP64pDa2TdXivs7GdRS/DSewhwif9pZ/z7bC85wY7Ct6x311c90EOI12ShNHv0HVHEBFw0ANEYys5hZg19ZgDDz6BEqdy7s2EnowZFDWHpl/248sQxs1cqsI2CASNnirKOrtGXY+LD1UsefDdfECgYEA3xIWLEyRh6uAo9ahKYiFtp4qt0Pi3RxIiWU6RSu8oavS4JO3b1+MhAq0IuDeUVen3gSZu6RKkGc7l4ofX9mlW/dv+CdKFJ+pTrmqHhzwStwwrebFSjTRL/PuR5RYZFk9NSkeoEuaM5xIMzsywp2Msa9OtqFlxhU4lS8mlovIVLsCgYAwiKZ7MDDX6NCjp+s31pu7E+WthxnU5bGFLkhVoE0W6rknX48qNGRAU82Uxv1ekCqYm/FMpvf3XpQQmAYUigCLdutDw2LKdUHcrZyJsf6H1My5F1dkIa3XTrimWBOlMgRiagE7IbQNbwujiODJsnH7qyJUHA251tgnt7xU/4wgIQKBgE0wnweZP0qpKAyJup76pPp6ZOGh1iEZJmiU5MMGzXFMWd5ofzNE5wTSB1+CXKvdHzOOd/wcb8jkUBSyMQUj9TqLtu0x+0qDrTyWtq1Q6j2dUCL9FgwFltV3HV8bkDK5RprcrcJeJu/xBnLj6z648fSSazR7SRJwSXImLL4vhJT9AoGBAKzRdUtYbN0fjie1/91qeTXUolc3YwBV7vqzhoWni194uasZ1Og02r0YBuGENhOLJH76ssW4MqdHWGmv3g+JkrH4E8YQ+pgogsW8n3ImKPLn767TgIBZfw5xEIak9DQtl1BjU7Yyy2SLsFedWVGASN4wrNx0AQ5vT5xKR83rKi8B-----END RSA PRIVATE KEY-----"
#################################################

    #Lecture 8, Digital Signatures (with Public Keys)

#1. Setup RSA stuff
    # Get the BotMaster's private/secret key
    private_key = open('privatekey.pem', 'rb').read()
    # Instantiate an RSA key objecg
    rsa_private_key = RSA.importKey(private_key_text)

#2. Setup PKCS1 signature stuff
    #Signature with private/secret key
# ??do we need a random nonce thing... (d, r, As)
    signature = PKCS1_v1_5.new(rsa_private_key)

#3. Make signature of the data (hash first)
    # Hash the data/message/file to size of 256
    h = SHA256.new(f)
    #Sign the hash of the message
    signed = signature.sign(h)

#4. Signed data => signed + data
    #Prefix digital/RSA signature to the file/message/data
    # Which 'Alice' sends to 'Bob' (or master sends to bot)
    return signed + f


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
