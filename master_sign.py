import os


def sign_file(f):
    # TODO: For Part 2, you'll use public key crypto here
    # The existing scheme just ensures the updates start with the line 'Caesar'
    # This is naive -- replace it with something better!

    #Lecture 8, Digital Signatures (with Public Keys)

    # Get the BotMaster's private/secret key
    private_key = RSA.importKey(open('privatekey.pem', 'rb').read())
    # Hash the data/message/file to size of 256
    h = SHA256.new(f)
    #Signature with private/secret key

# ??do we need a random nonce thing... (d, r, As)
    signature = PKCS1_v1_5.new(private_key)
    #Sign the hash of the message
    sign = signature.sign(h)

    #Prefix digital/RSA signature to the file/message/data
    # Which 'Alice' sends to 'Bob' (or master sends to bot)
    return sign + f


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
