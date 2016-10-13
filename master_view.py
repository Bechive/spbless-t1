import os


def decrypt_valuables(f):
    # TODO: For Part 2, you'll need to decrypt the contents of this file
    # The existing scheme uploads in plaintext
    # As such, we just convert it back to ASCII and print it out
    private_key = RSA.importKey(open('masterkey.pem', 'rb').read())

    # New PKCS1_OAEP Encrypt/Decrypt instance
    pkcs1_cipher = PKCS1_OAEP.new(private_key)

    #find key size + 1 in bytes (/ 8)

    # get the prefix bytes/word from the file

    # get the remaining bytes/word from the file

    # Decrypt asymmetric ciphertext
    # - split the data up to retrieve actual message, iv, symm key etc.

    # Decrypt symmetric ciphertext
    # - then use the above in symmetric cipher

    # print(--- decrypted message ---)
    
    decoded_text = str(f, 'ascii')
    print(decoded_text)


if __name__ == "__main__":
    fn = input("Which file in pastebot.net does the botnet master want to view? ")
    if not os.path.exists(os.path.join("pastebot.net", fn)):
        print("The given file doesn't exist on pastebot.net")
        os.exit(1)
    f = open(os.path.join("pastebot.net", fn), "rb").read()
    decrypt_valuables(f)
