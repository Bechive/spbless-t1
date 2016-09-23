import struct

from Crypto.Cipher import AES
from Crypto import Random
from Crypto.Util import Counter
from lib.crypto_utils import ANSI_X923_pad, ANSI_X923_unpad
from Crypto.Hash import HMAC
from Crypto.Hash import SHA256

from dh import create_dh_key, calculate_dh_secret

class StealthConn(object):
    def __init__(self, conn, client=False, server=False, verbose=False):
        self.conn = conn
        self.cipher = None
        self.secret_key = None
        self.shared_hash = None
        self.client = client
        self.server = server
        self.verbose = verbose
        self.initiate_session()

    def initiate_session(self):
        # Perform the initial connection handshake for agreeing on a shared secret

        ### TODO: Your code here!
        # This can be broken into code run just on the server or just on the client
        if self.server or self.client:
            my_public_key, my_private_key = create_dh_key()
            # Send them our public key
            self.send(bytes(str(my_public_key), "ascii"))
            # Receive their public key
            their_public_key = int(self.recv())
            # Obtain our shared secret
            self.shared_hash = calculate_dh_secret(their_public_key, my_private_key)
            self.secret_key = self.shared_hash
            print("Shared hash: {}".format(self.shared_hash))

        # Default XOR algorithm can only take a key of length 32
        iv = self.generate_iv()
        self.cipher = AES.new(self.secret_key[:16], AES.MODE_CBC, iv)

    def generate_iv(self):
        return Random.new().read(AES.block_size)

    def encrypt_data(self, data):
        #todo mac
        data = ANSI_X923_pad(data, AES.block_size)
        iv = self.generate_iv()
        self.cipher = AES.new(self.secret_key[:16], AES.MODE_CBC, iv)
        ciphertext = self.cipher.encrypt(data)
        return iv + ciphertext

    def decrypt_data(self, data):
        iv = data[:AES.block_size] #need proper implementation
        self.cipher = AES.new(self.secret_key[:16], AES.MODE_CBC, iv)
        data = self.cipher.decrypt(data[AES.block_size:])
        plaintext = ANSI_X923_unpad(data, AES.block_size)
        #streql.equals(actual_tag, tag) check tag
        return plaintext

    def encrypt_ctr(self, data):
        #64 bit nonce
        iv = Random.new().read(8)
        counter = Counter.new(64, prefix=iv)
        #AES.key_size[2] => 32, * 8 = 256 bit key
        self.cipher = AES.new(self.secret_key[:AES.key_size[2]], AES.MODE_CTR, counter=counter)
        ciphertext = self.cipher.encrypt(data)
        return iv + ciphertext

    def decrypt_ctr(self, data):
        #64 bit nonce
        iv = data[:8]
        counter = Counter.new(64, prefix=iv)
        #AES.key_size[2] => 32, * 8 = 256 bit key
        self.cipher = AES.new(self.secret_key[:AES.key_size[2]], AES.MODE_CTR, counter=counter)
        plaintext = self.cipher.decrypt(data[8:])
        return plaintext

    def send(self, data):
        if self.cipher:
            hmac = HMAC.new(self.shared_hash.encode('ascii'), digestmod=SHA256)
            hmac.update(data)
            raw_data = data.decode('ascii')
            data = hmac.hexdigest() + raw_data
            data = bytes(data, "ascii")

            encrypted_data = self.encrypt_ctr(data)
            if self.verbose:
                print("Original data: {}".format(data))
                print("Encrypted data: {}".format(repr(encrypted_data)))
                print("Sending packet of length {}".format(len(encrypted_data)))
        else:
            encrypted_data = data

        # Encode the data's length into an unsigned two byte int ('H')
        pkt_len = struct.pack('H', len(encrypted_data))
        self.conn.sendall(pkt_len)
        self.conn.sendall(encrypted_data)

    def recv(self):
        # Decode the data's length from an unsigned two byte int ('H')
        pkt_len_packed = self.conn.recv(struct.calcsize('H'))
        unpacked_contents = struct.unpack('H', pkt_len_packed)
        pkt_len = unpacked_contents[0]

        encrypted_data = self.conn.recv(pkt_len)
        if self.cipher:
            data = self.decrypt_ctr(encrypted_data)
            raw_hmac = data[:64]
            data = data[64:]
            hmac = HMAC.new(self.shared_hash.encode("ascii"), digestmod=SHA256)
            hmac.update(data)
            if hmac.hexdigest() != raw_hmac.decode("ascii"):
                print("Failed HMAC")
            else:
                print("Verified HMAC")


            if self.verbose:
                print("Receiving packet of length {}".format(pkt_len))
                print("Encrypted data: {}".format(repr(encrypted_data)))
                print("Original data: {}".format(data))
        else:
            data = encrypted_data

        return data

    def close(self):
        self.conn.close()
