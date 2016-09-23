import struct

from Crypto.Cipher import AES
from Crypto import Random
from Crypto.Util import Counter
from Crypto.Hash import HMAC
from Crypto.Hash import SHA256
import time

from dh import create_dh_key, calculate_dh_secret

#Provides key size for AES modules
#AES.key_size = (16,24,32)
AES_KEY_SIZE = AES.key_size[2]

class StealthConn(object):
    def __init__(self, conn, client=False, server=False, verbose=False):
        self.conn = conn
        self.cipher = None
        #Used for AES encryption and HMAC
        self.shared_hash = None
        #Random intial for ctr counter
        self.initial_counter = 95094152
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
            print("Shared hash: {}".format(self.shared_hash))

        iv = self.generate_iv()
        
        #Used for initial cipher configuration
        self.cipher = AES.new(self.shared_hash[:16], AES.MODE_CBC, iv)

    def get_session(self):
        #Gets the current user time within a 5 minute (300 second) interval and converts it to a string
        t = str(int(time.time())//300)
        #Configures a SHA256 hash of the time stamp
        h = SHA256.new(t.encode("ascii"))
        #Generates a hashed session token
        session = h.hexdigest()
        return session.encode("ascii")

    def generate_iv(self):
        #Generate a cryptographically secure random number
        return Random.new().read(AES.block_size)

    def encrypt_ctr(self, data):
        #The data input should include the session token + hmac + plaintext
        #Generate random 8 bytes (64bits) for CTR Counter prefix
        iv = Random.new().read(8)
        #Instatiate a 8 byte Counter object, given the prefix and an arbitrary initial value        
        counter = Counter.new(64, prefix=iv, initial_value=self.initial_counter)
        #Instatiate an AES cipher with CTR mode of operation
        #Take part of the secret shared key and the counter object as parameters
        self.cipher = AES.new(self.shared_hash[:AES_KEY_SIZE], AES.MODE_CTR, counter=counter)
        #Generate the ciphertext
        ciphertext = self.cipher.encrypt(data)
        #Return the concatenated random iv and ciphertext for transmission
        return iv + ciphertext

    def decrypt_ctr(self, data):
        #The data in this case in the iv + ciphertext
        #Take the first 8 bytes of data, which is the random iv
        iv = data[:8]
        #Instatiate a counter for decryption, given the prefix used for encrytion and an arbitrary initial value
        counter = Counter.new(64, prefix=iv, initial_value=self.initial_counter)
        #instantiate a AES cipher with CTR mode of operation
        #Taking the shared shared key and couner object as paramters
        self.cipher = AES.new(self.shared_hash[:AES_KEY_SIZE], AES.MODE_CTR, counter=counter)
        #Decrypt the portion of data after the random IV which was the first 8 bytes
        plaintext = self.cipher.decrypt(data[8:])
        #Return the plaintext which would include session token + hmac + plaintext
        return plaintext

    def send(self, data):
        if self.cipher:
            #Keys the hmac and configures the settings
            hmac = HMAC.new(self.shared_hash.encode('ascii'), digestmod=SHA256)
            #Generates the hmac
            hmac.update(self.get_session() + data)
            raw_data = data.decode('ascii')
            #Appends the data to the hmac
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
            #Separates the hmac from the received data
            raw_hmac = data[:64]
            data = data[64:]
            #Begins the recipient generated hmac by keying and configures the settings
            hmac = HMAC.new(self.shared_hash.encode("ascii"), digestmod=SHA256)
            #Generate recipient hmac 
            hmac.update(self.get_session() + data)
        
            #checks if the recipient generated hmac matches the hmac from the sender
            if hmac.hexdigest() != raw_hmac.decode("ascii"):
                print("Failed verification")
            else:
                print("Verified message")


            if self.verbose:
                print("Receiving packet of length {}".format(pkt_len))
                print("Encrypted data: {}".format(repr(encrypted_data)))
                print("Original data: {}".format(data))
        else:
            data = encrypted_data

        return data

    def close(self):
        self.conn.close()
