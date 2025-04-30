from assets import *
import secrets 
class Peer:
    def __init__(self, q, alpha, m, a, c, key_length=256, hashfunc=hashlib.sha256):
        self.hashfunc = hashfunc
        self.q = q
        self.alpha = alpha
        self.m = m
        self.a = a
        self.c = c
        self.key_length = key_length
        self.x_random = secrets.randbelow(q)
        self.seed = None 

    def generate_public_key(self):
        self.y = diffie_hellman_publication(self.q, self.alpha, self.x_random)
        return self.y
    
    def generate_shared_secret(self, y_other):
        # 2x key_length so we can use the first key_length bits for AES and the last key_length bits for HMAC
        full_key = diffie_hellman_shared_secret(y_other, self.x_random, self.q, self.key_length * 2)
    
        byte_length = (self.key_length * 2) // 8
        full_key_bytes = full_key.to_bytes(byte_length, "big")
        
        half_length = byte_length // 2
        self.aes_key = full_key_bytes[:half_length]
        self.hmac_key = full_key_bytes[half_length:]
    
    def process_message(self, message): # encrypt/decrypt

        #just for compatibility
        if isinstance(message, bytearray):
            message = bytes(message)
        elif not isinstance(message, bytes):
            raise ValueError("Message must be of type bytes or bytearray")
        
        message = int.from_bytes(message, "big") # convert to int for xor operation
        message = message ^ self.seed  # XOR operation for both encryption/decryption (a xor b = c, c xor a = b)
        message = message.to_bytes((message.bit_length() + 7) // 8, "big") # convert back to bytes (since sender and receiver are using same function)

        self.seed = LCG(self.seed, self.m, self.a, self.c, 1)[0]
        return message
    

