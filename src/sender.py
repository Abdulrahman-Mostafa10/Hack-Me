import secrets
from peer import Peer
from assets import *


class Sender(Peer):
    def __init__(self, q, alpha, m, a, c, key_length=256, hashfunc=hashlib.sha256):
        super().__init__(q, alpha, m, a, c, key_length, hashfunc)
        self.seed = secrets.randbits(key_length) 
    
    def send_initial_seed(self):
        encrypted_seed = aes_encrypt(self.aes_key, self.seed.to_bytes(self.key_length // 8, "big")) #the nasty looking to_bytes is because aes_encrypt expects bytes, not an int
        hmac_value = HMAC_generator(self.hmac_key, encrypted_seed, self.hashfunc)
        return encrypted_seed, hmac_value

