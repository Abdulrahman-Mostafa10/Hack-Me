from peer import Peer
from assets import *

class Receiver(Peer):
    def __init__(self, q, alpha, m, a, c, key_length=256, hashfunc=hashlib.sha256):
        super().__init__(q, alpha, m, a, c, key_length, hashfunc)
    
    def receive_initial_seed(self, encrypted_seed, hmac_value):
        if not HMAC_verifier(self.hmac_key, encrypted_seed, hmac_value, self.hashfunc):
            raise ValueError("HMAC verification failed")
        self.seed = aes_decrypt(self.aes_key, encrypted_seed)
        self.seed = int.from_bytes(self.seed, "big")

    
    

