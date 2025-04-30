import hmac
import hashlib
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

def LCG(seed, m, a, c, n):
    print("LCG Inputs:")
    print(f"Seed: {seed}, m: {m}, a: {a}, c: {c}, n: {n}")
    random_sequence = []
    x = seed
    for _ in range(n):
        x = (a * x + c) % m
        random_sequence.append(x)
    print("LCG Output:")
    print(random_sequence)
    return random_sequence

def diffie_hellman_publication(q, alpha, x_random):
    #  y = alpha^x mod q
    print("Diffie-Hellman publication Inputs:")
    print(f"q: {q}, alpha: {alpha}, x_random: {x_random}")
    y = pow(alpha, x_random, q)
    print("Diffie-Hellman publication Output:")
    print(f"y: {y}")
    return y

def diffie_hellman_shared_secret(y, x_random, q, key_length=512):
    #  k = y^x mod q
    print("Diffie-Hellman shared secret Inputs:")
    print(f"y: {y}, x_random: {x_random}, q: {q}, key_length: {key_length}")
    k = pow(y, x_random, q)
    # Ensure the key is of the specified length
    k = pow(k, 1, 2**key_length)  # Modulo to fit the key length
    print("Diffie-Hellman shared secret Output:")
    print(f"k: {k}")
    return k

def aes_encrypt(key, plaintext):
    print("AES Encryption Inputs:")
    print(f"Key: {key}, Plaintext: {plaintext}")
    cipher = AES.new(key, AES.MODE_CBC)
    ciphertext = cipher.encrypt(pad(plaintext, AES.block_size))
    print("AES Encryption Output:")
    print(f"Ciphertext: {cipher.iv + ciphertext}")
    return cipher.iv + ciphertext

def aes_decrypt(key, ciphertext):
    print("AES Decryption Inputs:")
    print(f"Key: {key}, Ciphertext: {ciphertext}")
    iv = ciphertext[:AES.block_size]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    plaintext = cipher.decrypt(ciphertext[AES.block_size:])
    plaintext = unpad(plaintext, AES.block_size)
    print("AES Decryption Output:")
    print(f"Plaintext: {plaintext}")
    return plaintext

def HMAC_generator(k, m, hashfunc=hashlib.sha256):
    print("HMAC Generation Inputs:")
    print(f"Key: {k}, Message: {m}, Hashfunc: {hashfunc}")
    gen_hmac = hmac.new(k, m, hashfunc).digest()
    print("HMAC Generation Output:")
    print(f"HMAC: {gen_hmac}")
    return gen_hmac

def HMAC_verifier(k, m, h, hashfunc=hashlib.sha256):
    print("HMAC Verification Inputs:")
    print(f"Key: {k}, Message: {m}, HMAC: {h}, Hashfunc: {hashfunc}")
    h_ = HMAC_generator(k, m, hashfunc)
    print("HMAC Verification Output:")
    print(f"HMAC Check: {h == h_}")
    return h == h_


    