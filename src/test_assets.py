import unittest
from Crypto.Random import get_random_bytes

from assets import (
    LCG,
    diffie_hellman_publication,
    diffie_hellman_shared_secret,
    aes_encrypt,
    aes_decrypt,
    HMAC_generator,
    HMAC_verifier,
)

class TestAssets(unittest.TestCase):
    def test_LCG(self):
        seed, m, a, c, n = 1, 16, 5, 3, 10
        expected = [8, 11, 10, 5, 12, 15, 14, 9, 0, 3]
        self.assertEqual(LCG(seed, m, a, c, n), expected)

    def test_diffie_hellman(self):
        q = 23
        alpha = 5
        x_random = 6
        y = diffie_hellman_publication(q, alpha, x_random)
        self.assertEqual(y, pow(alpha, x_random, q))

        y_other = 8
        shared_secret = diffie_hellman_shared_secret(y_other, x_random, q, 128)
        self.assertEqual(shared_secret, pow(y_other, x_random, q))

    def test_aes_encrypt_decrypt(self):
        key = get_random_bytes(16)
        plaintext = b"Secret Messagess"
        ciphertext = aes_encrypt(key, plaintext)
        decrypted = aes_decrypt(key, ciphertext)
        self.assertEqual(decrypted, plaintext)

    def test_HMAC(self):
        key = b"secret_key"
        message = b"Important message"
        hmac_value = HMAC_generator(key, message)
        self.assertTrue(HMAC_verifier(key, message, hmac_value))
        self.assertFalse(HMAC_verifier(key, message, b"tampered_hmac"))

if __name__ == "__main__":
    unittest.main()