import unittest
from src.ssage import SSAGE


class TestEncryptDecrypt(unittest.TestCase):
    def test_encrypt_decrypt_authenticated(self):
        e = SSAGE(SSAGE.generate_private_key())
        encrypted = e.encrypt('Hello, world!')
        decrypted = e.decrypt(encrypted)
        self.assertEqual(decrypted, 'Hello, world!')
