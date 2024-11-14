import unittest

import age.exceptions

from src.ssage import SSAGE


class TestEncryptDecrypt(unittest.TestCase):
    def test_encrypt_decrypt_authenticated(self):
        e = SSAGE(SSAGE.generate_private_key(), authenticate=True)
        encrypted = e.encrypt('Hello, world!')
        decrypted = e.decrypt(encrypted)
        self.assertEqual(decrypted, 'Hello, world!')

    def test_encrypt_decrypt_unauthenticated(self):
        e = SSAGE(SSAGE.generate_private_key(), authenticate=False)
        encrypted = e.encrypt('Hello, world!')
        decrypted = e.decrypt(encrypted, authenticate=False)
        self.assertEqual(decrypted, 'Hello, world!')

    def test_encrypt_decrypt_invalid_signature(self):
        e = SSAGE(SSAGE.generate_private_key(), authenticate=True)
        encrypted = e.encrypt('Hello, world!')
        encrypted = encrypted[:44] + encrypted[44:][::-1]
        with self.assertRaises(ValueError):
            e.decrypt(encrypted)

    def test_encrypt_decrypt_no_signature(self):
        e = SSAGE(SSAGE.generate_private_key(), authenticate=True)
        encrypted = e.encrypt('Hello, world!', authenticate=False)
        with self.assertRaises(ValueError):
            e.decrypt(encrypted)

    def test_encrypt_decrypt_invalid_key(self):
        e = SSAGE(SSAGE.generate_private_key(), authenticate=True)
        encrypted = e.encrypt('Hello, world!')
        e = SSAGE(SSAGE.generate_private_key(), authenticate=True)
        with self.assertRaises(age.exceptions.NoIdentity):
            e.decrypt(encrypted)
