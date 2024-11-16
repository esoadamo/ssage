import unittest

import pyrage.pyrage
from parameterized import parameterized

import age.exceptions

from src.ssage import SSAGE
from src.ssage.backend import SSAGEBackendAge, SSAGEBackendPyrage, SSAGEBackendNative

BACKENDS = [SSAGEBackendAge, SSAGEBackendPyrage, SSAGEBackendNative]

class TestEncryptDecrypt(unittest.TestCase):
    @parameterized.expand(BACKENDS)
    def test_encrypt_decrypt_authenticated(self, backend):
        e = SSAGE(SSAGE.generate_private_key(), backend=backend, authenticate=True)
        encrypted = e.encrypt('Hello, world!')
        decrypted = e.decrypt(encrypted)
        self.assertEqual(decrypted, 'Hello, world!')

    @parameterized.expand(BACKENDS)
    def test_encrypt_decrypt_unauthenticated(self, backend):
        e = SSAGE(SSAGE.generate_private_key(), backend=backend, authenticate=False)
        encrypted = e.encrypt('Hello, world!')
        decrypted = e.decrypt(encrypted, authenticate=False)
        self.assertEqual(decrypted, 'Hello, world!')

    @parameterized.expand(BACKENDS)
    def test_encrypt_decrypt_invalid_signature(self, backend):
        e = SSAGE("AGE-SECRET-KEY-1SPCSCWGZ28QND3D7CK62JF44T9SVVRCDCGWRL2CX4S7ZNZC76EMSDCKJ3M", backend=backend, authenticate=True)
        plaintext = "PateXS6PfCYjq+r30YODvBVL0huZOx3BMVBoMzEgLj0=4E7zW8ZI1zRmaeWUPZfWra3uWSMPgSfijHpIXNTpTXc=|1|Hello, world!"
        encrypted = e.encrypt(plaintext, authenticate=False)
        self.assertTrue(e.decrypt(encrypted, authenticate=False))
        self.assertTrue(e.decrypt(encrypted))
        plaintext = plaintext[:10] + "X" + plaintext[11:]
        encrypted = e.encrypt(plaintext, authenticate=False)
        self.assertTrue(e.decrypt(encrypted, authenticate=False))
        with self.assertRaises(ValueError):
            e.decrypt(encrypted)

    @parameterized.expand(BACKENDS)
    def test_encrypt_decrypt_forged_message(self, backend):
        e = SSAGE("AGE-SECRET-KEY-1SPCSCWGZ28QND3D7CK62JF44T9SVVRCDCGWRL2CX4S7ZNZC76EMSDCKJ3M", backend=backend, authenticate=True)
        plaintext = "PateXS6PfCYjq+r30YODvBVL0huZOx3BMVBoMzEgLj0=4E7zW8ZI1zRmaeWUPZfWra3uWSMPgSfijHpIXNTpTXc=|1|Hello, world!"
        plaintext = plaintext[:-1] + "."
        encrypted = e.encrypt(plaintext, authenticate=False)
        self.assertTrue(e.decrypt(encrypted, authenticate=False))
        with self.assertRaises(ValueError):
            e.decrypt(encrypted)

    @parameterized.expand(BACKENDS)
    def test_encrypt_decrypt_no_signature(self, backend):
        e = SSAGE(SSAGE.generate_private_key(), backend=backend, authenticate=True)
        encrypted = e.encrypt('Hello, world!', authenticate=False)
        with self.assertRaises(ValueError):
            e.decrypt(encrypted)

    @parameterized.expand(BACKENDS)
    def test_encrypt_decrypt_invalid_key(self, backend):
        e = SSAGE(SSAGE.generate_private_key(), backend=backend, authenticate=True)
        encrypted = e.encrypt('Hello, world!')
        e = SSAGE(SSAGE.generate_private_key(), backend=backend, authenticate=True)
        # noinspection PyTypeChecker
        with self.assertRaises((age.exceptions.NoIdentity, pyrage.pyrage.DecryptError, ValueError)):
            e.decrypt(encrypted)

class TestConstructorParams(unittest.TestCase):
    @parameterized.expand(BACKENDS)
    def test_both_public_and_private_keys(self, backend):
        with self.assertRaises(ValueError):
            SSAGE(SSAGE.generate_private_key(), public_key="age1u2l868p8kvyulzaccugynydssh8hmrhv737fg8p9lja80jvpn4gqmjtxy5", backend=backend)

    @parameterized.expand(BACKENDS)
    def test_no_keys(self, backend):
        with self.assertRaises(ValueError):
            SSAGE(backend=backend)

    @parameterized.expand(BACKENDS)
    def test_public_key_only_and_authenticate(self, backend):
        with self.assertRaises(ValueError):
            SSAGE(public_key="age1u2l868p8kvyulzaccugynydssh8hmrhv737fg8p9lja80jvpn4gqmjtxy5", backend=backend, authenticate=True)

class TestPublicKeyOnly(unittest.TestCase):
    @parameterized.expand(BACKENDS)
    def test_public_key_only(self, backend):
        e = SSAGE(public_key="age1u2l868p8kvyulzaccugynydssh8hmrhv737fg8p9lja80jvpn4gqmjtxy5", backend=backend)
        self.assertTrue(e.encrypt('Hello, world!'))

    @parameterized.expand(BACKENDS)
    def test_public_key_only_auth_encryption(self, backend):
        e = SSAGE(public_key="age1u2l868p8kvyulzaccugynydssh8hmrhv737fg8p9lja80jvpn4gqmjtxy5", backend=backend, authenticate=False)
        with self.assertRaises(ValueError):
            e.encrypt('Hello, world!', authenticate=True)

    @parameterized.expand(BACKENDS)
    def test_public_key_only_no_signature(self, backend):
        e = SSAGE(public_key="age1u2l868p8kvyulzaccugynydssh8hmrhv737fg8p9lja80jvpn4gqmjtxy5", backend=backend, authenticate=False)
        self.assertTrue(e.encrypt('Hello, world!'))

    @parameterized.expand(BACKENDS)
    def test_public_key_only_no_signature_decrypt(self, backend):
        e = SSAGE(public_key="age1u2l868p8kvyulzaccugynydssh8hmrhv737fg8p9lja80jvpn4gqmjtxy5", backend=backend, authenticate=False)
        encrypted = e.encrypt('Hello, world!')
        with self.assertRaises(ValueError):
            e.decrypt(encrypted)

class TestAdditionalRecipients(unittest.TestCase):
    @parameterized.expand(BACKENDS)
    def test_additional_recipients(self, backend):
        e = SSAGE(SSAGE.generate_private_key(), backend=backend, authenticate=False)
        encrypted = e.encrypt('Hello, world!', additional_recipients=["age1u2l868p8kvyulzaccugynydssh8hmrhv737fg8p9lja80jvpn4gqmjtxy5"])
        decrypted = e.decrypt(encrypted)
        self.assertEqual(decrypted, 'Hello, world!')

    @parameterized.expand(BACKENDS)
    def test_additional_recipients_authenticated(self, backend):
        e = SSAGE(SSAGE.generate_private_key(), backend=backend, authenticate=True)
        with self.assertRaises(ValueError):
            e.encrypt('Hello, world!', additional_recipients=["age1u2l868p8kvyulzaccugynydssh8hmrhv737fg8p9lja80jvpn4gqmjtxy5"])

    @parameterized.expand(BACKENDS)
    def test_additional_recipients_authenticated_explicit(self, backend):
        e = SSAGE(SSAGE.generate_private_key(), backend=backend, authenticate=False)
        with self.assertRaises(ValueError):
            e.encrypt('Hello, world!', additional_recipients=["age1u2l868p8kvyulzaccugynydssh8hmrhv737fg8p9lja80jvpn4gqmjtxy5"], authenticate=True)

if __name__ == '__main__':
    unittest.main()
