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
        e = SSAGE("AGE-SECRET-KEY-1SPCSCWGZ28QND3D7CK62JF44T9SVVRCDCGWRL2CX4S7ZNZC76EMSDCKJ3M", authenticate=True)
        plaintext = "AYWE82u5DmN5D2Hewf5A7QJXAgJXAQc4pgz/385Ax2g=4NW65RjT+P4kZm3yCtycRjUJGeuWVc4UAH/Q59oM8h8=|1|Hello, world!"
        encrypted = e.encrypt(plaintext, authenticate=False)
        self.assertTrue(e.decrypt(encrypted, authenticate=False))
        self.assertTrue(e.decrypt(encrypted))
        plaintext = plaintext[:10] + "X" + plaintext[11:]
        encrypted = e.encrypt(plaintext, authenticate=False)
        self.assertTrue(e.decrypt(encrypted, authenticate=False))
        with self.assertRaises(ValueError):
            e.decrypt(encrypted)

    def test_encrypt_decrypt_forged_message(self):
        e = SSAGE("AGE-SECRET-KEY-1SPCSCWGZ28QND3D7CK62JF44T9SVVRCDCGWRL2CX4S7ZNZC76EMSDCKJ3M", authenticate=True)
        plaintext = "AYWE82u5DmN5D2Hewf5A7QJXAgJXAQc4pgz/385Ax2g=4NW65RjT+P4kZm3yCtycRjUJGeuWVc4UAH/Q59oM8h8=|1|Hello, world!"
        plaintext = plaintext[:-1] + "."
        encrypted = e.encrypt(plaintext, authenticate=False)
        self.assertTrue(e.decrypt(encrypted, authenticate=False))
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


class TestConstructorParams(unittest.TestCase):
    def test_both_public_and_private_keys(self):
        with self.assertRaises(ValueError):
            SSAGE(SSAGE.generate_private_key(), public_key="age1u2l868p8kvyulzaccugynydssh8hmrhv737fg8p9lja80jvpn4gqmjtxy5")

    def test_no_keys(self):
        with self.assertRaises(ValueError):
            SSAGE()

    def test_public_key_only_and_authenticate(self):
        with self.assertRaises(ValueError):
            SSAGE(public_key="age1u2l868p8kvyulzaccugynydssh8hmrhv737fg8p9lja80jvpn4gqmjtxy5", authenticate=True)


class TestPublicKeyOnly(unittest.TestCase):
    def test_public_key_only(self):
        e = SSAGE(public_key="age1u2l868p8kvyulzaccugynydssh8hmrhv737fg8p9lja80jvpn4gqmjtxy5")
        self.assertTrue(e.encrypt('Hello, world!'))

    def test_public_key_only_auth_encryption(self):
        e = SSAGE(public_key="age1u2l868p8kvyulzaccugynydssh8hmrhv737fg8p9lja80jvpn4gqmjtxy5", authenticate=False)
        with self.assertRaises(ValueError):
            e.encrypt('Hello, world!', authenticate=True)

    def test_public_key_only_no_signature(self):
        e = SSAGE(public_key="age1u2l868p8kvyulzaccugynydssh8hmrhv737fg8p9lja80jvpn4gqmjtxy5", authenticate=False)
        self.assertTrue(e.encrypt('Hello, world!'))

    def test_public_key_only_no_signature_decrypt(self):
        e = SSAGE(public_key="age1u2l868p8kvyulzaccugynydssh8hmrhv737fg8p9lja80jvpn4gqmjtxy5", authenticate=False)
        encrypted = e.encrypt('Hello, world!')
        with self.assertRaises(ValueError):
            e.decrypt(encrypted)


class TestAdditionalRecipients(unittest.TestCase):
    def test_additional_recipients(self):
        e = SSAGE(SSAGE.generate_private_key(), authenticate=False)
        encrypted = e.encrypt('Hello, world!', additional_recipients=["age1u2l868p8kvyulzaccugynydssh8hmrhv737fg8p9lja80jvpn4gqmjtxy5"])
        decrypted = e.decrypt(encrypted)
        self.assertEqual(decrypted, 'Hello, world!')

    def test_additional_recipients_authenticated(self):
        e = SSAGE(SSAGE.generate_private_key(), authenticate=True)
        with self.assertRaises(ValueError):
            e.encrypt('Hello, world!', additional_recipients=["age1u2l868p8kvyulzaccugynydssh8hmrhv737fg8p9lja80jvpn4gqmjtxy5"])

    def test_additional_recipients_authenticated_explicit(self):
        e = SSAGE(SSAGE.generate_private_key(), authenticate=False)
        with self.assertRaises(ValueError):
            e.encrypt('Hello, world!', additional_recipients=["age1u2l868p8kvyulzaccugynydssh8hmrhv737fg8p9lja80jvpn4gqmjtxy5"], authenticate=True)
