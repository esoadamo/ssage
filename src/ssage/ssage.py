import sys
from base64 import b64encode, b64decode
from hashlib import sha256
from io import BytesIO
from secrets import token_bytes
from typing import Optional

from age.cli import encrypt as age_encrypt, Decryptor as AgeDecryptor, AsciiArmoredInput, AGE_PEM_LABEL
from age.keys.agekey import AgePrivateKey

SSAGE_SIGNATURE_SEPARATOR = b'|1|'


class SSAGE:
    """
    A simple wrapper around the AGE encryption library to provide a more user-friendly interface
    """

    def __init__(self, private_key: str, strip: bool = True, authenticate: bool = True):
        """
        Initialize the SSAGE object
        :param private_key: AGE private key
        :param strip: whether to return single-line ASCII armored data
        :param authenticate: whether to authenticate the data
        """
        self.__key = AgePrivateKey.from_private_string(private_key)
        self.__strip = strip
        self.__authenticate = authenticate

    def encrypt_bytes(self, data: bytes, authenticate: Optional[bool] = None) -> str:
        """
        Encrypt data using AGE encryption
        :param data: data to encrypt
        :param authenticate: whether to authenticate the data, None to use the default
        :return: ASCII armored encrypted data
        """
        key_public = self.__key.public_key()

        if authenticate or (authenticate is None and self.__authenticate):
            signature = self.__mac(data)
            data = signature + SSAGE_SIGNATURE_SEPARATOR + data

        data_in = BytesIO(data)
        data_out = BytesIOKeepClosedData()

        if not hasattr(sys.stdout, 'buffer'):
            # Needed for unit tests
            sys.stdout.buffer = None

        age_encrypt(
            recipients=[key_public.public_string()],
            infile=data_in,
            outfile=data_out,
            ascii_armored=True
        )
        
        ciphertext = data_out.captured_data.decode('ascii')

        if self.__strip:
            ciphertext = ''.join(ciphertext.splitlines(keepends=False)[1:-1])
        return ciphertext

    def decrypt_bytes(self, data: str, authenticate: Optional[bool] = None) -> bytes:
        """
        Decrypt data using AGE encryption
        :param data: ASCII armored encrypted data
        :param authenticate: whether to authenticate the data, None to use the default
        :return: decrypted data
        """

        if self.__strip:
            # Make every line max 64 characters long as per PEM
            data = '\n'.join([data[i:i + 64] for i in range(0, len(data), 64)])
            data = f'-----BEGIN {AGE_PEM_LABEL}-----\n{data}\n-----END {AGE_PEM_LABEL}-----\n'

        data_in = AsciiArmoredInput(AGE_PEM_LABEL, BytesIO(data.encode('ascii')))
        data_out = BytesIOKeepClosedData()

        if not hasattr(sys.stdout, 'buffer'):
            # Needed for unit tests
            sys.stdout.buffer = None

        with AgeDecryptor([self.__key], data_in) as decryptor:
            data_out.write(decryptor.read())

        plaintext = data_out.captured_data
        if authenticate or (authenticate is None and self.__authenticate):
            plaintext = self.__drop_and_verify_signature(plaintext)
        return plaintext

    def encrypt(self, data: str, authenticate: Optional[bool] = None) -> str:
        """
        Encrypt data using AGE encryption
        :param data: data to encrypt
        :param authenticate: whether to authenticate the data, None to use the default
        :return: ASCII armored encrypted data
        """
        return self.encrypt_bytes(data.encode('utf-8'), authenticate=authenticate)

    def decrypt(self, data: str, authenticate: Optional[bool] = None) -> str:
        """
        Decrypt data using AGE encryption
        :param data: ASCII armored encrypted data
        :param authenticate: whether to authenticate the data, None to use the default
        :return: decrypted data
        """
        return self.decrypt_bytes(data, authenticate=authenticate).decode('utf-8')
    
    def __mac(self, data: bytes) -> bytes:
        """
        Generate a signature for the data
        :param data: data to sign
        :return: Machine Authentication Code (MAC) for the data
        """
        salt_data = token_bytes(32)
        salt_data_str = b64encode(salt_data).decode('ascii')
        hash_data = sha256(data + self.__key.private_bytes() + salt_data).digest()
        hash_data_str = b64encode(hash_data).decode('ascii')

        return f"{hash_data_str}{salt_data_str}".encode('ascii')

    def __drop_and_verify_signature(self, data: bytes) -> bytes:
        """
        Drop the signature from the data and verify it
        :param data: data with signature
        :return: data without signature
        """
        try:
            signature, plaintext = data.split(SSAGE_SIGNATURE_SEPARATOR, 1)
        except ValueError:
            raise ValueError('Data does not contain any signature')
        
        if not self.__verify_signature(plaintext, signature):
            raise ValueError('Signature validation error')
        return plaintext

    def __verify_signature(self, data: bytes, signature: bytes) -> bool:
        """
        Verify the signature of the data
        :param data: plaintext data to verify the signature for
        :param signature: signature to verify
        :return: True if the signature is valid
        """
        signature_raw_str = signature.decode('ascii')
        hash_data = b64decode(signature_raw_str[:44])
        salt_data = b64decode(signature_raw_str[44:])

        hash_data_expected = sha256(data + self.__key.private_bytes() + salt_data).digest()
        if hash_data != hash_data_expected:
            raise ValueError('Signature mismatch')

        return True

    @staticmethod
    def generate_private_key() -> str:
        """
        Generate a new private key
        :return: AGE private key
        """
        return AgePrivateKey.generate().private_string()


class BytesIOKeepClosedData(BytesIO):
    """
    A helper class to capture the data written to a BytesIO object when it is closed
    """

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.__captured_data = None

    def close(self):
        self.__captured_data = self.getvalue()
        super().close()

    @property
    def captured_data(self):
        if not self.closed:
            return self.getvalue()

        data = self.__captured_data
        self.__captured_data = None
        return data


if __name__ == '__main__':
    def test():
        e = SSAGE(SSAGE.generate_private_key())
        encrypted = e.encrypt('Hello, world!')
        print(encrypted)
        decrypted_raw = e.decrypt(encrypted, authenticate=False)
        print(decrypted_raw)
        decrypted = e.decrypt(encrypted)
        print(decrypted)
        assert decrypted == 'Hello, world!'
        print('Test passed!')
    test()
