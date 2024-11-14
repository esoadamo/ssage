from io import BytesIO
from hashlib import sha256
from secrets import token_bytes
from json import dumps, loads
from typing import Optional
import bcrypt

from age.cli import encrypt as age_encrypt, Decryptor as AgeDecryptor, AsciiArmoredInput, AGE_PEM_LABEL
from age.keys.agekey import AgePrivateKey


SSAGE_SIGNATURE_SEPARATOR = b'|SSE|'


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
        salt_secret = token_bytes(32)
        salt_data = token_bytes(32)
        nonce = token_bytes(32).hex()
        salt_data_hex = salt_data.hex()
        salt_secret_hex = salt_secret.hex()

        hash_data = sha256(data + salt_data).hexdigest()
        hash_secret = sha256(self.__key.private_bytes() + salt_secret).hexdigest()
        
        signature_raw = {
            'secret': hash_secret,
            'secret_salt': salt_secret_hex,
            'data': hash_data,
            'data_salt': salt_data_hex,
            'nonce': nonce
        }
        return dumps(signature_raw, separators=(',', ':')).encode('ascii')

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
        signature_raw_str = self.decrypt(bytes.fromhex(signature.decode('ascii')).decode('ascii'))
        signature_raw = loads(signature_raw_str)

        hash_data = sha256(data + bytes.fromhex(signature_raw['data_salt'])).hexdigest()
        hash_secret = sha256(self.__key.private_bytes + bytes.fromhex(signature_raw['secret_salt'])).hexdigest()

        if hash_data != signature_raw['data'] or hash_secret != signature_raw['secret']:
            raise ValueError('Signature invalid')

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
        decrypted = e.decrypt(encrypted, authenticate=False)
        print(decrypted)
        assert decrypted == 'Hello, world!'
        print('Test passed!')
    test()
