import hmac
import sys
from base64 import b64encode, b64decode
from hashlib import sha256, pbkdf2_hmac
from io import BytesIO, StringIO
from secrets import token_bytes
from typing import Optional, List, Type

from age.cli import AGE_PEM_LABEL

try:
    from .backend import SSAGEBackendAge, SSAGEBackendBase
    from .backend.helpers.io_helpers import BytesIOPersistent, StringIOPersistent
except ImportError:
    from backend import SSAGEBackendAge, SSAGEBackendBase
    from backend.helpers.io_helpers import BytesIOPersistent, StringIOPersistent

SSAGE_SIGNATURE_SEPARATOR = b'|1|'


class SSAGE:
    """
    A simple wrapper around the AGE encryption library to provide a more user-friendly interface
    """

    def __init__(self, private_key: Optional[str] = None, strip: bool = True, authenticate: Optional[bool] = None, public_key: Optional[str] = None, backend: Type[SSAGEBackendBase] = SSAGEBackendAge):
        """
        Initialize the SSAGE object
        :param private_key: AGE private key, if not provided decryption and authenticated encryption will not be available
        :param strip: whether to return single-line ASCII armored data, if set to False the data will be returned with PEM headers
        :param authenticate: whether to authenticate the data, if set to False the data can be forged by anyone with the public key. Default is True if private_key is provided, False if only public_key is provided
        :param public_key: AGE public key, if not provided it will be derived from the private key
        """
        if private_key is None and authenticate:
            raise ValueError('Private key must be provided for authenticated encryption')

        self.__backend = backend(private_key, public_key)
        self.__strip = strip
        self.__authenticate = authenticate if authenticate is not None else bool(private_key)
        self.__authentication_key: Optional[bytes] = None

    def encrypt_bytes(self, data: bytes, authenticate: Optional[bool] = None, additional_recipients: Optional[List[str]] = None) -> str:
        """
        Encrypt data using AGE encryption
        :param data: data to encrypt
        :param authenticate: whether to authenticate the data, None to use the default
        :param additional_recipients: additional public keys to encrypt the data for
        :return: ASCII armored encrypted data
        """
        authenticate = authenticate or (authenticate is None and self.__authenticate)
        if authenticate:
            if not self.__backend.private_key:
                raise ValueError('Private key must be provided for authenticated encryption')

            signature = self.__mac(data)
            data = signature + SSAGE_SIGNATURE_SEPARATOR + data

        if authenticate and additional_recipients:
            raise ValueError('Additional recipients are not supported for authenticated encryption')

        data_in = BytesIO(data)
        data_out = StringIOPersistent()

        if not hasattr(sys.stdout, 'buffer'):
            # Needed for unit tests
            sys.stdout.buffer = None

        self.__backend.encrypt(data_in, data_out, additional_recipients=additional_recipients)
        ciphertext = data_out.captured_data

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
        if not self.__backend.private_key:
            raise ValueError('Private key must be provided for decryption')

        if self.__strip:
            # Make every line max 64 characters long as per PEM
            data = '\n'.join([data[i:i + 64] for i in range(0, len(data), 64)])
            data = f'-----BEGIN {AGE_PEM_LABEL}-----\n{data}\n-----END {AGE_PEM_LABEL}-----\n'

        data_out = BytesIOPersistent()

        self.__backend.decrypt(StringIO(data), data_out)

        plaintext = data_out.captured_data
        if authenticate or (authenticate is None and self.__authenticate):
            plaintext = self.__drop_and_verify_signature(plaintext)
        return plaintext

    def encrypt(self, data: str, authenticate: Optional[bool] = None, additional_recipients: Optional[List[str]] = None) -> str:
        """
        Encrypt data using AGE encryption
        :param data: data to encrypt
        :param authenticate: whether to authenticate the data, None to use the default
        :param additional_recipients: additional public keys to encrypt the data for
        :return: ASCII armored encrypted data
        """
        return self.encrypt_bytes(data.encode('utf-8'), authenticate=authenticate, additional_recipients=additional_recipients)

    def decrypt(self, data: str, authenticate: Optional[bool] = None) -> str:
        """
        Decrypt data using AGE encryption
        :param data: ASCII armored encrypted data
        :param authenticate: whether to authenticate the data, None to use the default
        :return: decrypted data
        """
        return self.decrypt_bytes(data, authenticate=authenticate).decode('utf-8')
    
    def __mac(self, data: bytes, salt: Optional[bytes] = None) -> bytes:
        """
        Generate a signature for the data
        :param data: data to sign
        :return: Machine Authentication Code (MAC) for the data
        """
        salt = salt if salt is not None else token_bytes(32)
        salt_str = b64encode(salt).decode('ascii')

        if self.__authentication_key is None:
            self.__authentication_key = pbkdf2_hmac('sha256', self.__backend.private_key.encode('ascii'), salt, 600000)

        hmac_data = hmac.new(self.__authentication_key, data, sha256).digest()
        hash_data_str = b64encode(hmac_data).decode('ascii')

        return f"{hash_data_str}{salt_str}".encode('ascii')

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
        salt = b64decode(signature_raw_str[44:])
        if not hmac.compare_digest(signature, self.__mac(data, salt)):
            raise ValueError('Signature mismatch')
        return True

    @property
    def public_key(self) -> str:
        """
        Get the public key
        :return: AGE public key
        """
        return self.__backend.public_key

    @staticmethod
    def generate_private_key() -> str:
        """
        Generate a new private key
        :return: AGE private key
        """
        return SSAGEBackendAge.generate_private_key()


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
