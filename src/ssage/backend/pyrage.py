import binascii
import re
from dataclasses import dataclass
from typing import Optional, TextIO, BinaryIO, Union

from .base import SSAGEBackendBase

try:
    from pyrage.x25519 import Identity, Recipient
    from pyrage import encrypt, decrypt
except ImportError:
    Identity = Recipient = encrypt = decrypt = None


class SSAGEBackendPyrage(SSAGEBackendBase):
    """
    A backend for the SSAGE library that uses the Pyrage library

    Advantages:
    - Uses Rust-based library for encryption
    Disadvantages:
    - Requires the Rust library to be compiled for the target platform
    - Cannot encrypt large data because of the limitations of the Pyrage library (missing ASCII armor streaming support)
    """

    def __init__(self, private_key: Optional[str] = None, public_key: Optional[str] = None):
        try:
            from pyrage import x25519
        except ImportError:
            raise ImportError('The pyrage library is not installed. Please install it using `pip install pyrage`')
        super().__init__(private_key, public_key)

    def encrypt(self, data_in: BinaryIO, data_out: TextIO, additional_recipients: Optional[str] = None) -> None:
        data = data_in.read()
        recipients = [self.__public_key_instance] + ([Recipient.from_str(x) for x in additional_recipients] if additional_recipients is not None else [])
        encrypted_data = encrypt(data, recipients)
        armored = Armored(encrypted_data).armored_data
        data_out.write(armored)

    def decrypt(self, data_in: TextIO, data_out: BinaryIO) -> None:
        armored_data = data_in.read()
        dearmored = Armored(armored_data).dearmored_data
        decrypted_data = decrypt(dearmored, [self.__private_key_instance])
        data_out.write(decrypted_data)

    @property
    def __private_key_instance(self) -> Identity:
        """
        Get the private key
        :return: AGE private key
        """
        from pyrage import x25519
        if self.private_key is None:
            raise ValueError('Private key is not available')
        return x25519.Identity.from_str(self.private_key)

    @property
    def __public_key_instance(self) -> Recipient:
        """
        Get the public key
        :return: AGE public key
        """
        return self.__private_key_instance.to_public() if self.private_key else Recipient.from_str(self.public_key)

    def parse_public_key(self) -> str:
        """
        Parse the public key from the private key
        :return: AGE public key
        """
        return str(self.__public_key_instance)

    @staticmethod
    def generate_private_key() -> str:
        """
        Generate a new private key
        :return: AGE private key
        """
        from pyrage import x25519
        return str(x25519.Identity.generate())



# Courtesy of Alchemyst0x @ https://github.com/woodruffw/pyrage/issues/45#issuecomment-2460684837
@dataclass
class Armored:
    """RFC-compliant ASCII Armor implementation for age encryption."""

    PEM_HEADER = '-----BEGIN AGE ENCRYPTED FILE-----'
    PEM_FOOTER = '-----END AGE ENCRYPTED FILE-----'

    PEM_RE = re.compile(
        rf'^{PEM_HEADER}\n' r'([A-Za-z0-9+/=\n]+)' rf'\n{PEM_FOOTER}$',
    )
    B64_LINE_RE = re.compile(
        r'(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=|[A-Za-z0-9+/]{4})?'
    )

    @property
    def armored_data(self) -> str:
        return self._armored_data

    @property
    def dearmored_data(self) -> bytes:
        return self._dearmored_data

    def __init__(self, data: Union[bytes, str]) -> None:
        if isinstance(data, bytes):
            self._armored_data = self._armor(data)
            self._dearmored_data = self._dearmor(self._armored_data)
        elif isinstance(data, str):
            self._dearmored_data = self._dearmor(data)
            self._armored_data = self._armor(self._dearmored_data)
        else:
            raise TypeError

    def _decode_b64_strict(self, b64_data: str) -> bytes:
        while '\r\n' in b64_data:
            b64_data = b64_data.replace('\r\n', '\n')
        while '\r' in b64_data:
            b64_data = b64_data.replace('\r', '\n')

        b64_lines = b64_data.split('\n')
        for idx, line in enumerate(b64_lines):
            if idx < len(b64_lines) - 1:
                if len(line) != 64:
                    raise ValueError(f'Line {idx+1} length is not 64 characters.')
            elif len(line) > 64:
                raise ValueError('Final line length exceeds 64 characters.')

        b64_str = ''.join(b64_lines)
        if not re.fullmatch(self.B64_LINE_RE, b64_str):
            raise ValueError('Invalid Base64 encoding detected.')

        try:
            decoded_data = binascii.a2b_base64(b64_str)
        except binascii.Error as exc:
            raise ValueError('Base64 decoding error: ' + str(exc)) from exc
        return decoded_data

    def _armor(self, data: bytes) -> str:
        b64_encoded = binascii.b2a_base64(data, newline=False).decode('ascii')
        b64_lines = [b64_encoded[i : i + 64] for i in range(0, len(b64_encoded), 64)]
        return '\n'.join([self.PEM_HEADER, *b64_lines, self.PEM_FOOTER])

    def _dearmor(self, pem_data: str) -> bytes:
        pem_data = pem_data.strip()
        match = re.fullmatch(self.PEM_RE, pem_data)
        if not match:
            raise ValueError('Invalid PEM format or extra data found.')
        b64_data = match.group(1)
        return self._decode_b64_strict(b64_data)
