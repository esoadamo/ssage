import sys
from typing import Optional, TextIO, BinaryIO

from age.cli import encrypt as age_encrypt, Decryptor as AgeDecryptor, AsciiArmoredInput, AGE_PEM_LABEL
from age.keys.agekey import AgePrivateKey, AgePublicKey

from .base import SSAGEBackendBase
from .helpers import TextIOToBinaryIOWrapper


class SSAGEBackendAge(SSAGEBackendBase):
    """
    A backend for the SSAGE library that uses the AGE encryption library

    Advantages:
    - No external dependencies
    - Run on any system where Python is installed
    Disadvantages:
    - No guarantee of side-channel resistance
    """

    def encrypt(self, data_in: BinaryIO, data_out: TextIO, additional_recipients: Optional[str] = None) -> None:
        if not hasattr(sys.stdout, 'buffer'):
            # Needed for unit tests
            sys.stdout.buffer = None

        data_out_binary = TextIOToBinaryIOWrapper(data_out)

        age_encrypt(
            recipients=[self.public_key] + (additional_recipients or []),
            infile=data_in,
            outfile=data_out_binary,
            ascii_armored=True
        )

    def decrypt(self, data_in: TextIO, data_out: BinaryIO) -> None:
        if not hasattr(sys.stdout, 'buffer'):
            # Needed for unit tests
            sys.stdout.buffer = None

        data_in_binary = AsciiArmoredInput(AGE_PEM_LABEL, TextIOToBinaryIOWrapper(data_in))

        with AgeDecryptor([self.__private_key_instance], data_in_binary) as decryptor:
            while data := decryptor.read(4096):
                data_out.write(data)

    @property
    def __private_key_instance(self) -> AgePrivateKey:
        """
        Get the private key
        :return: AGE private key
        """
        if self.private_key is None:
            raise ValueError('Private key is not available')
        return AgePrivateKey.from_private_string(self.private_key)

    @property
    def __public_key_instance(self) -> AgePublicKey:
        """
        Get the public key
        :return: AGE public key
        """
        return AgePublicKey.from_public_string(self.public_key)

    def parse_public_key(self) -> str:
        """
        Parse the public key from the private key
        :return: AGE public key
        """
        return AgePrivateKey.from_private_string(self.private_key).public_key().public_string()

    @staticmethod
    def generate_private_key() -> str:
        """
        Generate a new private key
        :return: AGE private key
        """
        return AgePrivateKey.generate().private_string()
