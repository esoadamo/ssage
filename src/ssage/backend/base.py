from io import IOBase, TextIOBase
from typing import Optional, TextIO, BinaryIO


class SSAGEBackendBase:
    def __init__(self, private_key: Optional[str] = None, public_key: Optional[str] = None):
        """
        Initialize the SSAGE Backend base object
        :param private_key: AGE private key
        :param public_key: AGE public key
        """
        if private_key is None and public_key is None:
            raise ValueError("Either a private or public key must be provided")
        if private_key is not None and public_key is not None:
            raise ValueError("Both a private and public key cannot be provided")

        self.__private_key = private_key
        self.__public_key = public_key or self.parse_public_key()

    def encrypt(self, data_in: BinaryIO, data_out: TextIO, additional_recipients: Optional[str] = None) -> None:
        """
        Encrypt the data
        :param data_in: input data
        :param data_out: output data
        :param additional_recipients: additional recipients
        """
        raise NotImplementedError()

    def decrypt(self, data_in: TextIO, data_out: BinaryIO) -> None:
        """
        Decrypt the data
        :param data_in: input data
        :param data_out: output data
        """
        raise NotImplementedError()

    def parse_public_key(self) -> str:
        """
        Parse the public key from the private key
        :return: AGE public key
        """
        raise NotImplementedError()

    @staticmethod
    def generate_private_key() -> str:
        """
        Generate a new private key
        :return: AGE private key
        """
        raise NotImplementedError()

    @property
    def private_key(self) -> Optional[str]:
        """
        Get the private key
        :return: AGE private key
        """
        return self.__private_key

    @property
    def public_key(self) -> str:
        """
        Get the public key
        :return: AGE public key
        """
        return self.__public_key
