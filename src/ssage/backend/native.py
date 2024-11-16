import tempfile
from pathlib import Path
from subprocess import Popen, PIPE, check_output
from typing import Optional, TextIO, BinaryIO


from .base import SSAGEBackendBase
from .helpers.io_helpers import TextIOToBinaryIOWrapper


class SSAGEBackendNative(SSAGEBackendBase):
    """
    A backend for the SSAGE library that uses the native `age` command line tool

    Advantages:
    - Runs on any system with the `age` command line tool installed
    Disadvantages:
    - Requires the `age` command line tool to be installed
    - Uses temporary files to store the private key and the encrypted data
    """

    def __init__(self, private_key: Optional[str] = None, public_key: Optional[str] = None):
        self.__private_key_file: Optional[Path] = None
        super().__init__(private_key, public_key)

    def __del__(self):
        if self.__private_key_file:
            self.__private_key_file.unlink()

    def encrypt(self, data_in: BinaryIO, data_out: TextIO, additional_recipients: Optional[str] = None) -> None:
        data_out_binary = TextIOToBinaryIOWrapper(data_out)
        recipients = [self.public_key] + (additional_recipients or [])
        command = ['age', '-a', '-r', *recipients]
        with tempfile.NamedTemporaryFile(delete=True) as temp_file:
            process = Popen(command, stdin=PIPE, stdout=temp_file)
            while data := data_in.read(4096):
                process.stdin.write(data)
            process.stdin.close()
            process.wait()
            with open(temp_file.name, 'rb') as temp_file_read:
                while data := temp_file_read.read(4096):
                    data_out_binary.write(data)

    def decrypt(self, data_in: TextIO, data_out: BinaryIO) -> None:
        data_in_binary = TextIOToBinaryIOWrapper(data_in)

        with tempfile.NamedTemporaryFile(delete=True) as temp_file:
            while data := data_in_binary.read(4096):
                temp_file.write(data)
            temp_file.flush()
            temp_file.seek(0)
            command = ['age', '-d', '-i', str(self.__get_private_key_file().absolute()), temp_file.name]
            process = Popen(command, stdout=PIPE)
            process.wait()
            while data := process.stdout.read(4096):
                data_out.write(data)

    def __get_private_key_file(self) -> Path:
        if self.__private_key_file is None:
            with tempfile.NamedTemporaryFile(delete=False) as temp_file:
                temp_file.write(self.private_key.encode('utf-8'))
                self.__private_key_file = Path(temp_file.name)
        return self.__private_key_file

    def parse_public_key(self) -> str:
        """
        Parse the public key from the private key
        :return: AGE public key
        """
        return check_output(['age-keygen', '-y'], text=True, input=self.private_key).strip()

    @staticmethod
    def generate_private_key() -> str:
        """
        Generate a new private key
        :return: AGE private key
        """
        lines = check_output(['age-keygen'], text=True).splitlines(keepends=False)
        return next(filter(lambda x: x.startswith('AGE-SECRET-KEY-'), lines)).strip()
