from abc import ABC
from io import StringIO, BytesIO, RawIOBase, SEEK_SET
from typing import TextIO, BinaryIO


class BytesIOPersistent(BytesIO):
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
            self.close()

        data = self.__captured_data
        self.__captured_data = None
        return data


class StringIOPersistent(StringIO):
    """
    A helper class to capture the data written to a StringIO object when it is closed
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
            self.close()

        data = self.__captured_data
        self.__captured_data = None
        return data


class TextIOToBinaryIOWrapper(BinaryIO, ABC):
    def __init__(self, text_stream: TextIO, encoding: str = 'ascii'):
        self.text_stream = text_stream
        self.__encoding = encoding

    def close(self) -> None:
        # Close the TextIO stream
        self.text_stream.close()

    def read(self, size=-1) -> bytes:
        # Read a chunk of text from the TextIO stream
        text_data = self.text_stream.read(size)
        if not text_data:  # End of the text stream
            return b""
        # Encode the text data to bytes
        return text_data.encode(self.__encoding)

    def write(self, b: bytes) -> int:
        # Decode binary data to text and write to the TextIO stream
        text_data = b.decode(self.__encoding)
        self.text_stream.write(text_data)
        return len(b)  # Return the number of bytes written

    def readable(self) -> bool:
        # Indicate that the stream is readable
        return True

    def writable(self) -> bool:
        # Indicate that the stream is writable
        return True

    def seekable(self) -> bool:
        # Indicate that the underlying stream supports seeking
        return self.text_stream.seekable()

    def seek(self, offset: int, whence: int = SEEK_SET) -> int:
        # Proxy seek to the underlying TextIO stream
        return self.text_stream.seek(offset, whence)

    def tell(self) -> int:
        # Proxy tell to the underlying TextIO stream
        return self.text_stream.tell()
