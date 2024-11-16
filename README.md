# Super-Simple AGE

A wrapper around the [age](https://pypi.org/project/age/) encryption library that makes it easier to use.
AGE stands for Actually Good Encryption, and is a modern encryption library that is easy to use and secure.

Additionally, this library provides an authenticated encryption. However, this feature is fully optional and can be disabled, achieving full compatibility with the age library.

## Installation

```bash
pip install ssage
```

## Supported backends

When using the `ssage` library, you can choose between backends
which handle the actual encryption and decryption.
Backends are chosen by passing `backend=` param to the `SSAGE` class.
The following backends are supported:

### Python age

This is the default backend, and it is a pure Python implementation of the age encryption library.
Its main advantage is that it does not require any additional dependencies,
but does not guarantee side-channel resistance.

### Native

Native backend uses the `age` and `age-keygen` binaries to perform encryption and decryption.
Its main advantage is that is runs anywhere the `age` binaries are available,
the main disadvantage is that is stores the private key in a temporary file.

### Pyrage

Pyrage is using a Rust-based binding for the age encryption.
Main advantage is that it is faster than the Python age backend, but
the Rust library needs to be compiled for the target platform.

## Code Example

### Simple Authenticated Encryption

```python
from ssage import SSAGE
e = SSAGE(SSAGE.generate_private_key())
encrypted = e.encrypt('Hello, world!')
print(encrypted)
decrypted = e.decrypt(encrypted)
print(decrypted)
assert decrypted == 'Hello, world!'
print('Test passed!')
```

### Public Key Encryption

```python
from ssage import SSAGE
public_key = SSAGE(SSAGE.generate_private_key()).public_key
e = SSAGE(public_key=public_key)
encrypted = e.encrypt('Hello, world!')
print(encrypted)
decrypted = e.decrypt(encrypted) # This will fail because the private key is not available
```

### Multiple Recipients

```python
from ssage import SSAGE
public_key_1 = SSAGE(SSAGE.generate_private_key()).public_key
public_key_2 = SSAGE(SSAGE.generate_private_key()).public_key
e = SSAGE(public_key=public_key_1)
e.encrypt('Hello, world!', additional_recipients=[public_key_2])
```
