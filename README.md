# Super-Simple AGE

A wrapper around the [age](https://pypi.org/project/age/) encryption library that makes it easier to use.
Age stands for Actually Good Encryption, and is a modern encryption library that is easy to use and secure.

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
