# Super-Simple AGE

A wrapper around the [age](https://pypi.org/project/age/) encryption library that makes it easier to use.
Age stands for Actually Good Encryption, and is a modern encryption library that is easy to use and secure.

## Code Example

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
