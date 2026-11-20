from typing import Protocol


class DecryptionError(Exception):
    pass


class SecretCipher(Protocol):
    def encrypt(self, plaintext: str, context: str) -> str: ...

    def decrypt(self, token: str, context: str) -> str: ...
