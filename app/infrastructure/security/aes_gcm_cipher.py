import base64
import binascii
import os

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from app.application.ports.secret_cipher import DecryptionError

VERSION = "v1"
NONCE_SIZE = 12


class AesGcmCipher:
    def __init__(self, key_b64: str) -> None:
        self._aead = AESGCM(base64.b64decode(key_b64, validate=True))

    def encrypt(self, plaintext: str, context: str) -> str:
        nonce = os.urandom(NONCE_SIZE)
        sealed = self._aead.encrypt(nonce, plaintext.encode("utf-8"), context.encode("utf-8"))
        return f"{VERSION}:{base64.urlsafe_b64encode(nonce + sealed).decode('ascii')}"

    def decrypt(self, token: str, context: str) -> str:
        version, _, encoded = token.partition(":")
        if version != VERSION or not encoded:
            raise DecryptionError("Formato de secreto cifrado no reconocido.")
        try:
            raw = base64.urlsafe_b64decode(encoded.encode("ascii"))
            if len(raw) <= NONCE_SIZE:
                raise DecryptionError("Secreto cifrado incompleto.")
            plain = self._aead.decrypt(raw[:NONCE_SIZE], raw[NONCE_SIZE:], context.encode("utf-8"))
        except (binascii.Error, ValueError, InvalidTag) as exc:
            raise DecryptionError("No se pudo descifrar el secreto.") from exc
        return plain.decode("utf-8")
