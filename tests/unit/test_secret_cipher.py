import base64

import pytest

from app.application.ports.secret_cipher import DecryptionError
from app.infrastructure.security.aes_gcm_cipher import AesGcmCipher

KEY = base64.b64encode(bytes(range(32))).decode()


def test_roundtrip() -> None:
    cipher = AesGcmCipher(KEY)

    token = cipher.encrypt("JBSWY3DPEHPK3PXP", "user-1")

    assert "JBSWY3DPEHPK3PXP" not in token
    assert cipher.decrypt(token, "user-1") == "JBSWY3DPEHPK3PXP"


def test_encrypting_twice_gives_different_tokens() -> None:
    cipher = AesGcmCipher(KEY)

    assert cipher.encrypt("secret", "ctx") != cipher.encrypt("secret", "ctx")


def test_wrong_context_fails() -> None:
    cipher = AesGcmCipher(KEY)
    token = cipher.encrypt("secret", "user-1")

    with pytest.raises(DecryptionError):
        cipher.decrypt(token, "user-2")


def test_wrong_key_fails() -> None:
    token = AesGcmCipher(KEY).encrypt("secret", "ctx")
    other = AesGcmCipher(base64.b64encode(bytes(32)).decode())

    with pytest.raises(DecryptionError):
        other.decrypt(token, "ctx")


@pytest.mark.parametrize("token", ["", "v1:", "v2:abcd", "v1:no-es-base64!!", "v1:AAAA"])
def test_malformed_tokens_fail(token: str) -> None:
    with pytest.raises(DecryptionError):
        AesGcmCipher(KEY).decrypt(token, "ctx")


def test_tampered_token_fails() -> None:
    cipher = AesGcmCipher(KEY)
    token = cipher.encrypt("secret", "ctx")
    version, _, body = token.partition(":")
    raw = bytearray(base64.urlsafe_b64decode(body))
    raw[-1] ^= 0x01
    tampered = f"{version}:{base64.urlsafe_b64encode(bytes(raw)).decode()}"

    with pytest.raises(DecryptionError):
        cipher.decrypt(tampered, "ctx")
