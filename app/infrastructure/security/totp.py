import pyotp


class PyOtpTotpService:
    def __init__(self, issuer: str = "SafeIT") -> None:
        self._issuer = issuer

    def generate_secret(self) -> str:
        return pyotp.random_base32()

    def provisioning_uri(self, secret: str, email: str) -> str:
        return pyotp.TOTP(secret).provisioning_uri(name=email, issuer_name=self._issuer)

    def verify(self, secret: str, code: str) -> bool:
        return bool(pyotp.TOTP(secret).verify(code, valid_window=1))
