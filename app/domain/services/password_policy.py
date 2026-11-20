from app.domain.errors import WeakPasswordError

MIN_LENGTH = 12
MAX_LENGTH = 128
MIN_DISTINCT_CHARACTERS = 5
MIN_EMAIL_FRAGMENT = 4


def validate_password(password: str, email: str) -> None:
    if len(password) < MIN_LENGTH:
        raise WeakPasswordError(f"La contraseña debe tener al menos {MIN_LENGTH} caracteres.")
    if len(password) > MAX_LENGTH:
        raise WeakPasswordError(f"La contraseña no puede superar {MAX_LENGTH} caracteres.")
    if len(set(password)) < MIN_DISTINCT_CHARACTERS:
        raise WeakPasswordError("La contraseña es demasiado repetitiva.")
    local_part = email.split("@", 1)[0].lower()
    if len(local_part) >= MIN_EMAIL_FRAGMENT and local_part in password.lower():
        raise WeakPasswordError("La contraseña no debe contener tu correo.")
