import argparse
import asyncio
import getpass
import sys
from dataclasses import replace

from app.config import get_settings
from app.container import build_container
from app.domain.errors import DomainError
from app.domain.value_objects.role import Role


async def seed_admin(email: str, password: str) -> str:
    container = build_container(get_settings())
    await container.database.open()
    try:
        normalized = email.strip().lower()
        user = await container.users.get_by_email(normalized)
        if user is None:
            user = await container.register_user.execute(normalized, password, "seed-admin")
        await container.users.save(replace(user, role=Role.ADMIN))
        return normalized
    finally:
        await container.database.close()


def main() -> int:
    parser = argparse.ArgumentParser(description="Crea o promueve un usuario administrador.")
    parser.add_argument("--email", required=True)
    args = parser.parse_args()
    password = getpass.getpass("Contraseña: ")
    if password != getpass.getpass("Repite la contraseña: "):
        print("Las contraseñas no coinciden.", file=sys.stderr)
        return 1
    try:
        email = asyncio.run(seed_admin(args.email, password))
    except DomainError as exc:
        print(exc.message, file=sys.stderr)
        return 1
    print(f"Administrador listo: {email}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
