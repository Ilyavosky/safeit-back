import base64
import json
import os
import sys
from pathlib import Path

os.environ.setdefault("ENVIRONMENT", "dev")
os.environ.setdefault("DATABASE_URL", "postgresql://export:export@localhost:5432/export")
os.environ.setdefault("JWT_SECRET", "x" * 32)
os.environ.setdefault("ENCRYPTION_KEY", base64.b64encode(bytes(32)).decode())


def main() -> None:
    from app.main import app

    target = Path(sys.argv[1] if len(sys.argv) > 1 else "openapi.json")
    schema = json.dumps(app.openapi(), ensure_ascii=False, indent=2, sort_keys=True)
    target.write_text(schema + "\n", encoding="utf-8")
    print(f"OpenAPI escrito en {target}")


if __name__ == "__main__":
    main()
