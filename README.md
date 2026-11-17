# SafeIT API

Backend de SafeIT (FastAPI, arquitectura hexagonal). Plan de desarrollo por fases en `../PLAN-DESARROLLO-BACKEND.md`.

## Requisitos

- Python 3.13 (el proyecto exige 3.12 o superior)
- [uv](https://docs.astral.sh/uv/)
- PostgreSQL accesible por `DATABASE_URL` (Supabase o local)

## Arranque

```
cp .env.example .env
uv sync
uv run fastapi dev app/main.py
```

En `.env` hay que completar al menos `DATABASE_URL`, `JWT_SECRET` (32 caracteres o más) y `ENCRYPTION_KEY` (32 bytes en base64):

```
python -c "import base64, os; print(base64.b64encode(os.urandom(32)).decode())"
```

`GET /health` devuelve 200 con la base arriba y 503 si no responde. Con la API levantada, la documentación está en `/docs` (se desactiva con `ENVIRONMENT=prod`).

## Calidad

```
uv run ruff check .
uv run ruff format --check .
uv run mypy
uv run pytest
```

Los mismos pasos corren en GitHub Actions (`.github/workflows/ci.yml`).

## Autenticación

| Método | Ruta | Descripción |
|---|---|---|
| POST | `/auth/register` | Alta de usuario (rol `viewer`) |
| POST | `/auth/login` | Devuelve `access_token` y fija la cookie `safeit_refresh`; con MFA activo devuelve `mfa_required` y un `mfa_token` |
| POST | `/auth/mfa/verify` | Completa el login con el código TOTP |
| POST | `/auth/mfa/setup` | Genera el secreto TOTP y el `otpauth_uri` para el QR (requiere sesión) |
| POST | `/auth/mfa/enable` | Activa el MFA confirmando un código (requiere sesión) |
| POST | `/auth/refresh` | Rota el refresh token; reutilizar uno ya rotado revoca toda la familia |
| POST | `/auth/logout` | Revoca la sesión y borra la cookie |
| GET / PATCH | `/users/me` | Perfil; para cambiar correo o contraseña se exige la contraseña actual |

El access token (15 min) va en `Authorization: Bearer`. El refresh token viaja solo en cookie `httpOnly` con `SameSite=Strict` y ruta `/auth`, y en la base se guarda su hash. Los roles se leen de la base en cada petición, así que un cambio de rol aplica de inmediato.

Primer administrador:

```
uv run python -m scripts.seed_admin --email admin@ejemplo.com
```

## Pruebas contra PostgreSQL

Las pruebas de repositorios se omiten si no existe `TEST_DATABASE_URL`. Deben apuntar a una base vacía: crean las tablas `users` y `refresh_tokens` desde `../bd/supabase/migrations/01_safeit_auth.sql` y las borran al terminar. Si `public.users` ya existe, se omiten para no tocar datos.

```
TEST_DATABASE_URL=postgresql://usuario:clave@localhost:5432/safeit_test uv run pytest tests/integration
```

## Estructura

```
app/
  domain/            entidades, reglas y errores; no importa nada de otras capas
  application/       puertos y casos de uso; solo importa domain
  infrastructure/    base de datos, logging y, más adelante, seguridad, recon, LLM, feeds y cola
  interfaces/api/    routers, manejo de errores y middlewares
  container.py       arma las dependencias
  config.py          variables de entorno validadas
tests/
  unit/              incluye la prueba que vigila la regla de dependencias
  integration/
  security/
```

Las migraciones SQL viven en el repositorio de base de datos (`supabase/migrations`).

## Errores

Toda respuesta de error tiene la forma:

```
{"code": "domain_not_verified", "message": "...", "request_id": "..."}
```

`request_id` coincide con la cabecera `X-Request-ID` y con los logs de la petición.
