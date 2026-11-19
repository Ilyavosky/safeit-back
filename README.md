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

## Dominios y auditoría

| Método | Ruta | Rol | Descripción |
|---|---|---|---|
| POST | `/domains` | analyst, admin | Registra un dominio y devuelve dónde publicar la prueba de propiedad |
| GET | `/domains` | cualquiera con sesión | Dominios propios (el admin ve todos) |
| GET | `/domains/{id}` | dueño o admin | Detalle e instrucciones de verificación |
| POST | `/domains/{id}/verify` | dueño con rol analyst o admin | Comprueba la propiedad; pasa el dominio a `verified` |
| GET | `/audit` | admin | Bitácora, más reciente primero; filtros `user_id`, `action`, `before_id`, `limit` (máx. 200) |
| GET | `/audit/verify` | admin | Recorre la cadena de hashes y devuelve `intact` y `broken_at_id` |

Métodos de verificación: `dns_txt` (registro TXT en `_safeit-verify.<dominio>` con el token) y `file` (`/.well-known/safeit-<id>.txt` con el token como contenido). La verificación por archivo resuelve el DNS antes de conectar, rechaza cualquier dirección que no sea pública (loopback, privadas, link-local, metadata, CGNAT, IPv4 embebida en IPv6), se conecta a la IP ya validada, no sigue redirecciones y limita tiempo y tamaño de la respuesta. Un dominio verificado por una cuenta no puede verificarse en otra.

Registro y los eventos de dominio y de autenticación (login, login fallido, MFA, reutilización de refresh token, cambios de perfil) escriben en `audit_log`. La cadena de hashes la calcula el trigger de la base; la tabla rechaza `UPDATE`, `DELETE` y `TRUNCATE`.

Las cuentas nuevas son `viewer`: pueden listar pero no registrar dominios. Para subir el rol de una cuenta en una base local:

```
update public.users set role = 'analyst' where email = 'tu@correo.com';
```

## Pruebas contra PostgreSQL

Las pruebas de repositorios se omiten si no existe `TEST_DATABASE_URL`. Deben apuntar a una base vacía: cargan las migraciones `01` a `06` de `../bd/supabase/migrations` y limpian el esquema `public` al terminar. Si `public.users` ya existe, se omiten para no tocar datos. La `07` (RLS) y la `08` (semillas) no se cargan porque la `07` usa los roles de Supabase.

```
TEST_DATABASE_URL=postgresql://usuario:clave@localhost:5432/safeit_test uv run pytest tests/integration
```

## Estructura

```
app/
  domain/            entidades, reglas y errores; no importa nada de otras capas
  application/       puertos y casos de uso; solo importa domain
  infrastructure/    base de datos, seguridad, verificadores de dominio, logging y, más adelante, recon, LLM, feeds y cola
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
