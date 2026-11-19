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

## Reconocimiento y activos

| Método | Ruta | Rol | Descripción |
|---|---|---|---|
| POST | `/domains/{id}/scans` | dueño o admin con rol analyst o admin | Crea un escaneo de reconocimiento y responde 202; el trabajo lo toma el worker de Celery |
| GET | `/scans/{id}` | dueño o admin | Estado: `queued`, `running`, `done` o `failed` |
| GET | `/assets?domain=<uuid>` | dueño o admin | Activos del dominio (subdominios e IP) |
| GET | `/assets/{id}` | dueño o admin | Activo con sus servicios y endpoints |
| POST | `/assets/{id}/rescan` | dueño o admin con rol analyst o admin | Vuelve a escanear solo ese subdominio |
| PUT | `/endpoints/{id}/whitelist` | dueño o admin con rol analyst o admin | Marca o desmarca un endpoint en alcance para las pruebas controladas |

Flujo: subfinder lista subdominios, se resuelve el DNS, nmap (`-sT`, 100 puertos, versiones) escanea las IP y httpx (con detección de tecnologías) prueba los hosts. Antes de registrar nada, cada host debe pertenecer al dominio verificado y resolver solo a direcciones públicas: si apunta a loopback, red privada, link-local o metadata se descarta y queda en la bitácora (`recon.asset_discarded`, máx. 50 por escaneo). Un solo escaneo activo por dominio (se garantiza con un candado en la base) y tope de `RECON_MAX_ASSETS`. Si pasa `RECON_TIMEOUT_SECONDS` el escaneo termina en `failed`; un escaneo que quedó colgado más del doble de ese tiempo se marca `failed` al pedir el siguiente. La tabla `scans` no tiene columna de motivo, así que el motivo del fallo (`timeout`, `error`, `domain_not_verified`, `queue_unavailable`) se guarda en `scan.recon_finished`. Si falta alguna herramienta, el escaneo sigue con lo que pudo y deja `warnings` en esa misma entrada.

Limitación conocida: "dirección ajena" significa no pública. Una IP pública de un tercero a la que apunte un subdominio verificado no se puede distinguir sin datos de propiedad, así que sí entra en alcance.

Los endpoints descubiertos quedan con `whitelisted = false`; hay que habilitarlos con el `PUT` de arriba antes de lanzar pruebas.

Cola y worker (Redis + Celery):

```
docker run -d --name safeit-redis -p 6379:6379 redis:7-alpine
uv run celery -A app.infrastructure.queue.tasks:celery_app worker --concurrency=2 --loglevel=INFO
```

Si Redis no responde, `POST /domains/{id}/scans` devuelve 503 (`queue_unavailable`), el escaneo queda `failed` y el dominio se libera. Para correr el worker aislado, `deploy/scanner/Dockerfile` instala nmap, subfinder, httpx (como `pd-httpx`), nuclei y testssl.sh con un usuario sin privilegios, y `deploy/docker-compose.yml` levanta Redis y el worker con sistema de archivos de solo lectura, sin capacidades extra y con límites de CPU, memoria y procesos. Las versiones de las herramientas están fijadas en el Dockerfile pero la imagen no se construyó en el entorno de desarrollo; compruébalas al hacer el primer `docker compose build`. La prueba `tests/integration/test_recon_live.py` (marca `slow`) corre contra un objetivo real propio: `SAFEIT_LIVE_TARGET=lab.tudominio.com uv run pytest -m slow`.

## Catálogo CVE y puntaje de riesgo

| Método | Ruta | Rol | Descripción |
|---|---|---|---|
| GET | `/cves/{cve_id}` | cualquiera con sesión | CVSS, vector, EPSS, pertenencia a CISA KEV y `priority_score`; si el CVE no está en el catálogo se consulta en NVD y se guarda |

El catálogo se llena con los CVE de CISA KEV (NVD con `hasKev`), los consultados bajo demanda y los que aún no tienen CVSS (hasta `CVE_SYNC_MAX_LOOKUPS`). EPSS se consulta en lotes de 100 y KEV se lee del JSON de CISA con caché de una hora. Preferencia de CVSS: v3.1, v3.0, v4.0 y v2. Sin `NVD_API_KEY` se espera 6 s entre peticiones; con clave, 0,7 s.

```
uv run python -m scripts.sync_cve_catalog
```

La sincronización es idempotente (no toca filas sin datos nuevos) y, si un feed falla, deja un aviso en el log y conserva el catálogo existente. La sincronización periódica con Celery beat no está programada todavía; por ahora se corre el script a mano o con cron.

Fórmula: `priority_score = min(100, CVSS × 10 + EPSS × 20)`, con piso de 90 si está en KEV y vacío si no hay ningún dato.

## Pruebas controladas

| Método | Ruta | Rol | Descripción |
|---|---|---|---|
| POST | `/domains/{id}/tests` | dueño o admin con rol analyst o admin | Encola las pruebas y responde 202 con el escaneo |
| GET | `/scans/{id}` | dueño o admin | Estado del escaneo |
| GET | `/scans/{id}/test-runs` | dueño o admin | Ejecuciones por herramienta |
| GET | `/scans/{id}/findings` | dueño o admin | Hallazgos ordenados por prioridad (sin la evidencia cifrada) |

Solo se prueban endpoints marcados `whitelisted` cuyo activo está `in_scope`, de un dominio verificado. El planificador es fijo: `headers` para cada endpoint, `testssl` una vez por host HTTPS y `nuclei` con las etiquetas `cve`, `exposure`, `misconfig`, `tech`. Los parámetros se validan contra `allowed_tools`: nuclei rechaza etiquetas fuera de la lista o en la lista negra (`dos`, `intrusive`, `fuzz`, `bruteforce`) y limita la tasa a 50. Los procesos se lanzan sin shell, con argumentos fijos y sin heredar variables de entorno sensibles; `headers` conecta solo a IP públicas ya resueltas. Resultados y evidencia se guardan cifrados (AES-GCM).

Si una herramienta no está instalada, esa ejecución queda en `failed` y el resto sigue. Rutas de los binarios: `NUCLEI_BIN` y `TESTSSL_BIN`.

Los endpoints salen del reconocimiento. Para registrar uno a mano sin correr el recon:

```
uv run python -m scripts.seed_lab_target --domain-id <uuid> --url https://lab.tudominio.com/
```

Severidad base cuando el hallazgo no trae CVE: info 5, low 20, medium 45, high 70, critical 90. Con CVE, se usa el mayor `priority_score` de sus CVE.

## Pipeline de LLM

Tras las pruebas, el mismo job analiza los hallazgos y genera el reporte. El modelo propone y el sistema valida: nada de lo que devuelve se ejecuta ni se guarda sin pasar por las reglas del dominio.

| Paso | Qué propone el modelo | Qué valida el sistema |
|---|---|---|
| Plan | pruebas por endpoint | herramienta activa en `allowed_tools`, parámetros dentro de la política, endpoint en lista blanca y en alcance; si falla, se usa el planificador fijo |
| Correlación | CVE por hallazgo | solo CVE que existen en `cve_catalog`; el resto se descarta y se recalcula la prioridad |
| Falsos positivos | veredicto con justificación | sin justificación no se guarda |
| Reporte | resumen y acciones | solo hallazgos del escaneo, una acción por hallazgo, prioridades ordenadas por el sistema |

Cada llamada queda en `llm_decisions` (modelo, hash de entrada, salida JSON, `validated`). Banners, cabeceras y evidencia viajan dentro de `<datos_no_confiables>` con un límite aleatorio, truncados y sin caracteres de control, y nunca en el mensaje de sistema. Los prompts están en `app/infrastructure/llm/prompts/`.

Variables: `LLM_API_KEY`, `LLM_MODEL`, `LLM_BASE_URL`, `LLM_MAX_TOKENS_PER_SCAN`, `LLM_REQUEST_TIMEOUT_SECONDS`, `LLM_STEP_TIMEOUT_SECONDS`. Sin `LLM_API_KEY` y `LLM_MODEL` el sistema funciona con el planificador fijo y un reporte de respaldo. La suite usa `FakeLlmGateway`, sin red ni clave.

## Hallazgos, reportes y dashboard

| Método | Ruta | Rol | Descripción |
|---|---|---|---|
| GET | `/findings` | cualquiera | Listado con `severity`, `status`, `asset_id`, `domain_id`, `scan_id`, `sort` (`priority` o `detected`), `cursor` y `limit` (máx. 100) |
| GET | `/findings/{id}` | cualquiera | Detalle |
| PATCH | `/findings/{id}/status` | analyst, admin | Cambia `open`, `in_progress`, `fixed`; reabrir un resuelto exige `reason` |
| GET | `/reports/{scanId}` | cualquiera | Resumen, cifras por severidad y recomendaciones por prioridad |
| GET | `/reports/{scanId}/pdf` | cualquiera | PDF con resumen ejecutivo, gráfica por severidad y recomendaciones |
| PATCH | `/recommendations/{id}` | analyst, admin | `pending`, `in_progress`, `done`, `dismissed` |
| GET | `/dashboard/summary` | cualquiera | Conteos por severidad, activos, escaneos y últimos hallazgos (`scan_id` o `domain_id` opcionales) |

El campo `status` de un hallazgo se calcula: `discovered` (escaneo en curso), `in_analysis` (escaneo terminado sin reporte), `confirmed`, `false_positive`, `in_remediation` y `resolved`. Los conteos excluyen falsos positivos y son los mismos en el reporte, el PDF y el dashboard. Sin `scan_id`, el dashboard usa el último escaneo de pruebas terminado de cada dominio. Los recursos de otro usuario responden 404.

El OpenAPI para el frontend se genera con `uv run python -m scripts.export_openapi` (escribe `openapi.json`).

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
  infrastructure/    base de datos, seguridad, verificadores de dominio, feeds de CVE, ejecutores de herramientas, recon, cola de Celery, cliente y prompts del LLM, PDF de reportes y logging
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
