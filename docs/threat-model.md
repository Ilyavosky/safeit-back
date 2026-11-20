# Modelo de amenazas de SafeIT

Alcance: la API (`SafeIT/back`), el worker de Celery, Redis, la base de datos en Supabase y el front en Vercel. El modelo usa STRIDE por frontera de confianza y enlaza cada mitigación con la prueba que la cubre.

## Activos

| Activo | Por qué importa |
|---|---|
| Credenciales, tokens de sesión y secretos TOTP | Permiten suplantar a un usuario |
| Evidencia de hallazgos y reportes | Describen debilidades de sistemas reales |
| Registro de auditoría encadenado | Es la prueba de quién hizo qué |
| Lista de dominios verificados y lista blanca de endpoints | Es lo que impide escanear sistemas ajenos |
| Clave de cifrado, `JWT_SECRET`, clave del LLM | Comprometerlas rompe todo lo anterior |

## Fronteras de confianza

1. Internet → Vercel → proxy `/api/*` → API en Railway (TLS terminado por la plataforma).
2. API → Redis (cola y límites de uso) y API → Supabase (PostgreSQL con RLS, sin acceso para `anon` ni `authenticated`).
3. Worker → sistemas objetivo. Es la frontera más delicada: ahí se ejecutan herramientas de terceros contra hosts que el usuario dice poseer.
4. API/Worker → proveedor del LLM. Todo lo que vuelve del objetivo es dato no confiable.
5. Worker → dominios ajenos en el análisis público. Solo lectura pasiva.

## STRIDE por componente

| Amenaza | Escenario | Mitigación | Prueba |
|---|---|---|---|
| Suplantación | Fuerza bruta o relleno de credenciales en login | Límite por IP y por correo en Redis; si Redis cae, el login rechaza | `tests/unit/test_rate_limit_redis.py` |
| Suplantación | JWT manipulado, firmado con otra clave, `alg=none` o expirado | Verificación estricta del algoritmo, emisor y tipo; el rol se lee de la base en cada petición | `tests/security/test_authorization.py` |
| Suplantación | Robo del refresh token | Rotación con detección de reutilización que revoca la familia; cookie `httpOnly` limitada a `/api/auth` | `tests/integration/test_auth_flow.py` |
| Manipulación | Alterar el registro de auditoría | Cadena de hashes con triggers que bloquean UPDATE y DELETE | `tests/security/test_audit_chain.py` |
| Manipulación | Inyección en el prompt desde banners o títulos de página | Datos envueltos como no confiables, esquema estricto de salida, lista cerrada de herramientas | `tests/security/test_prompt_injection.py` |
| Repudio | Un usuario niega haber lanzado un escaneo o análisis | Cada acción relevante queda en la cadena de auditoría; el análisis público registra la aceptación del aviso de uso | `tests/integration/test_public_analysis_api.py` |
| Divulgación | IDOR: leer dominios, escaneos o análisis de otro usuario | Las consultas validan propietario o rol admin y responden 404 | `tests/security/test_authorization.py`, `tests/integration/test_public_analysis_api.py` |
| Divulgación | Mensajes de error con trazas, o que revelen si un correo existe | Manejadores de errores uniformes y respuestas de login idénticas | `tests/security/test_error_leaks.py` |
| Divulgación | Lectura de datos desde la API REST de Supabase | RLS activo y permisos revocados para `anon` y `authenticated` | Migración 07 y 09 |
| Divulgación | Documentación de la API expuesta | `/docs` y `/openapi.json` desactivados con `ENVIRONMENT=prod` | `tests/unit/test_security_middleware.py` |
| Denegación de servicio | Peticiones enormes o ráfagas | Límite de tamaño de body (413) y límites por endpoint; un solo análisis activo por usuario y tope diario | `tests/unit/test_security_middleware.py`, `tests/integration/test_public_analysis_api.py` |
| Denegación de servicio | Análisis público que enumera miles de subdominios | Tope de 50 hosts, concurrencia 5 y tiempo máximo por tarea | `tests/integration/test_public_analysis_api.py` |
| Elevación | Un `viewer` ejecuta acciones de `analyst` o `admin` | `require_role` en cada ruta sensible; prueba que recorre todas las rutas y exige autenticación | `tests/security/test_route_protection.py` |
| Elevación | Escanear un dominio que no es del usuario | Verificación por DNS TXT o archivo; las pruebas exigen dominio verificado y endpoint en lista blanca | `tests/security/test_scope_enforcement.py` |

## Casos de abuso

**SSRF y DNS rebinding.** Un atacante registra un host que resuelve a una IP interna o que cambia de respuesta entre la comprobación y la conexión. Mitigación: toda conexión resuelve primero, exige que todas las direcciones sean públicas y conecta a la IP ya validada. Cubierto en `tests/security/test_scope_enforcement.py` y `tests/unit/test_public_infrastructure.py`.

**Uso del análisis público como herramienta de reconocimiento hostil.** El análisis público toca sistemas de terceros sin su permiso, por eso se limita a lo que haría un visitante normal:

- Una sola petición `GET /` por host, con `User-Agent` identificable.
- Fuentes de subdominios pasivas (Certificate Transparency y fuentes públicas de `subfinder`).
- Sin escaneo de puertos, sin plantillas de vulnerabilidades, sin pruebas de TLS agresivas.
- No se publican IPs, puertos ni versiones exactas; se muestra el proveedor o la CDN.
- El resumen del LLM describe, no evalúa vulnerabilidades ni sugiere ataques.
- Dominios `.gov`, `.mil`, internos y los propios de SafeIT quedan excluidos.
- Límite de 3 solicitudes por minuto, 5 análisis al día y uno activo por usuario.
- Los resultados caducan a los 30 días y se purgan de forma automática.

**Cuenta comprometida usada para escanear.** Un atacante con una cuenta válida solo puede escanear dominios verificados de esa cuenta. Los intentos fuera de alcance se registran como eventos de seguridad.

**Contenido hostil del objetivo hacia el LLM.** Cubierto arriba (prompt injection). El LLM nunca ejecuta herramientas por su cuenta: propone sobre una lista cerrada y el sistema valida.

## Riesgos residuales

- El worker ejecuta herramientas externas; un fallo en una de ellas podría afectar al contenedor. Se ejecutan sin privilegios, pero no hay aislamiento por escaneo.
- El proveedor del LLM recibe metadatos del objetivo (cabeceras, títulos, nombres de subdominio). Conviene un proveedor con política de no retención.
- Los secretos de producción se rotan manualmente. Pendiente: rotar la clave del LLM, `JWT_SECRET`, la contraseña de la base de datos y las cuentas de demostración antes de abrir el servicio.
- Beat embebido en el worker exige una sola réplica; con dos, las tareas diarias se duplicarían (son idempotentes).
- Detrás de Vercel y Railway la IP del cliente sale de `X-Forwarded-For` (uvicorn corre con `--proxy-headers`). Un cliente puede falsear esa cabecera para evadir el límite por IP; el límite por correo y por usuario sigue vigente. Si cambia la topología, hay que revisar `get_client_ip`.
- La suite de seguridad automatizada no sustituye una prueba de penetración externa.
