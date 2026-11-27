# SafeIT Back - About

**Descripción corta (campo About de GitHub):** API de SafeIT: reconocimiento y pruebas de seguridad controladas con FastAPI, Celery y LLM opcional

## Qué es

API de **SafeIT** con arquitectura hexagonal. Verifica la propiedad de los dominios, hace reconocimiento, ejecuta pruebas solo sobre endpoints autorizados y en lista blanca, prioriza hallazgos con CVSS, EPSS y CISA KEV, y genera reportes con apoyo opcional de un modelo de lenguaje.

## Tecnologías

- Python 3.13 y FastAPI
- PostgreSQL (Supabase) con psycopg
- Celery y Redis para tareas en segundo plano
- nmap, subfinder, httpx, nuclei y testssl
- argon2, JWT y MFA (TOTP)
- ReportLab para el PDF
- pytest, mypy y ruff

## Qué incluye

- Verificación de dominio por registro TXT
- Reconocimiento y pruebas controladas con política de herramientas
- Plan de pruebas con IA, validado por reglas del dominio
- Catálogo de CVE con NVD, EPSS y CISA KEV
- Reportes con resumen ejecutivo y PDF
- Auditoría encadenada por hash y límites de uso

## Proyecto completo

SafeIT se divide en tres repositorios: [safeit-front](https://github.com/Ilyavosky/safeit-front) (interfaz) y [safeit-bd](https://github.com/Ilyavosky/safeit-bd) (base de datos), además de [safeit-lab](https://github.com/Ilyavosky/safeit-lab), con objetivos de práctica ficticios.

Proyecto de la materia Seguridad Informática (periodo 263), UPCH. Autores: Ilya Cortés Ruiz y Brittany Aurora Hernández Muñoz.

## Más información

- [Arquitectura](ARQUITECTURA.md)
- [README](README.md)
