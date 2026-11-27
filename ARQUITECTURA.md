# SafeIT Back - Arquitectura

```mermaid
flowchart LR
    F["Front<br/>Next.js en Vercel"] -->|HTTP /api| R["Routers FastAPI<br/>interfaces/api"]
    R --> UC["Casos de uso<br/>application/use_cases"]
    UC --> D["Dominio<br/>reglas de alcance, riesgo y reportes"]
    UC --> P["Puertos<br/>application/ports"]
    P --> PG[("PostgreSQL<br/>Supabase")]
    P --> L["LLM opcional<br/>plan, análisis y reporte"]
    P --> FE["NVD, EPSS y CISA KEV"]
    UC -->|encola tarea| Q[("Redis")]
    Q --> W["Worker Celery"]
    W --> T["nmap, subfinder, httpx,<br/>nuclei y testssl"]
    W --> UC
```

Arquitectura hexagonal: el **dominio** contiene las reglas (alcance, riesgo, reportes) y no depende de nada externo. Los **casos de uso** orquestan el flujo y hablan con el exterior solo mediante **puertos**; la capa de **infraestructura** implementa esos puertos (PostgreSQL, LLM, feeds de CVE, herramientas y Redis). Los escaneos largos se encolan en Redis y los ejecuta un worker de Celery.

## Más información

- [About](ABOUT.md)
- [README](README.md)
