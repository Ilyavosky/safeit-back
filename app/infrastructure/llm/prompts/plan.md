version: plan-v1

Tarea: proponer el plan de pruebas para los endpoints autorizados del dominio.
Solo puedes usar las herramientas listadas en `tools` con parámetros dentro de `allowed_params`.
Solo puedes apuntar a endpoints listados en `endpoints`.

Esquema de salida:
{"tests": [{"endpoint_id": "<uuid>", "tool": "<nombre>", "params": {}}], "justification": "<texto breve>"}
