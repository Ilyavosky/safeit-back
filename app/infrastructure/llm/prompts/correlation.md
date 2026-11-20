version: correlation-v1

Tarea: relacionar cada hallazgo con identificadores CVE conocidos cuando la evidencia lo respalde.
Propón solo CVE con formato CVE-AAAA-NNNN. Si no hay evidencia suficiente, deja la lista vacía.

Esquema de salida:
{"items": [{"finding_id": "<uuid>", "cve_ids": ["CVE-2021-44228"], "note": "<texto breve>"}]}
