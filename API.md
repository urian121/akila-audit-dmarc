# API de Akila-DMARC

Todos los datos que ya muestra la aplicación (checker, monitoreo, tendencias, cumplimiento,
informes, cuenta) también están disponibles como JSON, para consumirlos desde un script, otro
backend, o un frontend propio (React, Next.js, o sin ningún framework). No reemplaza a la app web
— es una capa aparte que reusa exactamente los mismos cálculos.

Ver `API_PLAN.md` si te interesa el plan/decisiones de diseño detrás de esto; este archivo es la
referencia para consumir los endpoints ya construidos.

## Base URL

```
https://tu-dominio-de-despliegue/api/v1/...
```

(en local, `http://127.0.0.1:5000/api/v1/...`). Un solo endpoint vive fuera de `/api/v1/`, por
compatibilidad con el checker público que ya existía antes de esta API: `GET /api/check/<domain>`.

## Autenticación

Todo endpoint bajo `/api/v1/` (salvo que se aclare lo contrario) requiere una **API key** en el
header `Authorization`:

```
Authorization: Bearer <tu_api_key>
```

**No es self-service.** Un cliente no puede generar su propia key desde su cuenta — solo un
administrador la genera en su nombre, desde el panel de usuarios (`/admin/usuarios/<id>/plan`), y
se la tiene que hacer llegar por fuera de la aplicación. Se muestra en texto plano **una sola vez**
en el momento de generarla; después sólo queda guardado su hash, no se puede volver a ver. Generar
una nueva invalida la anterior al instante (una key por cuenta).

Si falta el header o la key no es válida (no existe, está desactivada, o la cuenta entera está
desactivada), toda ruta de `/api/v1/` responde:

```http
401 Unauthorized
```
```json
{ "error": "Falta el header Authorization: Bearer <api_key>." }
```
o
```json
{ "error": "API key inválida, desactivada, o cuenta desactivada." }
```

El único endpoint sin autenticación es el checker público, `GET /api/check/<domain>` — pensado
para integrarse sin cuenta, igual que ya funcionaba antes de esta API (ver más abajo, incluye rate
limit).

## Convenciones

**Dueño de un dominio**: cualquier endpoint `/api/v1/dominios/<access_token>/...` sólo devuelve
datos si ese dominio pertenece a la cuenta dueña de la API key usada (o si esa cuenta es admin —
los admins pueden ver cualquier dominio). Si el token no existe, o existe pero es de otra cuenta,
la respuesta es la misma en ambos casos — **404**, nunca 403 — para no confirmar ni negar que un
token ajeno existe:

```http
404 Not Found
```
```json
{ "error": "No se encontró ese dominio." }
```

**Paginación**: todo endpoint que lista una tabla (remitentes, alertas, informes, usuarios, etc.)
devuelve siempre la misma forma:

```json
{
  "items": [ /* ... */ ],
  "total_items": 42,
  "page": 1,
  "total_pages": 3
}
```

`page` se lee de `?page=N` (default 1). Fuera de rango se ajusta solo al límite válido (nunca da
error por una página inexistente).

**Rango de fechas**: los endpoints que aceptan `?rango=` usan `7d`/`30d`/`90d` (algunos también
aceptan `todos`, para sin límite de fecha — se aclara endpoint por endpoint). Un valor inválido cae
solo a `30d`, nunca da error.

**Fechas en las respuestas**: siempre ISO 8601 (`"2026-08-18T14:30:00+00:00"`), nunca otro formato.

---

## Cuenta

### `GET /api/check/<domain>`

Sin autenticación, público a propósito — audita un dominio en vivo (SPF/DMARC/DKIM/MX/DNSSEC/
MTA-STS/TLS-RPT/BIMI) y devuelve el resultado completo, igual que el checker de la página
principal. No guarda nada. **Rate limit: 10 requests por minuto por IP** — al superarlo:

```http
429 Too Many Requests
```
```json
{ "error": "Demasiadas consultas — probá de nuevo en un minuto." }
```

Parámetro opcional: `?selector=` (selector DKIM adicional a probar, adelante de los que ya se
detectan solos).

### `GET /api/v1/me`

Info de la cuenta dueña de la API key — también sirve para probar que la key funciona.

```json
{
  "id": 12,
  "name": "Nombre de la cuenta",
  "email": "cliente@ejemplo.com",
  "is_admin": false,
  "created_at": "2026-06-01T10:00:00+00:00",
  "plan": {
    "max_domains": 5,
    "expires_at": null,
    "plan": { "name": "paid", "label": "Pago", "max_domains": 5, "price_usd": 12.0, "trial_days": null }
  },
  "plan_max_domains": 5,
  "domains_used": 2
}
```

`plan` es `null` si la cuenta usa el límite default (nunca tuvo un plan propio asignado).
`plan_max_domains` es el número que de verdad se hace cumplir (`null` = sin límite, sólo en
cuentas admin) — puede no coincidir con `plan.max_domains` si el plan ya venció (vuelve solo al
default) o si nunca tuvo un plan del catálogo asignado.

---

## Dominios

### `GET /api/v1/dominios`

Lista los dominios monitoreados de la cuenta.

```json
{
  "dominios": [
    {
      "id": 8, "domain": "tudominio.com", "access_token": "xxxxxxxx",
      "is_active": true, "dns_verified": true, "dns_verified_at": "2026-07-21T14:41:34+00:00",
      "tls_rpt_verified": false, "tls_rpt_verified_at": null,
      "created_at": "2026-07-16T22:17:02+00:00"
    }
  ]
}
```

### `GET /api/v1/dominios/<access_token>`

Dashboard completo de un dominio: alertas recientes (hasta 50), informes DMARC agregados
recientes (hasta 20) y reportes forenses recientes (hasta 20).

```json
{
  "dominio": { "id": 8, "domain": "tudominio.com", "...": "..." },
  "alertas": [
    { "id": 3, "kind": "unknown_sender", "kind_label": "Remitente desconocido",
      "message": "Correo enviado desde ... que no está en el SPF declarado.",
      "related_ip": "35.174.145.124", "created_at": "2026-07-17T09:25:19+00:00", "notified_at": null }
  ],
  "informes": [
    { "id": 14, "org_name": "outlook.com", "report_id": "e5d3af44...",
      "date_begin": "2026-07-15T00:00:00+00:00", "date_end": "2026-07-16T00:00:00+00:00",
      "received_at": "2026-07-17T02:45:57+00:00" }
  ],
  "forenses": []
}
```

`forenses` casi siempre viene vacío — muchos proveedores grandes (Gmail, Yahoo) ya no mandan
reportes forenses por temas de privacidad; no es un problema de la app.

### `GET /api/v1/dominios/<access_token>/remitentes`

Tabla paginada de remitentes reales (IPs que enviaron correo en nombre del dominio), agrupados,
con su tasa de SPF/DKIM.

Query params: `rango` (`7d`/`30d`/`90d`/`todos`, default `30d`), `estado`
(`todos`/`con_fallas`/`sin_fallas`), `q` (busca por IP u organización), `page`.

```json
{
  "items": [
    { "source_ip": "209.85.210.175", "source_asn_org": "Google", "source_country": "US",
      "total": 1500, "spf_pass": 1500, "spf_fail": 0, "spf_rate": 100.0,
      "dkim_pass": 1480, "dkim_fail": 20, "dkim_rate": 98.7,
      "first_seen": "2026-07-15T00:00:00+00:00", "last_seen": "2026-08-01T00:00:00+00:00",
      "has_failures": false }
  ],
  "total_items": 1, "page": 1, "total_pages": 1
}
```

### `GET /api/v1/dominios/<access_token>/alertas`

Tabla paginada de alertas (cambios de configuración detectados, o remitentes desconocidos —
agrupados por organización). Query params: `rango` (`7d`/`30d`/`90d`/`todos`, default `30d`),
`tipo` (`todos`/`remitente_desconocido`/`cambio_configuracion`), `q`, `page`.

```json
{
  "items": [
    { "kind": "unknown_sender", "kind_label": "Remitente desconocido",
      "detail": "Check Point Avanan", "ips": ["35.174.145.124"], "count": 3,
      "last_seen": "2026-08-01T09:25:19+00:00" }
  ],
  "total_items": 1, "page": 1, "total_pages": 1
}
```

### `GET /api/v1/dominios/<access_token>/impacto/afectados`

Tabla paginada de los emisores que se verían afectados si hoy se pasara a bloquear/poner en
cuarentena el correo que falla DMARC. Query params: `rango` (`7d`/`30d`/`90d`, **sin** `todos`,
default `30d`), `q`, `page`.

```json
{
  "items": [
    { "source_ip": "9.9.9.9", "source_asn_org": "Desconocido", "count": 12 }
  ],
  "total_items": 1, "page": 1, "total_pages": 1
}
```

### `GET /api/v1/dominios/<access_token>/subdominios`

Desglose de volumen/cumplimiento agrupado por el dominio o subdominio real que aparece en el
correo (`facturacion.tudominio.com` puede reportar aparte de `tudominio.com`). Query params:
`rango` (`7d`/`30d`/`90d`, default `30d`).

```json
{
  "subdominios": [
    { "name": "tudominio.com", "total": 1500, "pass": 1480, "fail": 20, "compliance_rate": 98.7 },
    { "name": "facturacion.tudominio.com", "total": 40, "pass": 10, "fail": 30, "compliance_rate": 25.0 }
  ]
}
```

### `GET /api/v1/dominios/<access_token>/tendencias`

Volumen pass/fail día por día + tasa de cumplimiento, para graficar en el tiempo. Query params:
`rango` (`7d`/`30d`/`90d`, default `30d`).

```json
{
  "labels": ["2026-07-19", "2026-07-20", "..."],
  "pass_series": [120, 98, "..."],
  "fail_series": [3, 5, "..."],
  "compliance_series": [97.6, 95.1, "..."],
  "has_data": true,
  "total_pass": 1480, "total_fail": 20, "total": 1500, "pass_rate": 98.7,
  "dmarc_policy": "quarantine",
  "period_label": "agosto 2026"
}
```

Un día sin ningún reporte recibido queda en `compliance_series: null` ese día (no `0`) — no hay
evidencia de que algo falló, sólo de que no hubo/no llegó tráfico que medir.

### `GET /api/v1/dominios/<access_token>/impacto`

Estado actual y análisis de qué pasaría si se refuerza la política DMARC (sin la tabla de
afectados, que es el endpoint de arriba). Query params: `rango` (`7d`/`30d`/`90d`, default `30d`).

```json
{
  "has_data": true, "total_reports": 12, "total_messages": 1500, "total_fail": 20,
  "pass_rate": 98.7, "unique_sources": 4,
  "current_policy": "quarantine", "policy_step": 1, "ready_to_enforce": true
}
```

`ready_to_enforce`: `true` si el `pass_rate` ya alcanza el 95% — umbral único de "cumplimiento" en
toda la app (mismo que usan `/cumplimiento` e `/informes-dmarc`).

### `GET /api/v1/dominios/<access_token>/analisis-ia`

Análisis de salud DMARC generado con IA, en lenguaje llano. Query params: `rango` (`7d`/`30d`/
`90d`, default `30d`).

```json
{
  "analisis": {
    "health_score": 80,
    "verdict": "bueno",
    "summary": "El dominio está bien encaminado...",
    "strengths": ["SPF y DKIM alinean en la mayoría del tráfico"],
    "needs_attention": ["Hay un remitente sin declarar en el SPF"],
    "critical": []
  }
}
```

`analisis` es `null` si no hubo tráfico en el período elegido, o si la IA no está configurada
(falta `OPENAI_PROJECT_API_KEY`) o falla — se degrada sola, el resto de la API sigue funcionando
igual.

---

## Cross-dominio (todas las cuentas monitoreadas juntas)

### `GET /api/v1/cumplimiento`

Cumplimiento de TODOS los dominios de la cuenta, de un vistazo — igual que la tabla de
`/cumplimiento`, sin el chequeo de DNS en vivo (eso es sólo para la UI). Query params: `rango`
(`7d`/`30d`/`90d`, default `30d`).

```json
{
  "dominios": [
    {
      "dominio": { "id": 8, "domain": "tudominio.com", "...": "..." },
      "current_policy": "quarantine", "policy_label": "Cuarentena",
      "pass_rate": 98.7, "total": 1500, "status": "ok"
    }
  ]
}
```

`status`: `"ok"` (política ≥ cuarentena y pass_rate ≥ 95%), `"attention"` (no cumple ese criterio,
pero sí hubo tráfico) o `"no_data"` (sin tráfico en el período — no es una falla, sólo falta
evidencia).

### `GET /api/v1/informes-dmarc`

Lista paginada de todos los informes DMARC agregados de la cuenta, de todos sus dominios juntos.
Query params: `rango` (`7d`/`30d`/`90d`/`todos`, default `30d`), `estado`
(`todos`/`aprobado`/`con_fallas`), `q` (busca por reportero, dominio o ID de informe), `page`.

```json
{
  "items": [
    {
      "informe": { "id": 14, "org_name": "outlook.com", "report_id": "e5d3af44...", "...": "..." },
      "dominio": { "id": 8, "domain": "tudominio.com", "...": "..." },
      "domain_shown": "tudominio.com", "total": 1500, "compliance_rate": 98.7
    }
  ],
  "total_items": 1, "page": 1, "total_pages": 1
}
```

### `GET /api/v1/informes-dmarc/<id>`

Detalle de un informe puntual: metadata + desglose SPF/DKIM + todos sus registros.

```json
{
  "informe": { "id": 14, "org_name": "outlook.com", "...": "..." },
  "dominio": { "id": 8, "domain": "tudominio.com", "...": "..." },
  "domain_shown": "tudominio.com",
  "registros": [
    { "id": 62, "source_ip": "209.85.210.175", "source_country": "US", "source_asn": "15169",
      "source_asn_org": "Google", "count": 1, "disposition": "none",
      "dkim_aligned": true, "spf_aligned": true, "dmarc_aligned": true, "header_from": "tudominio.com" }
  ],
  "total": 1500, "compliance_rate": 98.7,
  "only_spf": 5, "only_dkim": 10, "both_failed": 5
}
```

`only_spf`/`only_dkim`: mensajes que sólo alinearon uno de los dos (igual pasan DMARC, que es OR).
`both_failed`: ninguno de los dos alineó — estos sí fallan DMARC de verdad.

### `GET /api/v1/tls-rpt`

Estado de verificación DNS de TLS-RPT de los dominios de la cuenta. Query params: `estado`
(`todos`/`verificado`/`no_verificado`).

```json
{ "dominios": [ { "id": 8, "domain": "tudominio.com", "tls_rpt_verified": true, "...": "..." } ] }
```

---

## Admin

Sólo responden si la API key es de una cuenta con `is_admin=true` — 404 (no 403) para cualquier
otra cuenta, mismo criterio de "no confirmar que la ruta existe" que el resto de la API.

### `GET /api/v1/admin/usuarios`

Lista paginada de todas las cuentas de la aplicación. Query params: `rol`
(`todos`/`admin`/`cliente`), `estado` (`todos`/`activos`/`inactivos`), `q`, `page`.

```json
{
  "items": [
    {
      "usuario": { "id": 7, "name": "Cliente Demo", "email": "demo@ejemplo.com", "...": "..." },
      "domain_count": 2, "plan_max_domains": 5,
      "plan_expires_label": null, "plan_is_expired": false, "plan_label": "Pago"
    }
  ],
  "total_items": 1, "page": 1, "total_pages": 1
}
```

### `GET /api/v1/admin/usuarios/<id>`

Detalle de una cuenta puntual: perfil + plan + estado de su API key.

```json
{
  "id": 7, "name": "Cliente Demo", "email": "demo@ejemplo.com", "is_admin": false,
  "created_at": "2026-06-01T10:00:00+00:00", "plan": { "...": "..." },
  "is_active": true, "has_api_key": true, "api_key_active": true,
  "domains_used": 2,
  "plan_form": { "max_domains": 5, "expires_at_input": "", "is_expired": false, "plan_label": "Pago" }
}
```

---

## Lo que NO cubre esta API (todavía)

- Sólo lectura — no se puede registrar un dominio, activar/desactivar, ni cambiar un plan por API.
  Si hace falta, es una fase aparte (ver `API_PLAN.md`), no asumir que existe.
- No hay endpoint para generar/gestionar la propia API key — eso siempre lo hace un admin desde
  `/admin/usuarios/<id>/plan`, nunca la propia cuenta.
