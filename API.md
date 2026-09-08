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

Además de los datos crudos de DNS (`spf`, `dmarc`, `dkim`, `mx`, `dnssec`, `mta_sts`,
`smtp_tls_reporting`, `bimi`, `ns`, `soa`), la respuesta incluye:

```json
{
  "...": "... (campos crudos de DNS) ...",
  "cards": [
    { "title": "SPF", "status": "ok", "badge_label": "OK", "kind": "spf",
      "help_text": "Define qué servidores pueden enviar correos en nombre de este dominio.",
      "record": "v=spf1 include:_spf.google.com mx -all",
      "mechanisms": [{ "prefix": "Incluye reglas de", "value": "_spf.google.com", "suffix": "" }],
      "all_explanation": "Los demás servidores son rechazados (-all) — la opción más estricta.",
      "warnings": [] },
    { "title": "DANE", "status": "ok", "kind": "dane",
      "help_text": "Ata el certificado TLS de tus servidores de correo a un registro DNS (TLSA)...",
      "hosts": [{ "hostname": "aspmx.l.google.com", "has_tlsa": false, "dnssec": true }] },
    "...": "... (una tarjeta por protocolo, mismo formato que /api/v1/dominios/<token>/protocolo)"
  ],
  "risks": [
    { "title": "DMARC", "severity": "Media", "mitigation": "Sube la política DMARC a cuarentena o rechazo cuando estés listo — hoy sólo está en modo monitoreo, no bloquea nada." },
    { "title": "TLS-RPT", "severity": "Baja", "mitigation": "Opcional: publica TLS-RPT para que te avisen si falla el cifrado del correo entrante.",
      "dns_example": { "host": "_smtp._tls.tudominio.com", "type": "TXT", "value": "v=TLSRPTv1; rua=mailto:tls-reports@tudominio.com" } }
  ],
  "summary": {
    "ok": 4, "warn": 6, "fail": 0, "total": 10,
    "ok_pct": 40, "warn_pct": 60, "fail_pct": 0,
    "score": 70, "score_color": "text-amber-600"
  },
  "ai_summary": "El dominio tiene una buena protección general, pero hay áreas que necesitan atención..."
}
```

`cards`: una tarjeta por protocolo evaluado (10 en total, incluye DANE), con `status`
(`ok`/`warn`/`fail`/`na`) ya resuelto y una explicación en lenguaje simple (`help_text`) — mismo
formato exacto que devuelve `GET /api/v1/dominios/<access_token>/protocolo` para un dominio ya
registrado. Los campos extra varían según `kind` (`spf`, `dmarc`, `dkim`, `mx`, `dane`, `record`,
`text`, `list`, `error`, `empty`).

`risks`: solo las tarjetas en `warn`/`fail` (las que están `ok` no traen riesgo), con `severity`
(`Alta`/`Media`/`Baja`) y una acción concreta a tomar (`mitigation`). Algunas incluyen
`dns_example` (host/tipo/valor) con un registro de ejemplo para publicar, a modo de plantilla —
no es un valor real, hay que adaptarlo (ver `rua`/`ruf` con la casilla propia del dominio).

`summary`: conteo de protocolos en ok/advertencia/falla + `score` (0-100, igual al que muestra la
barra de salud del checker — una advertencia pesa la mitad que un ok, una falla no suma nada).
`ai_summary` es el mismo resumen en lenguaje llano que genera la IA para la página del checker —
`null` si la IA no está configurada (falta `OPENAI_PROJECT_API_KEY`) o falla; se degrada sola, el
resto de la respuesta sigue igual.

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
      "created_at": "2026-07-16T22:17:02+00:00", "alert_count": 3
    }
  ]
}
```

`alert_count`: total histórico de alertas de ese dominio (cambios de config + remitentes
desconocidos), no solo las no leídas/no notificadas — para el detalle real usar
`.../alertas` o el dashboard del dominio (`GET /api/v1/dominios/<access_token>`).

### `POST /api/v1/dominios`

Registra un dominio nuevo para monitoreo bajo la cuenta dueña de la API key — equivalente al
formulario de `/monitoreo`, pero sin sesión. Si el dominio ya estaba registrado por la misma
cuenta pero inactivo, lo reactiva en vez de duplicarlo (respeta el límite de dominios activos
del plan en ambos casos).

Body (JSON):
```json
{ "domain": "tudominio.com", "owner_email": "correo@donde-recibir-alertas.com" }
```
`owner_email` es opcional — si falta, usa el email de la cuenta dueña de la API key.

```json
{ "dominio": { "id": 9, "domain": "tudominio.com", "access_token": "xxxxxxxx", "...": "..." } }
```

`201` si se creó un registro nuevo, `200` si reactivó uno existente. Errores:
- `400` — dominio inválido o vacío.
- `409` — el dominio ya está siendo monitoreado por **otra** cuenta.
- `403` — la cuenta ya alcanzó el límite de dominios activos de su plan.

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
  "policy_label": "Cuarentena",
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
  "current_policy": "quarantine", "current_policy_label": "Cuarentena",
  "policy_step": 1, "ready_to_enforce": true
}
```

`ready_to_enforce`: `true` si el `pass_rate` ya alcanza el 95% — umbral único de "cumplimiento" en
toda la app (mismo que usan `/cumplimiento` e `/informes-dmarc`).

### `GET /api/v1/dominios/<access_token>/protocolo`

Estado de cada protocolo (chequeo DNS **en vivo**, no cacheado) — el mismo cálculo que arma el
grid de tarjetas de `/tendencias/<token>` en la web, con el status (`ok`/`warn`/`fail`) ya resuelto
por protocolo, incluido DANE (no está en `/api/check/<domain>`, que trae los datos crudos sin
status pre-calculado).

```json
{
  "protocolos": [
    { "title": "DNSSEC", "status": "ok", "badge_label": "OK", "badge_cls": "...", "kind": "text", "text": "..." },
    { "title": "SPF", "status": "ok", "badge_label": "OK", "badge_cls": "...", "kind": "spf", "record": "v=spf1 ..." },
    { "title": "DMARC", "status": "warn", "...": "..." },
    { "title": "DKIM", "status": "ok", "...": "..." },
    { "title": "MX", "status": "ok", "kind": "mx", "hosts": ["..."] },
    { "title": "DANE", "status": "ok", "kind": "dane", "hosts": ["..."] },
    { "title": "MTA-STS", "status": "ok", "...": "..." },
    { "title": "TLS-RPT", "status": "ok", "...": "..." },
    { "title": "BIMI", "status": "warn", "...": "..." },
    { "title": "Nameservers", "status": "ok", "kind": "list", "...": "..." }
  ]
}
```

Cada tarjeta trae `title`, `status` (`ok`/`warn`/`fail`/`na`), `badge_label`, `badge_cls`,
`help_text` y campos extra según `kind` (`record`, `message`, `hosts`, `warnings`, `text`, etc.) —
mismos campos que usa la plantilla HTML, sin transformar.

### `GET /api/v1/dominios/<access_token>/dns`

Instrucciones de DNS a publicar — equivalente a `/monitoreo/<token>/configuracion-dns` en la web.
Sólo lectura, no persiste nada. No repite `dns_verified`/`tls_rpt_verified` (eso ya viene en el
dominio de `GET /api/v1/dominios/<access_token>` — no hace falta pedirlo dos veces).

```json
{
  "dns": {
    "host": "_dmarc.tudominio.com",
    "type": "TXT",
    "value": "v=DMARC1; p=none; rua=mailto:postmaster@tudominio.com,mailto:reports@akila.io; pct=25; adkim=r; aspf=r;",
    "has_existing_record": true,
    "policy": { "p": "none", "sp": "", "pct": 25, "adkim": "r", "aspf": "r" },
    "rua": "mailto:postmaster@tudominio.com,mailto:reports@akila.io",
    "ruf": "mailto:postmaster@tudominio.com,mailto:reports@akila.io"
  },
  "extra_dns": {
    "spf": { "record": "v=spf1 include:_spf.google.com ~all" },
    "tls_rpt": {
      "host": "_smtp._tls.tudominio.com",
      "type": "TXT",
      "value": "v=TLSRPTv1; rua=mailto:reports@akila.io",
      "has_existing_record": false
    },
    "bimi": { "record": null },
    "mta_sts": { "record": null }
  }
}
```

`dns.policy`/`dns.rua`/`dns.ruf` son las piezas sueltas del valor ya armado en `dns.value` — sirven
para que el consumidor arme una vista previa interactiva (cambiar `p`/`sp`/`pct`/`adkim`/`aspf`) sin
volver a golpear este endpoint por cada cambio; la fórmula es la misma que usa
`utils/dmarc_builder.build_dmarc_value()`. `p`/`pct`/`adkim`/`aspf` siempre arrancan en el valor
conservador (`none`/25%/relajado) sin importar la política que el dominio tenga publicada hoy — es
un generador de un valor nuevo, no un espejo del registro existente.

Si `extra_dns.spf.record` es `null` (el dominio no tiene SPF), se agrega `extra_dns.spf.provider`
con `{ "hosts": [...], "label": "Google Workspace / Gmail" | null, "include": "include:_spf.google.com" | null }`,
detectado a partir de sus MX — heurística no oficial, sólo un punto de partida.

### `POST /api/v1/dominios/<access_token>/verificar-dns`

Vuelve a consultar el DNS en vivo y guarda si ya se publicó la casilla de monitoreo (`reports@`) en
el `rua=` de DMARC — botón "Verificar de nuevo" de la sección DMARC en `/configuracion-dns`. Sin
body. Devuelve el dominio ya actualizado, no hace falta un GET aparte:

```json
{ "dominio": { "id": 8, "domain": "tudominio.com", "dns_verified": true, "dns_verified_at": "2026-07-29T19:19:00+00:00", "...": "..." } }
```

### `POST /api/v1/dominios/<access_token>/verificar-tls-rpt`

Igual que `verificar-dns` pero para el `rua=` de TLS-RPT — botón "Verificar de nuevo" de la sección
TLS-RPT en `/configuracion-dns`. Sin body. Devuelve el dominio actualizado
(`tls_rpt_verified`/`tls_rpt_verified_at`), mismo formato que arriba.

### `GET /api/v1/dominios/<access_token>/reportantes`

Desglose de organizaciones reportantes (top 5 por volumen + "Otros") y resultados de política
SPF/DKIM (pass/fail), de los reportes DMARC agregados del período. Query params: `rango`
(`7d`/`30d`/`90d`, default `30d`).

```json
{
  "orgs": [{ "name": "google.com", "count": 1200 }, { "name": "Otros", "count": 45 }],
  "has_orgs": true,
  "spf_pass": 1450, "spf_fail": 50, "has_spf": true,
  "dkim_pass": 1490, "dkim_fail": 10, "has_dkim": true
}
```

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

### `GET /api/v1/cumplimiento/protocolos`

Chequeo de DNS **en vivo** (no de tráfico histórico) de todos los dominios de la cuenta, corridos
en paralelo — la columna "DNS en vivo" de `/cumplimiento`. A propósito es un endpoint aparte de
`/api/v1/cumplimiento`: son N consultas DNS reales (una por dominio) que pueden tardar varios
segundos en total, no debe bloquear la carga de la tabla principal. Sin query params — siempre es
el estado actual.

```json
{
  "protocolos": {
    "8": { "ok": 4, "warn": 6, "fail": 0, "total": 10, "ok_pct": 40, "warn_pct": 60, "fail_pct": 0, "score": 70, "score_color": "text-amber-600" },
    "9": null
  }
}
```

Las claves de `protocolos` son el `id` de cada dominio (como string, por cómo serializa JSON las
claves de objeto) — mismo `id` que trae `dominio.id` en `/api/v1/dominios` y `/api/v1/cumplimiento`.
El valor es el mismo formato que el campo `summary` de `GET /api/check/<domain>` — `null` si no se
pudo completar el chequeo DNS de ese dominio puntual (no tumba el resto).

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
