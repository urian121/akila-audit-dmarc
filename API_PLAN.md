# Plan: API pública sobre Akila-DMARC

Objetivo: exponer toda la información que hoy solo se ve en las páginas HTML (checker,
monitoreo, tendencias, cumplimiento, informes, cuenta/plan) a través de una API JSON versionada
(`/api/v1/...`), reusando los `services/*.py` que ya existen — sin reescribir lógica de negocio.

No cubre: integrar una pasarela de pago (aparte, ver `AGENTS.md`) ni un frontend nuevo que
consuma la API — solo la API en sí.

---

## Decisiones a tomar antes de escribir código

Nada de esto se puede adivinar bien, hay que fijarlo primero:

1. **¿Solo lectura, o también acciones?** Solo lectura (ver dominios, tendencias, informes) es
   mucho más simple de blindar que además poder registrar un dominio, activar/desactivar, o
   cambiar un plan por API. Recomendado: arrancar **solo lectura** en la v1, sumar acciones
   después si hace falta.
2. **¿La API es para el propio usuario (self-service, cada uno ve lo suyo) o también para
   admins (ver todo)?** Cambia si hace falta un segundo nivel de permisos en el API key.
3. **¿Rate limit desde el día uno?** Recomendado sí, al menos en el endpoint de checker (hace
   consultas DNS en vivo, es el único que ya es público hoy sin límite).

---

## Fase 0 — Base: autenticación de la API ✅ HECHA

Se descartó JWT/login (no hacía falta para el caso de uso: consumo desde un servicio externo,
no un flujo de login interactivo) — quedó API key estática por usuario, sin login ni expiración:

- [x] 3 columnas nuevas en `User` (`ALTER TABLE` manual, ver `AGENTS.md`): `api_key_hash`
      (SHA-256, nunca la key en texto plano — no el mismo hash que las contraseñas, ver por qué
      en `AGENTS.md`), `api_key_active`, `api_key_created_at`. Sin tabla aparte — una key por
      usuario alcanza hoy.
- [x] **Generar y desactivar son solo de admin, no self-service** (corregido sobre la primera
      versión, que sí dejaba generar desde `/cuenta`) — `POST /admin/usuarios/<id>/api-key/generar`
      y `POST /admin/usuarios/<id>/api-key/toggle`, ambas en `admin/edit_plan.html`. El cliente no
      ve ninguna opción de API key en su propia cuenta; el admin genera en nombre del usuario
      elegido y ve la key en texto plano **una sola vez**, ahí mismo — es quien se la tiene que
      hacer llegar por fuera de la app.
- [x] Decorador `@require_api_key` (`app.py`): lee `Authorization: Bearer <token>`, resuelve el
      usuario en `g.api_user`, 401 si falta o no matchea/está desactivada.
- [x] `GET /api/v1/me` — primer endpoint real, prueba el mecanismo de punta a punta.
- [x] `access_token` de `MonitoredDomain` no se tocó — sigue siendo su propio mecanismo (link
      mágico público), no se mezcló con esto.

Probado: `/cuenta` ya no muestra la opción (ni existe la ruta vieja de self-service, 404); admin
genera la key de otro usuario → 200 con la key real; sin header o key inválida → 401; admin
desactiva → esa misma key pasa a 401; admin reactiva → vuelve a 200; regenerar invalida la key
vieja al instante; un usuario no-admin no puede generar ni tocar el toggle de nadie, ni el suyo
propio (404).

---

## Fase 1 — Serialización

`jsonify()` no sabe convertir objetos de SQLAlchemy. Antes de exponer cualquier endpoint hace
falta un `to_dict()` (o función serializadora) por cada modelo que se vaya a devolver:

- [ ] `User` (solo campos públicos: id, nombre, correo, plan — nunca `password_hash`)
- [ ] `MonitoredDomain`
- [ ] `DomainSnapshot`
- [ ] `AggregateReport` / `AggregateRecord`
- [ ] `ForensicReport`
- [ ] `Alert`
- [ ] `UserPlan` / `Plan`

---

## Fase 2 — Endpoints

Uno por cada cosa que hoy es una página HTML. Todos bajo `/api/v1/`, todos `GET` en esta v1
(solo lectura), todos gateados por `@require_api_key` salvo que se aclare lo contrario.

| Endpoint | Reemplaza / usa | Nota |
|---|---|---|
| `GET /api/v1/me` | — | ✅ Ya existe — prueba del mecanismo de auth, info básica de la cuenta dueña de la key |
| `GET /api/v1/check/<domain>` | ya existe (`/api/check/<domain>`) | Sin auth, público — se mantiene igual, solo se versiona la URL |
| `GET /api/v1/dominios` | `list_domains()` | Dominios monitoreados del usuario |
| `GET /api/v1/dominios/<token>` | `get_dashboard_data()` | Dashboard: alertas + reportes agregados + forenses |
| `GET /api/v1/dominios/<token>/remitentes` | `list_domain_senders()` | Con `estado`/`q`/`page`, igual que la tabla HTML |
| `GET /api/v1/dominios/<token>/alertas` | `list_domain_alerts()` | Con `tipo`/`rango`/`q`/`page` |
| `GET /api/v1/dominios/<token>/subdominios` | `get_subdomain_breakdown()` | |
| `GET /api/v1/dominios/<token>/tendencias` | `get_trends_data()` | `?rango=7d\|30d\|90d` |
| `GET /api/v1/dominios/<token>/impacto` | `get_impact_analysis()` | |
| `GET /api/v1/dominios/<token>/impacto/afectados` | `list_affected_senders()` | Con `q`/`page` |
| `GET /api/v1/dominios/<token>/analisis-ia` | `generate_health_analysis()` | Igual que hoy, se degrada solo sin `OPENAI_PROJECT_API_KEY` |
| `GET /api/v1/cumplimiento` | `get_compliance_overview()` | Todos los dominios del usuario de un vistazo |
| `GET /api/v1/informes-dmarc` | `list_dmarc_reports()` | Con `estado`/`rango`/`q`/`page` |
| `GET /api/v1/informes-dmarc/<id>` | `get_dmarc_report_detail()` | |
| `GET /api/v1/tls-rpt` | ya calculado en `tls_rpt_reports()` | Estado de verificación por dominio |
| `GET /api/v1/cuenta` | `User` + `UserPlan` | Plan actual, límite, cuántos dominios lleva usados |

Admin (opcional, solo si la API también es para administración):

| Endpoint | Reemplaza / usa |
|---|---|
| `GET /api/v1/admin/usuarios` | `list_users()` |
| `GET /api/v1/admin/usuarios/<id>` | detalle + plan |

---

## Fase 3 — Rate limiting

- [ ] `Flask-Limiter` (o similar) en `/api/v1/check/<domain>` — es el único endpoint que queda
      público sin API key, y hace consultas DNS reales por request.
- [ ] Límite razonable a definir (ej. N por minuto por IP) una vez que se sepa el uso esperado.

---

## Fase 4 — Documentación

- [ ] Un `API.md` (mismo estilo que `SERVICIOS.md`/`README.md`, sin Swagger/OpenAPI a menos que
      se pida): un endpoint por sección, método, parámetros, ejemplo de respuesta.

---

## Orden recomendado de ataque

1. ~~Fase 0 (auth)~~ — hecha.
2. Fase 1 (serialización) — empezar por los modelos más usados
   (`MonitoredDomain`, `AggregateReport`/`AggregateRecord`).
3. Fase 2, de a poco, dominio por dominio de la tabla — no hace falta todo de una:
   sugerido, arrancar por `check`, `dominios`, `dominios/<token>` (lo más pedido / más simple),
   después el resto.
4. Fase 3 y 4 al final, una vez que los endpoints reales ya estén probados.

**No es chico** (~15-20 endpoints + una capa de auth nueva), pero nada acá es lógica de negocio
nueva — es exponer, con serialización y permisos correctos, lo que los `services/` ya calculan
hoy para el HTML.
