# Agente: Backend de Validación de Autenticación de Correo

## Comunicación

* Responder siempre en español, directo y sin rodeos.

## Reglas de código

* Cada función/método lleva un docstring de una línea.
* `app.py` solo define rutas y arma la respuesta — la lógica de negocio va en `services/`, los helpers puros (sin Flask/checkdmarc/dkimpy) van en `utils/`.
* **Nunca editar, agregar ni eliminar datos de la base de datos** (filas, columnas, tablas, migraciones, `INSERT`/`UPDATE`/`DELETE`, scripts de limpieza) sin autorización explícita del usuario, ni en local ni en producción. Preguntar y esperar confirmación antes de tocar la base real.
* No duplicar lógica ya resuelta por `checkdmarc`, `dkimpy` o `parsedmarc`. `dkimpy` es la única responsable de todo lo de DKIM. Mantener la arquitectura desacoplada: cualquiera de estas libs debe poder sustituirse sin afectar el resto.

## Arquitectura

* `app.py` — rutas Flask, delega a `services/`.
* `services/checkdmarc_service.py` — corre `checkdmarc` + DKIM (`dkimpy`) + arma instrucciones DNS para monitoreo.
* `services/card_builder.py` — arma las "cards" (ok/warn/fail) y los riesgos priorizados.
* `services/monitoring_service.py`, `reports_service.py`, `notifications.py` — alta/estado de dominios monitoreados, ingesta de reportes DMARC, alertas por correo.
* `services/auth_service.py` — registro/login/actualización de cuenta.
* `services/pdf_service.py` — generación de PDF (ReportLab).
* `utils/` — helpers puros (`domain_validation.py`, `formatting.py`, `dmarc_builder.py`).
* `models/` — `db = SQLAlchemy()`, modelos en `monitoring.py`/`user.py`. Persistencia en Postgres.
* `jobs/recheck_domains.py` — vigilancia DNS periódica, programada con APScheduler dentro del mismo proceso web (`start_scheduler()` en `app.py`), no un Railway Cron aparte.

## Frontend

* Interactividad vía [htmx](https://htmx.org/), no JS manual (fetch + DOM a mano). El servidor responde con fragmentos HTML (`templates/partials/`) a las rutas que consume htmx — JSON solo en `/api/...`. Preferir `hx-on:`/`hx-*` declarativo antes que sumar un `.js` nuevo.
* Todo botón/link estilizado como botón lleva un ícono SVG inline (`stroke="currentColor"`), sin librerías de íconos externas.
* **Layout con sidebar** (`templates/layout.html` + `partials/sidebar.html`/`topbar.html`): toda página autenticada nueva debe usar `{% extends "layout.html" %}` (bloques `title`/`head_extra`/`body_class`/`content`), no un `<html>` completo propio. Excepción a propósito: `auth/login.html`/`auth/register.html` (pantalla completa sin nav, antes de loguearse no hay nada que navegar).
* El checkbox `#sidebar-toggle` debe ser **hermano directo** del `<aside>` (mismo nivel del DOM) — `peer-checked:` de Tailwind solo alcanza hermanos, no ancestros/descendientes.
* Ítem activo del nav/sidebar: comparar contra `request.endpoint`, nunca contra la URL (sobrevive a un rename de ruta).
* **Tema**: fondo `#fcfaef`, tarjetas blancas, tipografía "Plus Jakarta Sans" (clase `.font-jakarta` en `home.css`, no arbitrary-value de Tailwind) en todo el sitio, incluidas `auth/login.html`/`register.html`. Color primario único: **`#2d2147`** (botones, hovers, nav activo, foco de inputs, logo) — no queda ningún otro accent color en la app (el rosa `#ef5184` y el gris `#474545` anteriores fueron retirados por completo). Si se ajusta el tema, revisar también `STATUS_META`/`RISK_SEVERITY`/`score_color` en `card_builder.py` (colores de estado ok/warn/fail, independientes del accent). El PDF (`pdf_service.py`) es 100% independiente de estas clases Tailwind.
* **Regla: nunca usar `border border-zinc-200` ni `shadow-sm`/`shadow-md`** — ninguna sombra ni borde gris neutro para separar tarjetas del fondo; el contraste `bg-white` contra el fondo `#fcfaef` ya alcanza. Para hover en elementos interactivos, usar un borde de color sólido (ej. `border border-transparent hover:border-[#2d2147]`). Bordes de color (`border-emerald-200`, `border-[#2d2147]/60`, etc.) sí se mantienen. Excepciones:
  * `.verify-btn`: necesita `border-transparent` (no omitir `border`) porque `home.css` le pinta `border-color` con `!important` mientras dura el POST — sin ancho de borde esa animación no tiene contra qué animar.
  * Inputs de texto: `border border-zinc-200` en reposo (sin sombra) + `focus:border-[#2d2147]/60` — patrón ya validado, no reintentar `shadow-md` en foco ni `border-transparent` en reposo (ya descartados).
* Tamaño de letra: el texto chico (`text-[9px]` a `text-[13px]`, `text-xs`/`text-sm`) tiene overrides `!important` en `home.css` (+2px). Un tamaño arbitrario nuevo en ese rango necesita su propia regla ahí o queda más chico que el resto.
* Pace.js (barra de progreso) en toda página completa: `window.paceOptions` se define antes de cargar `pace.min.js`.

## Checker de un dominio (`/`, `POST /check`, `GET /api/check/<domain>`)

* DKIM: `checkdmarc` no lo reporta — se prueba una lista de selectores comunes con `dkimpy`, más `?selector=` opcional.
* Ausencia vs. falla: para MTA-STS/TLS-RPT/BIMI (`SOFT_ABSENCE_KEYS`), que el registro no exista es ADVERTENCIA, no FALLA (protocolos opcionales, a diferencia de SPF/DMARC).
* Timeouts de DNS → siempre `na` (N/D), nunca FALLA; no afectan el `score`.
* Nuevos tags/mecanismos DMARC o SPF a traducir van en los diccionarios de `card_builder.py` (`DMARC_POLICY_LABELS`, `SPF_MECHANISM_LABELS`, etc.), no hardcodeados en la plantilla.
* SPF sin registro: nunca sugerir un valor final (podría rechazar correo legítimo) — solo mostrar los hostnames MX reales y, si matchea un proveedor conocido, un `include:` de partida.
* Resumen con IA (`services/ai_summary.py`) es opcional: sin `OPENAI_PROJECT_API_KEY` o si falla/tarda, no se muestra y el resto sigue funcionando. Solo en el flujo HTML, nunca en `/api/check/<domain>`.
* PDF (`GET /reporte-pdf?domain=...`): ReportLab (no WeasyPrint, exige libs de sistema no disponibles en Railway/Windows sin config extra). `pdf_service.py` arma el documento a mano a partir del mismo contexto que `build_result_context()` — un `kind` de tarjeta nuevo en `card_builder.py` necesita su rama en `_card_content()` o sale vacía en el PDF. `ParagraphStyle` no hereda `leading` de `fontSize` (>10pt necesita `leading` explícito). Tablas anidadas dentro de una caja deben dimensionarse contra `width - 2*CARD_PAD`, no el ancho total de página.
* Botón de descarga de PDF: `fetch` → blob → `<a download>` sintético (`downloadPdfReport()` en `partials/pdf_download_script.html`) para poder deshabilitar el botón durante la generación — incluir ese partial en vez de duplicar la lógica.

## Monitoreo continuo de DMARC

* **Vigilancia DNS** (`jobs/recheck_domains.py`): compara contra el último `DomainSnapshot`, genera `Alert` si cambió política DMARC/SPF/selectores DKIM. Se dispara sola vía `start_scheduler()` (APScheduler, `BackgroundScheduler`) desde `app.py` — cada `RECHECK_DOMAINS_INTERVAL_HOURS` horas (default 12), corriendo dentro del mismo proceso web, no como servicio/cron aparte. Sólo arranca en `if __name__ == "__main__"` (nunca al importar `app` para tests) y sólo una vez si el reloader de Flask está activo (`WERKZEUG_RUN_MAIN`). **Requiere una sola instancia** del servicio — con réplicas, el job correría duplicado una vez por instancia.
* **Vigilancia de tráfico real** (`services/reports_service.py`): ingiere reportes agregados vía [parsedmarc](https://github.com/domainaware/parsedmarc) (webhook), compara remitentes reales contra el SPF declarado, genera `Alert` tipo `unknown_sender`.
* `detect_unknown_senders()`: comparar tanto substring directo (nombres de ASN cortos) como la palabra clave del dominio base del target vs. las palabras del nombre de organización (nombres largos no son substring literal) — evita falsos positivos ya vistos en producción.
* `Alert.kind_label`/`KIND_LABELS` (`models/monitoring.py`): un `kind` nuevo necesita su entrada ahí o se muestra crudo en inglés.
* Activar/desactivar (`is_active`): pausar, nunca eliminar — reversible, conserva historial.
* Generador de política DMARC (`utils/dmarc_builder.py`): vista previa, no se persiste. `p`/`pct`/`adkim`/`aspf` siempre arrancan conservadores (`p=none`, `pct=25`, `adkim=r`, `aspf=r`) sin importar la política real ya publicada — decisión explícita del usuario, riesgo asumido a propósito. `sp`/`rua`/`ruf` sí respetan el valor real si ya existe.
* MAX_REPORT_RECORDS=30 en el PDF del dashboard: sin este tope, un reporte real grande revienta el layout (`LayoutError`) — se recorta y se avisa cuántos quedaron afuera, nunca en silencio.

## Login (Flask-Login)

* `models/user.py` (`User`, `UserMixin`): `email` + `password_hash` (werkzeug.security) + `created_at`.
* Rutas gateadas con `@login_required`: `/`, `POST /check`, `GET/POST /monitoreo`, `GET /monitoreos/`, `/cuenta`, `/documentacion`. **No gateadas a propósito**: `GET /api/check/<domain>` (API pública) y las rutas por `access_token` (el token es su propio mecanismo de acceso).
* Perfil de cuenta (`/cuenta`, `/cuenta/correo`, `/cuenta/contrasena`): dos forms independientes; cambiar contraseña exige la actual (`check_password()`), cambiar correo no.
* `@login_manager.unauthorized_handler`: si el destino bloqueado era `/` sin parámetros, redirige a `/ingresar` limpio (sin `?next=%2F`); cualquier otra ruta sí agrega `?next=`.
* `SECRET_KEY`: si falta en el entorno, se genera una al azar en cada arranque (invalida sesiones activas en cada deploy, pero no rompe la app). Definir en Railway para sesiones persistentes.

## Base de datos: Postgres

* `DATABASE_URL` es obligatoria — `app.py` lanza `RuntimeError` si falta, sin fallback local. Railway entrega `postgres://`; SQLAlchemy 2.x solo reconoce `postgresql://` — `app.py` reescribe el prefijo.
* No hay Alembic. `db.create_all()` solo crea tablas nuevas. Con usuarios y datos reales en producción: cualquier columna nueva se agrega con `ALTER TABLE` manual (sintaxis Postgres), nunca borrando tablas. `drop_all()`/cualquier borrado cae bajo la regla de "nunca tocar la base sin autorización explícita".
* Usar siempre tipos de SQLAlchemy dialecto-agnósticos (`db.Boolean`, `db.DateTime(timezone=True)`, `db.JSON`), nunca SQL crudo específico de un motor.
* Si se agrega un `.delete()`, usar `db.session.delete(instancia)`, no `Query.delete()` en bloque, para que el `cascade` funcione.

## Librerías base — no reimplementar su lógica

* **[checkdmarc](https://github.com/domainaware/checkdmarc)**: SPF/DMARC/BIMI/MTA-STS/TLS-RPT/MX/DNSSEC/NS/SOA.
* **[dkimpy](https://pypi.org/project/dkimpy/)**: todo lo de DKIM.
* **[parsedmarc](https://github.com/domainaware/parsedmarc)**: ingesta de reportes DMARC/SMTP TLS vía IMAP (solo monitoreo continuo). Consultar su documentación ante dudas de `config.ini`/`PARSEDMARC_*`/esquema del JSON — no asumir sintaxis.

## Pendiente (fuera del alcance de código)

* Crear la casilla de correo real (`DMARC_REPORTS_MAILBOX`) y su TXT de verificación de destino externo si vive en otro dominio.
* Desplegar el worker de parsedmarc como servicio aparte en Railway (`config/parsedmarc.ini.example`).
* Prueba end-to-end con reportes reales (tardan 24-48h en llegar).
