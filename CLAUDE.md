# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Qué es este proyecto

**Akila-dmarc** (repo: `api-dmarc`): app Flask + Jinja2 (SSR, sin build de frontend) que audita y monitorea la configuración de autenticación de correo de un dominio — SPF, DMARC, DKIM, MX, DNSSEC, MTA-STS, TLS-RPT y BIMI. Dos modos:

1. **Checker puntual** (`/`, `/check`, `/api/check/<domain>`): audita un dominio bajo demanda, no guarda nada.
2. **Monitoreo continuo** (`/monitoreo/...`, `/tendencias/...`, etc.): registra un dominio, genera las instrucciones de DNS exactas, ingiere reportes DMARC agregados reales (vía un worker de `parsedmarc` aparte) y vigila cambios de configuración periódicamente — persistido en Postgres.

Para las reglas detalladas de negocio, frontend y arquitectura (mucho más exhaustivo que este archivo), ver **`AGENTS.md`** — es la fuente de verdad del proyecto, léelo antes de tocar código.

## Stack

Python 3.11+, Flask, Flask-SQLAlchemy (Postgres), Flask-Login, APScheduler. Frontend: Jinja2 + Tailwind CSS (CDN) + [htmx](https://htmx.org/) — sin JS build, sin framework de frontend. `checkdmarc` + `dkimpy` para las validaciones; `parsedmarc` para ingerir reportes DMARC agregados; `reportlab` para PDFs; `openai` para el resumen/análisis con IA (opcional).

## Comandos

```bash
python -m venv env
env\Scripts\activate          # Windows; source env/bin/activate en Linux/Mac
pip install -r requirements.txt
python app.py                 # sirve en 0.0.0.0:$PORT (default 5000)
```

Variables de entorno: copiar `.env-example` a `.env`. `DATABASE_URL` (Postgres) es **obligatoria** — la app no arranca sin ella, no hay fallback a SQLite. El resto (`OPENAI_PROJECT_API_KEY`, `SMTP_*`, `DMARC_*`, `PARSEDMARC_*`) es opcional y cada feature se degrada sola si falta (ver `AGENTS.md`).

**No hay suite de tests automatizada** (no hay carpeta `tests/`, no hay pytest). La verificación de cualquier cambio se hace con el `test_client()` de Flask contra la base real, ej.:

```python
from app import app
with app.test_client() as c:
    r = c.get("/ingresar")
    print(r.status_code)
```

Para probar rutas gateadas con `@login_required` sin credenciales reales, fabricar la sesión de Flask-Login directamente (con un id de usuario real de solo lectura, o un usuario desechable creado y borrado en el mismo script):

```python
with c.session_transaction() as sess:
    sess["_user_id"] = "1"
    sess["_fresh"] = True
```

Cualquier dato de prueba escrito en la base (usuarios, dominios) debe borrarse al terminar — ver la regla de "nunca tocar la base sin autorización explícita" en `AGENTS.md`.

## Arquitectura

Capas: `app.py` (solo rutas Flask, arma la respuesta) → `services/` (lógica de negocio) → `models/`/`utils/` (persistencia y helpers puros). No hay `blueprints`, todas las rutas viven en `app.py`.

**Flujo del checker**: `app.py` → `services/checkdmarc_service.run_check(domain)` (llama a `checkdmarc` + `dkimpy`) → `services/card_builder.build_cards()` (convierte el resultado crudo en tarjetas ok/warn/fail por protocolo) → `build_risks()`/`build_summary()` (prioriza qué corregir y calcula el score) → `services/ai_summary.generate_summary()` (opcional, resumen en lenguaje simple). El mismo contexto (`build_result_context()` en `app.py`) alimenta tanto el HTML como el PDF (`services/pdf_service.py`), para que ambos salgan siempre sincronizados.

**Flujo de monitoreo continuo**: registrar un dominio (`services/monitoring_service.register_domain()`) crea un `MonitoredDomain` con un `access_token` propio (el dashboard por token es público a propósito, sin login — ver `AGENTS.md`). A partir de ahí, dos vigilancias independientes corren dentro del mismo proceso web (sin servicios/cron aparte en Railway):

- **Vigilancia DNS** (`jobs/recheck_domains.py`, disparada por `start_scheduler()`/APScheduler en `app.py`): vuelve a correr `run_check()` periódicamente y compara contra el último `DomainSnapshot` para detectar cambios de política.
- **Vigilancia de tráfico real** (`services/reports_service.py`): un worker de `parsedmarc` (proceso externo, no parte de este deploy) lee reportes DMARC agregados reales por IMAP y los manda por webhook (`POST /webhooks/dmarc-aggregate/<secret>`) a esta app, que los guarda (`AggregateReport`/`AggregateRecord`) y detecta remitentes no declarados en el SPF.

Las páginas de análisis (`/tendencias`, dashboard por dominio, "Informes DMARC") todas leen de esos mismos `AggregateReport`/`AggregateRecord` — `services/monitoring_service.py` tiene las funciones de agregación (SQL con `GROUP BY`, no loops en Python, por rendimiento con muchos informes).

**Auth**: Flask-Login, `models/user.py`. Rutas del checker/monitoreo gateadas con `@login_required`; la API JSON pública (`/api/check/<domain>`) y las rutas por `access_token` quedan sin gate a propósito (el token es su propio mecanismo de acceso, tipo link mágico).

**Base de datos**: Postgres únicamente, sin Alembic — `db.create_all()` solo crea tablas nuevas, cualquier columna nueva en una tabla existente se agrega con `ALTER TABLE` manual (hay usuarios y datos reales en producción).

**Frontend**: SSR con Jinja2, `templates/layout.html` es el layout compartido (sidebar + topbar) que extienden casi todas las páginas — excepto `auth/login.html`/`auth/register.html`, que son standalone a propósito. htmx para toda interactividad (fragmentos HTML desde `templates/partials/`, nunca JSON). Ver `AGENTS.md` para las convenciones de estilo (tema, color de acento, tipografía, reglas de bordes/sombras) — son detalladas y ya fueron decisiones explícitas del usuario, no adivinar ni improvisar ahí.

**Reglas de layout que no hay que reabrir**:

- `html { scrollbar-gutter: stable; }` en `home.css` — reserva siempre el espacio de la barra de scroll, para que los contenedores centrados (`mx-auto`) no se corran unos píxeles entre una página/estado con scroll y uno sin scroll. No quitar esta regla.
- Ancho de contenedor por página: **un solo tamaño, `max-w-5xl` mx-auto px-6 py-16, para toda página que extiende `layout.html`** — no `max-w-4xl` ni ningún otro, ni siquiera para formularios de una columna. Se unificó explícitamente porque el esquema anterior de dos tamaños ya causó una vez que una página quedara mal documentada en los dos buckets a la vez. `auth/login.html`/`auth/register.html` son la única excepción (standalone, no llevan esta clase). Ver detalle en `AGENTS.md`.

## Toasts / alertas — vocabulario del usuario

Cuando el usuario dice **"toast"** o **"alerta"**, se refiere siempre a la librería [nextjs-toast-notify](https://www.nextjstoastnotify.com/) (CDN `unpkg.com/nextjs-toast-notify@1.62.0/...`, ya cargada en `layout.html` y en `auth/login.html`) — nunca un `alert()` nativo, nunca un div de error/éxito armado a mano. Toda confirmación de una acción (crear, activar/desactivar, guardar, error de validación, login fallido, etc.) debe usar esta librería. Detalle completo de la API y las opciones estándar (`duration`, `position`, `transition`, etc.) en `AGENTS.md`, sección Frontend.

Tres formas de dispararlo, según cómo responde la ruta:

1. **La ruta hace `render_template()` directo** (form POST sin redirect, ej. `auth/account.html`, `monitoring/registered.html`): pasar el mensaje como variable de contexto y disparar `showToast.*` en un `<script>` dentro de `{% block head_extra %}`, condicionado con Jinja (`{% if error %}`/`{% if just_registered %}`), envuelto en `document.addEventListener('DOMContentLoaded', ...)`.
2. **La ruta hace `redirect()`**: no hay forma de pasar un mensaje efímero a través de un redirect en esta app (no se usa `flash()` de Flask) — se manda como **query param en la URL del redirect**, y la ruta destino lo lee con `request.args.get(...)` y lo pasa al template, que lo usa igual que el caso 1.
3. **htmx, sin recargar la página** (preferido cuando la acción ya es o puede ser htmx — ver regla de htmx en `AGENTS.md`): la ruta devuelve el fragmento normal + el header `HX-Trigger` (`response.headers["HX-Trigger"] = json.dumps({"showToast": {"message": "..."}})`); un listener ya cargado en la página (`document.body.addEventListener('showToast', ...)`) dispara el `showToast.*` real. Ejemplo real: activar/desactivar un dominio (`monitoring_toggle` en `app.py` + `templates/partials/monitoring_toggle_status.html` + el listener en `templates/monitoring/dashboard.html`) — convertido de redirect a htmx justamente para evitar la recarga completa de la página.

Si se agrega una acción nueva que confirma algo al usuario, usar uno de estos tres patrones — no inventar un cuarto. Y en general: si una acción se puede hacer sin recargar la página, usar htmx (opción 3) en vez de un form POST con redirect (opción 2) — es la dirección que prefiere el usuario para evitar JS espagueti y recargas innecesarias.
