import os
import secrets
from datetime import datetime, timezone
from functools import wraps

from dotenv import load_dotenv
from flask import Flask, Response, abort, g, jsonify, redirect, render_template, request, url_for
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_login import LoginManager, current_user, login_required, login_user, logout_user

from models import DomainSnapshot, Plan, User, db
from services.ai_summary import generate_summary
from services.auth_service import authenticate, generate_api_key, get_user_by_api_key, list_users, register_user, set_api_key_active, set_user_active, update_email, update_password
from services.card_builder import DMARC_POLICY_LABELS, build_cards, build_risks, build_summary
from services.checkdmarc_service import build_dns_screen_data, run_check
from services.domain_health_analysis import generate_health_analysis
from services.pdf_service import build_dashboard_pdf_bytes, build_pdf_bytes
from utils.dmarc_builder import build_dmarc_value
from models.user import DEFAULT_MAX_DOMAINS
from services.monitoring_service import assign_plan, count_active_domains, get_compliance_overview, get_compliance_protocol_status, get_dashboard_data, get_dmarc_report_detail, get_domain_by_token, get_impact_analysis, get_max_domains, get_report_breakdown, get_subdomain_breakdown, get_trends_data, get_user_plan_form_data, list_affected_senders, list_domain_alerts, list_domain_senders, list_domains, list_dmarc_reports, register_domain, set_active, update_user_plan, verify_dns, verify_tls_rpt
from services.forensic_reports_service import ingest_forensic_report
from services.reports_service import ingest_aggregate_report
from utils.domain_validation import is_valid_domain
from utils.serializers import serialize_alert, serialize_aggregate_record, serialize_aggregate_report, serialize_forensic_report, serialize_monitored_domain, serialize_paginated, serialize_user

# Sólo tiene efecto en local: .env está en .gitignore, así que Railway (que
# despliega desde el repo de GitHub) nunca ve este archivo. Las variables de
# producción se definen en el dashboard de Railway, no acá.
load_dotenv()

app = Flask(__name__)

# Sesiones de login. Sin SECRET_KEY en el entorno, se genera una al azar en
# cada arranque — funciona, pero invalida las sesiones activas en cada
# reinicio/deploy. Para sesiones persistentes, definir SECRET_KEY en .env/Railway.
app.secret_key = os.environ.get("SECRET_KEY") or secrets.token_hex(32)

login_manager = LoginManager()
login_manager.login_view = "auth_login"
login_manager.init_app(app)

# Rate limit — sólo se aplica al endpoint que se decora explícitamente (default_limits=[]), hoy
# únicamente /api/check/<domain> (Fase 3 de API_PLAN.md): es el único endpoint público sin API key
# y hace consultas DNS reales por request. Storage en memoria (default) alcanza porque la app corre
# en un solo proceso web (sin workers/réplicas separadas, ver AGENTS.md) — si algún día se agregan
# más procesos, esto necesitaría un backend compartido (ej. Redis) para que el límite sea real entre todos.
limiter = Limiter(get_remote_address, app=app, default_limits=[])


@app.errorhandler(429)
def handle_rate_limit(error):
    """429 en JSON, no la página HTML de handle_not_found — hoy sólo lo dispara /api/check/<domain>,
    un endpoint de API."""
    return jsonify({"error": "Demasiadas consultas — probá de nuevo en un minuto."}), 429


@login_manager.user_loader
def load_user(user_id):
    """Carga el usuario de la sesión activa a partir de su id."""
    return User.query.get(int(user_id))


@login_manager.unauthorized_handler
def handle_unauthorized():
    """Redirige a /ingresar; omite ?next= cuando el destino era la home sin parámetros, para no ensuciar la URL en el caso más común."""
    if request.path == "/" and not request.query_string:
        return redirect(url_for("auth_login"))
    return redirect(url_for("auth_login", next=request.full_path.rstrip("?")))


@app.before_request
def reject_deactivated_sessions():
    """Si una cuenta se desactiva mientras alguien ya tiene sesión iniciada, esa sesión existente
    deja de poder hacer nada de inmediato — Flask-Login por sí solo no revisa esto en cada request
    (`login_required`/`current_user.is_authenticated` sólo confirman que hay sesión, no que la
    cuenta siga activa), así que sin este chequeo desactivar a alguien sólo bloquearía su próximo
    login, no la sesión que ya tenía abierta."""
    if current_user.is_authenticated and not current_user.is_active:
        logout_user()
        return redirect(url_for("auth_login"))


def admin_required(view):
    """Como @login_required pero además exige is_admin — 404 (no 403) para no confirmar que la
    ruta existe a quien inicie sesión sin ser admin, mismo criterio que el resto de la app
    (ej. el webhook de parsedmarc)."""
    @wraps(view)
    def wrapped(*args, **kwargs):
        if not current_user.is_authenticated:
            return login_manager.unauthorized()
        if not current_user.is_admin:
            abort(404)
        return view(*args, **kwargs)
    return wrapped


def require_api_key(view):
    """Autenticación de la API JSON (`/api/v1/...`) — header `Authorization: Bearer <api_key>`,
    sin sesión de cookie: pensada para un consumidor externo (script, otro backend, un frontend
    propio con o sin framework de JS), no para el navegador. Resuelve el usuario dueño de la key
    en `g.api_user` — a propósito no reusa `current_user` de Flask-Login, esto no inicia sesión."""
    @wraps(view)
    def wrapped(*args, **kwargs):
        auth_header = request.headers.get("Authorization", "")
        if not auth_header.startswith("Bearer "):
            return jsonify({"error": "Falta el header Authorization: Bearer <api_key>."}), 401
        raw_key = auth_header[len("Bearer "):].strip()
        user = get_user_by_api_key(raw_key)
        if not user:
            return jsonify({"error": "API key inválida, desactivada, o cuenta desactivada."}), 401
        g.api_user = user
        return view(*args, **kwargs)
    return wrapped


def _domain_owned_by(monitored, user):
    """Un dominio es "del" usuario si lo registró él, o si es admin (los admins ven cualquier
    dominio, igual que ya pueden ver/editar cualquier cuenta desde /admin/usuarios). Único punto
    con esta regla — la usan tanto las rutas web (sesión) como la API (API key)."""
    return monitored is not None and (monitored.user_id == user.id or user.is_admin)


def get_owned_domain_or_404(access_token):
    """Resuelve un dominio monitoreado por su access_token para las rutas web (sesión de
    Flask-Login) y exige que sea del usuario logueado — 404 si no existe o si es de otro
    usuario, mismo criterio que admin_required (no confirmar existencia a quien no es dueño).

    El dashboard por token dejó de ser un "link mágico" público (compartible sin cuenta) — ahora
    hace falta sesión propia y ser el dueño (o admin) para entrar, a pedido explícito del usuario.
    Todas las rutas /monitoreo/<token>... y /tendencias/<token>... llaman esto antes que nada."""
    monitored = get_domain_by_token(access_token)
    if not _domain_owned_by(monitored, current_user):
        abort(404)
    return monitored


def get_api_owned_domain(access_token):
    """Igual que get_owned_domain_or_404 pero para la API por API key (g.api_user, no
    current_user de Flask-Login) — devuelve None en vez de abortar, porque un abort(404) plano
    renderiza la página 404 en HTML (ver handle_not_found), no sirve para un consumidor JSON. La
    ruta que llama esto arma su propio jsonify({"error": ...}), 404."""
    monitored = get_domain_by_token(access_token)
    return monitored if _domain_owned_by(monitored, g.api_user) else None


def require_api_admin(view):
    """Como @require_api_key pero además exige is_admin — 404 (no 403), mismo criterio que
    @admin_required en el resto de la app (no confirmar que la ruta existe a quien no es admin).
    Envuelve a @require_api_key en vez de repetir la lectura del header Authorization."""
    @wraps(view)
    def wrapped(*args, **kwargs):
        if not g.api_user.is_admin:
            return jsonify({"error": "No se encontró esa ruta."}), 404
        return view(*args, **kwargs)
    return require_api_key(wrapped)


@app.errorhandler(404)
def handle_not_found(error):
    """Ruta inexistente: página 404 propia que redirige sola al inicio a los pocos segundos (meta refresh), con un botón para ir de inmediato.

    Sólo aplica a rutas que no matchean nada o a un abort(404) explícito — las
    vistas que ya devuelven su propio (contenido, 404) a mano (ej. "No se
    encontró ese dashboard" en las rutas de monitoreo) no pasan por acá.
    """
    return render_template("404.html"), 404


# Monitoreo continuo (fases 1-7 del plan): persistencia en Postgres. No hay
# fallback a SQLite — DATABASE_URL es obligatoria (ver AGENTS.md). Railway la
# inyecta solo al agregar el addon de Postgres; en local hay que copiarla a .env.
database_url = os.environ.get("DATABASE_URL")
if not database_url:
    raise RuntimeError(
        "Falta DATABASE_URL. Este proyecto usa Postgres — copia la cadena de "
        "conexión del addon de Postgres en Railway (o de tu Postgres local) a .env."
    )
# Railway/Heroku entregan el esquema como "postgres://", pero SQLAlchemy 2.x
# sólo reconoce "postgresql://" — sin este reemplazo, falla al conectar.
if database_url.startswith("postgres://"):
    database_url = database_url.replace("postgres://", "postgresql://", 1)

app.config["SQLALCHEMY_DATABASE_URI"] = database_url
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
# pool_pre_ping: antes de reusar una conexión del pool, verifica que siga viva.
# Sin esto, si el servidor de Postgres cierra una conexión inactiva (timeout,
# reinicio, etc.), la siguiente consulta falla con "server closed the
# connection unexpectedly" en vez de reconectar sola.
app.config["SQLALCHEMY_ENGINE_OPTIONS"] = {"pool_pre_ping": True}
db.init_app(app)
with app.app_context():
    db.create_all()

# Casilla que recibe los reportes DMARC (se le pide al usuario que la agregue
# a su rua=) y secreto que debe traer la URL del webhook de parsedmarc.
DMARC_REPORTS_MAILBOX = os.environ.get("DMARC_REPORTS_MAILBOX", "reports@tudominio.com")
DMARC_WEBHOOK_SECRET = os.environ.get("DMARC_WEBHOOK_SECRET")


def build_result_context(domain, extra_selector=None):
    """Corre la auditoría del dominio y arma el contexto compartido por la vista HTML y el PDF de descarga."""
    data = run_check(domain, extra_selector)
    cards = build_cards(data)
    return {
        "cards": cards,
        "risks": build_risks(cards, data.get("domain") or domain),
        "summary": build_summary(data),
        "result_domain": data.get("domain"),
        "base_domain": data.get("base_domain"),
        "ai_summary": generate_summary(data.get("domain") or domain, cards),
        "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
    }


def render_result(domain, extra_selector=None):
    """Corre la auditoría del dominio, pide el resumen con IA y renderiza el fragmento HTML de resultados."""
    return render_template("partials/check_result.html", **build_result_context(domain, extra_selector))


@app.route("/", methods=["GET"])
@login_required
def inicio():
    """Sirve la página principal (requiere sesión); si viene ?domain=, renderiza el resultado directamente (SSR)."""
    domain = request.args.get("domain", "").strip().lower()
    context = {"domain": domain}
    if domain:
        if not is_valid_domain(domain):
            context["error"] = "Ingresa un dominio válido, por ejemplo: tudominio.com"
        else:
            try:
                context["result_html"] = render_result(domain)
            except Exception as error:
                context["error"] = f"No se pudo completar el análisis: {error}"
    return render_template("index.html", **context)


@app.route("/documentacion", methods=["GET"])
@login_required
def documentacion():
    """Página de referencia: qué es DMARC/SPF/DKIM y demás conceptos, en lenguaje simple."""
    return render_template("documentation.html")


@app.route("/check", methods=["POST"])
@login_required
def check_partial():
    """Endpoint HTML consumido por htmx (hx-post), requiere sesión — devuelve un fragmento renderizado."""
    domain = request.form.get("domain", "").strip().lower()
    selector = request.form.get("selector") or None

    if not is_valid_domain(domain):
        return render_template(
            "partials/error.html",
            message="Ingresa un dominio válido, por ejemplo: tudominio.com",
        )

    try:
        return render_result(domain, selector)
    except Exception as error:
        return render_template(
            "partials/error.html",
            message=f"No se pudo completar el análisis: {error}",
        )


@app.route("/api/check/<domain>", methods=["GET"])
@limiter.limit("10/minute")
def check(domain):
    """API JSON pública (sin sesión, a propósito): ejecuta la auditoría del dominio indicado y la
    devuelve completa. Rate limit: 10/minuto por IP (Fase 3 de API_PLAN.md) — es el único endpoint
    de la API sin API key, y hace consultas DNS reales por request."""
    custom_selector = request.args.get("selector")
    result = run_check(domain, custom_selector)
    return jsonify(result)


@app.route("/api/v1/me", methods=["GET"])
@require_api_key
def api_me():
    """Primer endpoint de la API por API key (ver API_PLAN.md) — prueba el mecanismo de
    autenticación end to end: info básica de la cuenta dueña de la key mandada en el header."""
    data = serialize_user(g.api_user)
    data["plan_max_domains"] = get_max_domains(g.api_user.id)  # None = sin límite (admin)
    data["domains_used"] = count_active_domains(g.api_user.id)
    return jsonify(data)


@app.route("/api/v1/dominios", methods=["GET"])
@require_api_key
def api_dominios():
    """Lista los dominios monitoreados de la cuenta dueña de la API key (equivalente a /monitoreos/)."""
    domains = list_domains(g.api_user.id)
    return jsonify({"dominios": [serialize_monitored_domain(d) for d in domains]})


@app.route("/api/v1/dominios/<access_token>", methods=["GET"])
@require_api_key
def api_dominio_dashboard(access_token):
    """Dashboard de un dominio puntual (equivalente a /monitoreo/<token>): dominio + alertas +
    informes agregados + reportes forenses recientes."""
    monitored = get_api_owned_domain(access_token)
    if monitored is None:
        return jsonify({"error": "No se encontró ese dominio."}), 404
    data = get_dashboard_data(access_token)
    return jsonify({
        "dominio": serialize_monitored_domain(data["monitored"]),
        "alertas": [serialize_alert(a) for a in data["alerts"]],
        "informes": [serialize_aggregate_report(r) for r in data["reports"]],
        "forenses": [serialize_forensic_report(f) for f in data["forensic_reports"]],
    })


@app.route("/api/v1/dominios/<access_token>/remitentes", methods=["GET"])
@require_api_key
def api_dominio_remitentes(access_token):
    """Tabla paginada de remitentes reales (equivalente a /monitoreo/<token>/remitentes).
    Query params: rango (7d/30d/90d/todos), estado (todos/con_fallas/sin_fallas), q, page."""
    monitored = get_api_owned_domain(access_token)
    if monitored is None:
        return jsonify({"error": "No se encontró ese dominio."}), 404
    _, days = _parse_rango()
    estado = request.args.get("estado", "todos")
    q = request.args.get("q", "").strip()
    page = request.args.get("page", 1, type=int) or 1
    senders = list_domain_senders(monitored, days=days, estado=estado, q=q, page=page)
    return jsonify(serialize_paginated(senders, date_keys=("first_seen", "last_seen")))


@app.route("/api/v1/dominios/<access_token>/alertas", methods=["GET"])
@require_api_key
def api_dominio_alertas(access_token):
    """Tabla paginada de alertas (equivalente a /monitoreo/<token>/alertas).
    Query params: rango (7d/30d/90d/todos), tipo (todos/remitente_desconocido/cambio_configuracion), q, page."""
    monitored = get_api_owned_domain(access_token)
    if monitored is None:
        return jsonify({"error": "No se encontró ese dominio."}), 404
    _, days = _parse_rango()
    tipo = request.args.get("tipo", "todos")
    q = request.args.get("q", "").strip()
    page = request.args.get("page", 1, type=int) or 1
    alerts = list_domain_alerts(monitored, days=days, tipo=tipo, q=q, page=page)
    return jsonify(serialize_paginated(alerts, date_keys=("last_seen",)))


@app.route("/api/v1/dominios/<access_token>/impacto/afectados", methods=["GET"])
@require_api_key
def api_dominio_afectados(access_token):
    """Tabla paginada de emisores que se verían afectados por endurecer la política (equivalente
    a /tendencias/<token>/afectados). Query params: rango (7d/30d/90d, sin "todos"), q, page."""
    monitored = get_api_owned_domain(access_token)
    if monitored is None:
        return jsonify({"error": "No se encontró ese dominio."}), 404
    _, days = _parse_rango(allow_todos=False)
    q = request.args.get("q", "").strip()
    page = request.args.get("page", 1, type=int) or 1
    affected = list_affected_senders(monitored, days=days, q=q, page=page)
    return jsonify(serialize_paginated(affected))


@app.route("/api/v1/dominios/<access_token>/subdominios", methods=["GET"])
@require_api_key
def api_dominio_subdominios(access_token):
    """Desglose por subdominio/header_from (equivalente al bloque de subdominios del dashboard).
    Ya es JSON-safe tal cual (lista de dicts con solo str/int/float) — no necesita serializer.
    Query params: rango (7d/30d/90d, default 30d)."""
    monitored = get_api_owned_domain(access_token)
    if monitored is None:
        return jsonify({"error": "No se encontró ese dominio."}), 404
    _, days = _parse_rango(allow_todos=False)
    return jsonify({"subdominios": get_subdomain_breakdown(monitored, days)})


@app.route("/api/v1/dominios/<access_token>/tendencias", methods=["GET"])
@require_api_key
def api_dominio_tendencias(access_token):
    """Volumen pass/fail por día + tasa de cumplimiento (equivalente a /tendencias/<token>). Ya es
    JSON-safe tal cual — no necesita serializer. Query params: rango (7d/30d/90d, default 30d)."""
    monitored = get_api_owned_domain(access_token)
    if monitored is None:
        return jsonify({"error": "No se encontró ese dominio."}), 404
    _, days = _parse_rango(allow_todos=False)
    return jsonify(get_trends_data(monitored, days))


@app.route("/api/v1/dominios/<access_token>/impacto", methods=["GET"])
@require_api_key
def api_dominio_impacto(access_token):
    """Estado actual + análisis de impacto de endurecer la política DMARC (equivalente al bloque
    "Análisis de impacto" de Tendencias, sin la tabla de afectados — ver .../impacto/afectados
    aparte). Ya es JSON-safe tal cual. Query params: rango (7d/30d/90d, default 30d)."""
    monitored = get_api_owned_domain(access_token)
    if monitored is None:
        return jsonify({"error": "No se encontró ese dominio."}), 404
    _, days = _parse_rango(allow_todos=False)
    return jsonify(get_impact_analysis(monitored, days))


@app.route("/api/v1/dominios/<access_token>/analisis-ia", methods=["GET"])
@require_api_key
def api_dominio_analisis_ia(access_token):
    """Análisis de salud DMARC generado por IA (equivalente a /tendencias/<token>/analisis-ia).
    `analisis` es `None` si no hay tráfico en el período o si la IA no está configurada/falla —
    se degrada sola, ver domain_health_analysis.py. Query params: rango (7d/30d/90d, default 30d)."""
    monitored = get_api_owned_domain(access_token)
    if monitored is None:
        return jsonify({"error": "No se encontró ese dominio."}), 404
    _, days = _parse_rango(allow_todos=False)
    trend_data = get_trends_data(monitored, days)
    analysis = None
    if trend_data["has_data"]:
        impact = get_impact_analysis(monitored, days)
        report_breakdown = get_report_breakdown(monitored, days)
        top_affected_senders = list_affected_senders(monitored, days, per_page=5)["items"]
        analysis = generate_health_analysis(monitored, trend_data, impact, report_breakdown, top_affected_senders)
    return jsonify({"analisis": analysis})


@app.route("/api/v1/cumplimiento", methods=["GET"])
@require_api_key
def api_cumplimiento():
    """Cumplimiento de TODOS los dominios monitoreados de la cuenta dueña de la key, de un vistazo
    (equivalente a /cumplimiento). No incluye el chequeo de DNS en vivo — eso es sólo para la UI
    (ver get_compliance_protocol_status en AGENTS.md), acá sólo lo ya calculado a partir de tráfico
    real. Query params: rango (7d/30d/90d, default 30d)."""
    _, days = _parse_rango(allow_todos=False)
    overview = get_compliance_overview(g.api_user.id, days)
    return jsonify({"dominios": [
        {
            "dominio": serialize_monitored_domain(item["monitored"]),
            "current_policy": item["current_policy"],
            "policy_label": item["policy_label"],
            "pass_rate": item["pass_rate"],
            "total": item["total"],
            "status": item["status"],
        }
        for item in overview
    ]})


def _serialize_dmarc_report_item(item):
    """item_serializer para serialize_paginated() — cada fila de list_dmarc_reports() trae objetos
    ORM (report/monitored) mezclados con campos ya calculados, a diferencia de list_domain_senders
    y compañía (que arman dicts planos). Un solo lugar con este mapeo, lo usan lista y detalle."""
    return {
        "informe": serialize_aggregate_report(item["report"]),
        "dominio": serialize_monitored_domain(item["monitored"]),
        "domain_shown": item["domain_shown"],
        "total": item["total"],
        "compliance_rate": item["compliance_rate"],
    }


@app.route("/api/v1/informes-dmarc", methods=["GET"])
@require_api_key
def api_informes_dmarc():
    """Lista paginada de todos los informes DMARC agregados de la cuenta, de todos sus dominios
    juntos (equivalente a /informes-dmarc). Query params: rango (7d/30d/90d/todos, default 30d),
    estado (todos/aprobado/con_fallas), q, page."""
    _, days = _parse_rango()
    estado = request.args.get("estado", "todos")
    q = request.args.get("q", "").strip()
    page = request.args.get("page", 1, type=int) or 1
    data = list_dmarc_reports(g.api_user.id, days=days, estado=estado, q=q, page=page)
    return jsonify(serialize_paginated(data, item_serializer=_serialize_dmarc_report_item))


@app.route("/api/v1/informes-dmarc/<int:report_id>", methods=["GET"])
@require_api_key
def api_informe_dmarc_detail(report_id):
    """Detalle de un informe DMARC agregado puntual: metadata + desglose SPF/DKIM + lista de
    registros (equivalente a /informes-dmarc/<id>). Igual que su equivalente web, sin bypass de
    admin — get_dmarc_report_detail() ya valida que el informe sea de un dominio de esta cuenta."""
    detail = get_dmarc_report_detail(report_id, g.api_user.id)
    if detail is None:
        return jsonify({"error": "No se encontró ese informe."}), 404
    return jsonify({
        "informe": serialize_aggregate_report(detail["report"]),
        "dominio": serialize_monitored_domain(detail["monitored"]),
        "domain_shown": detail["domain_shown"],
        "registros": [serialize_aggregate_record(r) for r in detail["records"]],
        "total": detail["total"],
        "compliance_rate": detail["compliance_rate"],
        "only_spf": detail["only_spf"],
        "only_dkim": detail["only_dkim"],
        "both_failed": detail["both_failed"],
    })


@app.route("/api/v1/tls-rpt", methods=["GET"])
@require_api_key
def api_tls_rpt():
    """Estado de verificación DNS de TLS-RPT de los dominios de la cuenta (equivalente a
    /reportes-tls-rpt). Query params: estado (todos/verificado/no_verificado)."""
    domains = list_domains(g.api_user.id)
    estado = request.args.get("estado", "todos")
    if estado == "verificado":
        domains = [d for d in domains if d.tls_rpt_verified]
    elif estado == "no_verificado":
        domains = [d for d in domains if not d.tls_rpt_verified]
    return jsonify({"dominios": [serialize_monitored_domain(d) for d in domains]})


@app.route("/api/v1/admin/usuarios", methods=["GET"])
@require_api_admin
def api_admin_usuarios():
    """Lista de todas las cuentas de la aplicación (equivalente a /admin/usuarios) — solo para una
    API key de cuenta admin. Query params: rol (todos/admin/cliente), estado (todos/activos/inactivos), q, page."""
    rol = request.args.get("rol", "todos")
    estado = request.args.get("estado", "todos")
    q = request.args.get("q", "").strip()
    page = request.args.get("page", 1, type=int) or 1
    data = list_users(rol=rol, estado=estado, q=q, page=page)
    return jsonify(serialize_paginated(data, item_serializer=lambda item: {
        "usuario": serialize_user(item["user"]),
        "domain_count": item["domain_count"],
        "plan_max_domains": item["plan_max_domains"],
        "plan_expires_label": item["plan_expires_label"],
        "plan_is_expired": item["plan_is_expired"],
        "plan_label": item["plan_label"],
    }))


@app.route("/api/v1/admin/usuarios/<int:user_id>", methods=["GET"])
@require_api_admin
def api_admin_usuario_detail(user_id):
    """Detalle de una cuenta puntual: perfil + plan (equivalente a /admin/usuarios/<id>/plan, sólo
    lectura acá) — solo para una API key de cuenta admin."""
    target_user = User.query.get(user_id)
    if target_user is None:
        return jsonify({"error": "No se encontró ese usuario."}), 404
    data = serialize_user(target_user)
    data["is_active"] = target_user.is_active
    data["has_api_key"] = bool(target_user.api_key_hash)
    data["api_key_active"] = target_user.api_key_active
    data["domains_used"] = count_active_domains(target_user.id)
    data["plan_form"] = get_user_plan_form_data(target_user.id)
    return jsonify(data)


@app.route("/reporte-pdf", methods=["GET"])
@login_required
def descargar_pdf():
    """Genera y descarga el PDF del reporte (ReportLab, sin dependencias de sistema) para el dominio indicado."""
    domain = request.args.get("domain", "").strip().lower()
    if not is_valid_domain(domain):
        abort(404)
    try:
        context = build_result_context(domain)
        pdf_bytes = build_pdf_bytes(context)
    except Exception as error:
        return render_template("partials/error.html", message=f"No se pudo generar el PDF: {error}"), 500
    filename = f"reporte-dmarc-{context['result_domain']}.pdf"
    return Response(
        pdf_bytes,
        mimetype="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@app.route("/registro", methods=["GET", "POST"])
def auth_register():
    """Crea una cuenta nueva; si se crea con éxito, inicia sesión y va al checker."""
    if current_user.is_authenticated:
        return redirect(url_for("inicio"))
    if request.method == "GET":
        return render_template("auth/register.html")

    name = request.form.get("name", "").strip()
    email = request.form.get("email", "").strip()
    password = request.form.get("password", "")

    if not name:
        return render_template("auth/register.html", error="Ingresa tu nombre.", name=name, email=email)
    if "@" not in email:
        return render_template("auth/register.html", error="Ingresa un correo válido.", name=name, email=email)
    if len(password) < 8:
        return render_template("auth/register.html", error="La contraseña debe tener al menos 8 caracteres.", name=name, email=email)

    user, error = register_user(name, email, password)
    if error:
        return render_template("auth/register.html", error=error, name=name, email=email)

    login_user(user)
    user.last_login_at = datetime.now(timezone.utc)
    db.session.commit()
    return redirect(url_for("inicio"))


@app.route("/ingresar", methods=["GET", "POST"])
def auth_login():
    """Inicia sesión con correo + contraseña; redirige a `next` si venía de una ruta protegida, o al checker."""
    if current_user.is_authenticated:
        return redirect(url_for("inicio"))
    if request.method == "GET":
        return render_template("auth/login.html")

    email = request.form.get("email", "").strip()
    password = request.form.get("password", "")

    user = authenticate(email, password)
    if not user:
        return render_template("auth/login.html", error="Correo o contraseña incorrectos.", email=email)
    if not user.is_active:
        return render_template("auth/login.html", error="Esta cuenta fue desactivada. Contactá al administrador.", email=email)

    login_user(user)
    user.last_login_at = datetime.now(timezone.utc)
    db.session.commit()
    next_url = request.args.get("next")
    return redirect(next_url or url_for("inicio"))


@app.route("/salir", methods=["POST"])
def auth_logout():
    """Cierra la sesión activa y va directo al login (evita el redirect de más hacia `/` que rebotaría igual)."""
    logout_user()
    return redirect(url_for("auth_login"))


@app.route("/cuenta", methods=["GET"])
@login_required
def account():
    """Perfil de la cuenta logueada: ver y actualizar correo/contraseña."""
    return render_template("auth/account.html")


@app.route("/cuenta/correo", methods=["POST"])
@login_required
def account_update_email():
    """Actualiza el nombre y el correo de la cuenta logueada."""
    ok, error = update_email(current_user, request.form.get("name", ""), request.form.get("email", ""))
    if not ok:
        return render_template("auth/account.html", email_error=error), 400
    return render_template("auth/account.html", email_success="Datos actualizados.")


@app.route("/cuenta/contrasena", methods=["POST"])
@login_required
def account_update_password():
    """Cambia la contraseña de la cuenta logueada — exige la actual para confirmarla."""
    ok, error = update_password(
        current_user,
        request.form.get("current_password", ""),
        request.form.get("new_password", ""),
    )
    if not ok:
        return render_template("auth/account.html", password_error=error), 400
    return render_template("auth/account.html", password_success="Contraseña actualizada.")


@app.route("/admin/usuarios", methods=["GET"])
@admin_required
def admin_users():
    """Panel de administración: lista de cuentas (clientes y administradores), solo para admins."""
    users_table = list_users()
    return render_template(
        "admin/users.html", users_table=users_table, rol="todos", estado="todos", q="",
    )


@app.route("/admin/usuarios/lista", methods=["GET"])
@admin_required
def admin_users_list():
    """Fragmento htmx: tabla de usuarios filtrada/paginada — separada de admin_users para que
    cambiar un filtro solo recalcule la tabla, mismo patrón que las demás tablas de la app."""
    rol = request.args.get("rol", "todos")
    estado = request.args.get("estado", "todos")
    q = request.args.get("q", "").strip()
    page = request.args.get("page", 1, type=int) or 1
    users_table = list_users(rol=rol, estado=estado, q=q, page=page)
    return render_template(
        "partials/admin_users_table.html", users_table=users_table, rol=rol, estado=estado, q=q,
    )


@app.route("/admin/usuarios/<int:user_id>/toggle", methods=["POST"])
@admin_required
def admin_toggle_user(user_id):
    """htmx: activa o desactiva una cuenta y devuelve la tabla actualizada con los mismos filtros
    que tenía (mandados por hx-include desde el form de filtros), más un toast de confirmación o error."""
    activar = request.form.get("activar") == "1"
    user, error = set_user_active(user_id, activar, current_user.id)
    if user is None:
        return render_template("partials/error.html", message="No se encontró ese usuario."), 404

    rol = request.form.get("rol", "todos")
    estado = request.form.get("estado", "todos")
    q = request.form.get("q", "").strip()
    page = request.form.get("page", 1, type=int) or 1
    users_table = list_users(rol=rol, estado=estado, q=q, page=page)

    if error == "self":
        toggle_message = "No podés desactivar tu propia cuenta."
        toggle_toast_type = "error"
    elif error == "last_admin":
        toggle_message = "No podés desactivar al último administrador activo."
        toggle_toast_type = "error"
    else:
        toggle_message = f"Cuenta {'activada' if activar else 'desactivada'} correctamente."
        toggle_toast_type = "success" if activar else "warning"

    return render_template(
        "partials/admin_users_table.html", users_table=users_table, rol=rol, estado=estado, q=q,
        toggle_message=toggle_message, toggle_toast_type=toggle_toast_type,
    )


@app.route("/admin/usuarios/<int:user_id>/plan", methods=["GET", "POST"])
@admin_required
def admin_edit_plan(user_id):
    """Formulario para que un admin edite el límite de dominios activos y la fecha de vencimiento
    del plan de cualquier usuario — crea el UserPlan si todavía no tenía uno propio."""
    target_user = User.query.get(user_id)
    if target_user is None:
        abort(404)
    plans = Plan.query.order_by(Plan.id).all()

    if request.method == "GET":
        form_data = get_user_plan_form_data(user_id)
        return render_template(
            "admin/edit_plan.html", target_user=target_user, form_data=form_data,
            default_max_domains=DEFAULT_MAX_DOMAINS, plans=plans,
        )

    max_domains_raw = request.form.get("max_domains", "").strip()
    expires_at_raw = request.form.get("expires_at", "").strip()

    error = None
    try:
        max_domains = int(max_domains_raw)
        if max_domains < 1:
            error = "El límite debe ser un número entero de al menos 1."
    except ValueError:
        max_domains = None
        error = "Ingresa un número entero válido para el límite."

    expires_at = None
    if not error and expires_at_raw:
        try:
            expires_at = datetime.strptime(expires_at_raw, "%Y-%m-%d").replace(
                hour=23, minute=59, second=59, tzinfo=timezone.utc
            )
        except ValueError:
            error = "Fecha de vencimiento inválida."

    if not error:
        _plan, error = update_user_plan(user_id, max_domains, expires_at)

    form_data = get_user_plan_form_data(user_id) if not error else {
        "max_domains": max_domains_raw, "expires_at_input": expires_at_raw, "is_expired": False, "plan_label": None,
    }
    if error:
        return render_template(
            "admin/edit_plan.html", target_user=target_user, form_data=form_data,
            default_max_domains=DEFAULT_MAX_DOMAINS, plans=plans, error=error,
        ), 400
    return render_template(
        "admin/edit_plan.html", target_user=target_user, form_data=form_data,
        default_max_domains=DEFAULT_MAX_DOMAINS, plans=plans, success="Plan actualizado correctamente.",
    )


@app.route("/admin/usuarios/<int:user_id>/plan/asignar", methods=["POST"])
@admin_required
def admin_assign_plan(user_id):
    """Atajo rápido para asignar un plan del catálogo (Free/Pago) a un usuario — alternativa a
    editar el límite/vencimiento a mano, más abajo en la misma página."""
    target_user = User.query.get(user_id)
    if target_user is None:
        abort(404)
    plans = Plan.query.order_by(Plan.id).all()

    plan_name = request.form.get("plan_name", "")
    _user_plan, error = assign_plan(user_id, plan_name)
    form_data = get_user_plan_form_data(user_id)
    if error:
        return render_template(
            "admin/edit_plan.html", target_user=target_user, form_data=form_data,
            default_max_domains=DEFAULT_MAX_DOMAINS, plans=plans, error=error,
        ), 400
    return render_template(
        "admin/edit_plan.html", target_user=target_user, form_data=form_data,
        default_max_domains=DEFAULT_MAX_DOMAINS, plans=plans,
        success=f"Plan actualizado a {form_data['plan_label']}.",
    )


@app.route("/admin/usuarios/<int:user_id>/api-key/generar", methods=["POST"])
@admin_required
def admin_generate_api_key(user_id):
    """Genera (o regenera) la API key de un usuario — solo un admin puede hacerlo, no es
    self-service (a pedido explícito). Se muestra en texto plano una sola vez, en esta misma
    respuesta — el admin es quien se la tiene que hacer llegar al usuario por fuera de la app.
    Regenerar invalida cualquier key anterior de inmediato."""
    target_user = User.query.get(user_id)
    if target_user is None:
        abort(404)
    plans = Plan.query.order_by(Plan.id).all()

    raw_key = generate_api_key(user_id)
    form_data = get_user_plan_form_data(user_id)
    return render_template(
        "admin/edit_plan.html", target_user=target_user, form_data=form_data,
        default_max_domains=DEFAULT_MAX_DOMAINS, plans=plans, new_api_key=raw_key,
    )


@app.route("/admin/usuarios/<int:user_id>/api-key/toggle", methods=["POST"])
@admin_required
def admin_toggle_api_key(user_id):
    """Activa o desactiva la API key de un usuario — solo un admin puede hacerlo (a propósito, no
    es self-service todavía). No la borra, es reversible."""
    target_user = User.query.get(user_id)
    if target_user is None:
        abort(404)
    plans = Plan.query.order_by(Plan.id).all()

    activar = request.form.get("activar") == "1"
    _user, error = set_api_key_active(user_id, activar)
    form_data = get_user_plan_form_data(user_id)
    if error == "no_key":
        return render_template(
            "admin/edit_plan.html", target_user=target_user, form_data=form_data,
            default_max_domains=DEFAULT_MAX_DOMAINS, plans=plans,
            error="Este usuario todavía no generó ninguna API key.",
        ), 400
    return render_template(
        "admin/edit_plan.html", target_user=target_user, form_data=form_data,
        default_max_domains=DEFAULT_MAX_DOMAINS, plans=plans,
        success=f"API key {'activada' if activar else 'desactivada'} correctamente.",
    )


@app.route("/monitoreo", methods=["GET", "POST"])
@login_required
def monitoring_register():
    """Formulario de alta de un dominio para monitoreo continuo (vigilancia DNS + reportes DMARC) — requiere sesión."""
    if request.method == "GET":
        return render_template("monitoring/register.html")

    domain = request.form.get("domain", "").strip().lower()
    owner_email = request.form.get("owner_email", "").strip()

    if not is_valid_domain(domain):
        return render_template(
            "monitoring/register.html",
            error="Ingresa un dominio válido, por ejemplo: tudominio.com",
            domain=domain, owner_email=owner_email,
        )
    if "@" not in owner_email:
        return render_template(
            "monitoring/register.html",
            error="Ingresa un correo válido para recibir las alertas.",
            domain=domain, owner_email=owner_email,
        )

    monitored, created, error = register_domain(domain, owner_email, current_user.id)
    if error == "other_user":
        return render_template(
            "monitoring/register.html",
            error="Ese dominio ya está siendo monitoreado por otra cuenta.",
            domain=domain, owner_email=owner_email,
        )
    if error == "limit_reached":
        limit = get_max_domains(current_user.id)
        return render_template(
            "monitoring/register.html",
            error=f"Alcanzaste el límite de {limit} dominios activos de tu plan. Desactivá alguno desde \"Monitores\" para poder registrar otro.",
            domain=domain, owner_email=owner_email,
        )
    dns, extra_dns = build_dns_screen_data(domain, DMARC_REPORTS_MAILBOX)
    return render_template(
        "monitoring/registered.html",
        monitored=monitored,
        rua_mailbox=DMARC_REPORTS_MAILBOX,
        just_registered=True,
        already_existed=not created,
        dns=dns,
        extra_dns=extra_dns,
    )


@app.route("/monitoreo/dns/preview", methods=["POST"])
def monitoring_dns_preview():
    """htmx: recalcula el Valor del registro DMARC según los controles de política (p/sp/pct/adkim/aspf) del generador."""
    value = build_dmarc_value(
        rua=request.form.get("rua", ""),
        ruf=request.form.get("ruf", ""),
        p=request.form.get("p", "none"),
        sp=request.form.get("sp", ""),
        pct=request.form.get("pct", "100"),
        adkim="s" if request.form.get("adkim") == "s" else "r",
        aspf="s" if request.form.get("aspf") == "s" else "r",
    )
    return render_template("partials/dns_value_preview.html", value=value)


@app.route("/monitoreo/<access_token>/configuracion-dns", methods=["GET"])
@login_required
def monitoring_dns(access_token):
    """Vuelve a mostrar las instrucciones de DNS (host/tipo/valor) de un dominio ya registrado."""
    monitored = get_owned_domain_or_404(access_token)
    dns, extra_dns = build_dns_screen_data(monitored.domain, DMARC_REPORTS_MAILBOX)
    return render_template(
        "monitoring/registered.html",
        monitored=monitored,
        rua_mailbox=DMARC_REPORTS_MAILBOX,
        just_registered=False,
        dns=dns,
        extra_dns=extra_dns,
    )


@app.route("/monitoreo/<access_token>/verificar-dns", methods=["POST"])
@login_required
def monitoring_verify_dns(access_token):
    """htmx: vuelve a consultar el DNS en vivo y guarda si ya se publicó la casilla de monitoreo en el rua=."""
    get_owned_domain_or_404(access_token)
    monitored = verify_dns(access_token, DMARC_REPORTS_MAILBOX)
    return render_template("partials/dns_verify_status.html", monitored=monitored)


@app.route("/monitoreo/<access_token>/verificar-tls-rpt", methods=["POST"])
@login_required
def monitoring_verify_tls_rpt(access_token):
    """htmx: vuelve a consultar el DNS en vivo y guarda si ya se publicó la casilla de monitoreo en el rua= de TLS-RPT."""
    get_owned_domain_or_404(access_token)
    monitored = verify_tls_rpt(access_token, DMARC_REPORTS_MAILBOX)
    return render_template("partials/tls_rpt_verify_status.html", monitored=monitored)


@app.route("/monitoreos/", methods=["GET"])
@login_required
def monitoring_list():
    """Lista de los dominios registrados para monitoreo por el usuario logueado — requiere sesión."""
    return render_template("monitoring/list.html", monitored_domains=list_domains(current_user.id))


@app.route("/cumplimiento", methods=["GET"])
@login_required
def compliance():
    """Vista de cumplimiento cross-dominio: para todos los dominios monitoreados del usuario, política
    DMARC actual y pass_rate de los últimos 30 días — la columna de DNS en vivo llega aparte por htmx."""
    overview = get_compliance_overview(current_user.id)
    return render_template("monitoring/compliance.html", overview=overview, protocol_status=None)


@app.route("/cumplimiento/protocolos", methods=["GET"])
@login_required
def compliance_protocol_status():
    """Fragmento htmx: chequeo de DNS en vivo de todos los dominios monitoreados del usuario, corridos
    en paralelo — cargado aparte de /cumplimiento para no bloquear su carga inicial."""
    overview = get_compliance_overview(current_user.id)
    protocol_status = get_compliance_protocol_status(list_domains(current_user.id))
    return render_template("partials/compliance_rows.html", overview=overview, protocol_status=protocol_status)


TRENDS_RANGE_DAYS = {"7d": 7, "30d": 30, "90d": 90}


def _parse_rango(allow_todos=True):
    """Lee ?rango= de la query string y lo traduce a días — mismo patrón que ya repiten las rutas
    web de remitentes/alertas/tendencias, extraído acá para los endpoints de la API nuevos.
    `allow_todos=False` para los que no soportan "todos" (ej. afectados, igual que su equivalente
    web trends_affected_senders)."""
    rango = request.args.get("rango", "30d")
    if allow_todos and rango == "todos":
        return rango, None
    if rango not in TRENDS_RANGE_DAYS:
        rango = "30d"
    return rango, TRENDS_RANGE_DAYS[rango]


@app.route("/reportes-tls-rpt", methods=["GET"])
@login_required
def tls_rpt_reports():
    """Lista filtrable de los dominios monitoreados con su estado de verificación DNS de TLS-RPT.

    No hay ingesta de reportes TLS-RPT reales todavía (parsedmarc no tiene cableado ese webhook,
    solo el de reportes DMARC agregados) — esto muestra sólo si el registro TLS-RPT ya quedó
    publicado con nuestra casilla de monitoreo, que es el mismo chequeo que ya existe en la
    pantalla de instrucciones de DNS de cada dominio."""
    domains = list_domains(current_user.id)
    estado = request.args.get("estado", "todos")
    if estado == "verificado":
        domains = [d for d in domains if d.tls_rpt_verified]
    elif estado == "no_verificado":
        domains = [d for d in domains if not d.tls_rpt_verified]
    return render_template("monitoring/tls_rpt_reports.html", domains=domains, estado=estado)


@app.route("/informes-dmarc", methods=["GET"])
@login_required
def dmarc_reports():
    """Lista paginada y filtrable de los reportes DMARC agregados de todos los dominios monitoreados del usuario."""
    rango = request.args.get("rango", "30d")
    if rango == "todos":
        days = None
    else:
        if rango not in TRENDS_RANGE_DAYS:
            rango = "30d"
        days = TRENDS_RANGE_DAYS[rango]
    estado = request.args.get("estado", "todos")
    q = request.args.get("q", "").strip()
    page = request.args.get("page", 1, type=int) or 1
    data = list_dmarc_reports(current_user.id, days=days, estado=estado, q=q, page=page)
    return render_template("monitoring/dmarc_reports.html", rango=rango, estado=estado, q=q, **data)


@app.route("/informes-dmarc/<int:report_id>", methods=["GET"])
@login_required
def dmarc_report_detail(report_id):
    """Detalle de un reporte DMARC agregado puntual: verdict, desglose SPF/DKIM y lista de remitentes."""
    detail = get_dmarc_report_detail(report_id, current_user.id)
    if not detail:
        abort(404)
    last_snapshot = detail["monitored"].snapshots.order_by(DomainSnapshot.checked_at.desc()).first()
    current_policy = (last_snapshot.raw_data or {}).get("dmarc_policy") if last_snapshot else None
    detail["policy_label"] = DMARC_POLICY_LABELS.get(current_policy, (current_policy or "Desconocida", None))[0]
    return render_template("monitoring/dmarc_report_detail.html", **detail)


@app.route("/tendencias", methods=["GET"])
@login_required
def trends():
    """Muestra el selector de dominio sin cargar ninguno por defecto — antes redirigía directo a un
    dominio (con sus queries de reportes + chequeo de DNS), lo que hacía sentir lenta la sola entrada
    al link del sidebar. Elegir un dominio queda en manos del usuario."""
    return render_template("monitoring/trends.html", domains=list_domains(current_user.id), monitored=None)


@app.route("/tendencias/<access_token>", methods=["GET"])
@login_required
def trends_domain(access_token):
    """Página de tendencias (tasa de cumplimiento + volumen pass/fail) de un dominio monitoreado del usuario logueado.

    El estado del protocolo (chequeo de DNS en vivo) NO se calcula acá — se carga aparte vía htmx
    (trends_protocol_status) para no bloquear esta página con una consulta de DNS que puede tardar
    varios segundos; antes hacía que todo /tendencias se sintiera lento."""
    monitored = get_owned_domain_or_404(access_token)
    rango = request.args.get("rango", "30d")
    if rango not in TRENDS_RANGE_DAYS:
        rango = "30d"
    trend_data = get_trends_data(monitored, TRENDS_RANGE_DAYS[rango])
    policy_label = DMARC_POLICY_LABELS.get(trend_data["dmarc_policy"], (trend_data["dmarc_policy"] or "Desconocida", None))[0]
    report_breakdown = get_report_breakdown(monitored, TRENDS_RANGE_DAYS[rango])
    impact = get_impact_analysis(monitored, TRENDS_RANGE_DAYS[rango])
    impact["current_policy_label"] = DMARC_POLICY_LABELS.get(impact["current_policy"], (impact["current_policy"] or "Desconocida", None))[0]
    affected_table = list_affected_senders(monitored, TRENDS_RANGE_DAYS[rango])
    return render_template(
        "monitoring/trends.html",
        domains=list_domains(current_user.id),
        monitored=monitored,
        rango=rango,
        trend_data=trend_data,
        impact=impact,
        policy_label=policy_label,
        report_breakdown=report_breakdown,
        affected_table=affected_table,
        affected_q="",
    )


@app.route("/tendencias/<access_token>/afectados", methods=["GET"])
@login_required
def trends_affected_senders(access_token):
    """Fragmento htmx: tabla de emisores afectados del análisis de impacto, filtrada/paginada —
    separada de trends_domain para que buscar/paginar no recalcule toda la página de Tendencias."""
    monitored = get_owned_domain_or_404(access_token)
    rango = request.args.get("rango", "30d")
    if rango not in TRENDS_RANGE_DAYS:
        rango = "30d"
    q = request.args.get("q", "").strip()
    page = request.args.get("page", 1, type=int) or 1
    affected_table = list_affected_senders(monitored, TRENDS_RANGE_DAYS[rango], q=q, page=page)
    return render_template(
        "partials/affected_senders_table.html",
        monitored=monitored, affected_table=affected_table, rango=rango, affected_q=q,
    )


@app.route("/tendencias/<access_token>/protocolo", methods=["GET"])
@login_required
def trends_protocol_status(access_token):
    """Fragmento htmx: chequeo de DNS en vivo (mismo pipeline que el checker de '/'), cargado aparte
    de trends_domain para no bloquear la carga inicial de Tendencias con una consulta de DNS lenta."""
    monitored = get_owned_domain_or_404(access_token)
    try:
        protocol_cards = build_cards(run_check(monitored.domain))
    except Exception as error:
        print(f"[trends_protocol_status] no se pudo chequear el DNS de {monitored.domain}: {error}")
        protocol_cards = None
    return render_template("partials/protocol_status.html", protocol_cards=protocol_cards)


@app.route("/tendencias/<access_token>/analisis-ia", methods=["GET"])
@login_required
def trends_ai_analysis(access_token):
    """Fragmento htmx: análisis de salud DMARC generado por IA (services/domain_health_analysis.py),
    a partir de los mismos datos ya calculados en trends_domain — no repite el chequeo de DNS en vivo,
    ese ya se carga aparte en trends_protocol_status. Cargado en su propia petición para no sumarle
    la latencia de la IA a la carga inicial de la página."""
    monitored = get_owned_domain_or_404(access_token)
    rango = request.args.get("rango", "30d")
    if rango not in TRENDS_RANGE_DAYS:
        rango = "30d"
    days = TRENDS_RANGE_DAYS[rango]
    trend_data = get_trends_data(monitored, days)
    impact = get_impact_analysis(monitored, days)
    report_breakdown = get_report_breakdown(monitored, days)
    analysis = None
    if trend_data["has_data"]:
        top_affected_senders = list_affected_senders(monitored, days, per_page=5)["items"]
        analysis = generate_health_analysis(monitored, trend_data, impact, report_breakdown, top_affected_senders)
    return render_template("partials/ai_health_analysis.html", analysis=analysis, monitored=monitored)


@app.route("/monitoreo/<access_token>/alertas", methods=["GET"])
@login_required
def monitoring_dashboard_alerts(access_token):
    """Fragmento htmx: tabla de alertas del dominio, filtrada/paginada — separada de
    monitoring_dashboard por el mismo motivo que monitoring_dashboard_senders."""
    monitored = get_owned_domain_or_404(access_token)

    rango = request.args.get("rango", "30d")
    if rango == "todos":
        days = None
    else:
        if rango not in TRENDS_RANGE_DAYS:
            rango = "30d"
        days = TRENDS_RANGE_DAYS[rango]
    tipo = request.args.get("tipo", "todos")
    q = request.args.get("q", "").strip()
    page = request.args.get("page", 1, type=int) or 1
    alerts_table = list_domain_alerts(monitored, days=days, tipo=tipo, q=q, page=page)

    return render_template(
        "partials/domain_alerts_table.html",
        monitored=monitored, alerts_table=alerts_table,
        alerts_rango=rango, alerts_tipo=tipo, alerts_q=q,
    )


@app.route("/monitoreo/<access_token>/remitentes", methods=["GET"])
@login_required
def monitoring_dashboard_senders(access_token):
    """Fragmento htmx: tabla de remitentes reales del dominio, filtrada/paginada — separada de
    monitoring_dashboard para que cambiar un filtro solo recalcule la tabla, no toda la página
    (alertas, desglose por subdominio, reportes forenses)."""
    monitored = get_owned_domain_or_404(access_token)

    rango = request.args.get("rango", "30d")
    if rango == "todos":
        days = None
    else:
        if rango not in TRENDS_RANGE_DAYS:
            rango = "30d"
        days = TRENDS_RANGE_DAYS[rango]
    estado = request.args.get("estado", "todos")
    q = request.args.get("q", "").strip()
    page = request.args.get("page", 1, type=int) or 1
    senders = list_domain_senders(monitored, days=days, estado=estado, q=q, page=page)

    return render_template(
        "partials/domain_senders_table.html",
        monitored=monitored, senders=senders, rango=rango, estado=estado, q=q,
    )


@app.route("/monitoreo/<access_token>", methods=["GET"])
@login_required
def monitoring_dashboard(access_token):
    """Dashboard privado de un dominio monitoreado: remitentes reales (agrupados y filtrables) y alertas generadas."""
    get_owned_domain_or_404(access_token)
    data = get_dashboard_data(access_token)

    rango = request.args.get("rango", "30d")
    if rango == "todos":
        days = None
    else:
        if rango not in TRENDS_RANGE_DAYS:
            rango = "30d"
        days = TRENDS_RANGE_DAYS[rango]
    estado = request.args.get("estado", "todos")
    q = request.args.get("q", "").strip()
    page = request.args.get("page", 1, type=int) or 1
    senders = list_domain_senders(data["monitored"], days=days, estado=estado, q=q, page=page)
    # Filtros propios con nombres fijos (no leídos de la URL): esta página comparte
    # rango/estado/q/page con la tabla de remitentes de arriba — leer los mismos query
    # params para esta tabla los pisaría entre sí. Sin hx-push-url en ninguna de las
    # dos tablas, la URL de la página nunca refleja el filtro activo, así que no hay
    # necesidad real de deep-linking al estado filtrado de esta tabla en particular.
    alerts_table = list_domain_alerts(data["monitored"], days=30, tipo="todos", q="", page=1)

    return render_template(
        "monitoring/dashboard.html", rua_mailbox=DMARC_REPORTS_MAILBOX,
        alerts_table=alerts_table, alerts_rango="30d", alerts_tipo="todos", alerts_q="",
        subdomain_breakdown=get_subdomain_breakdown(data["monitored"]),
        senders=senders, rango=rango, estado=estado, q=q, **data,
    )


@app.route("/monitoreo/<access_token>/reporte-pdf", methods=["GET"])
@login_required
def monitoring_dashboard_pdf(access_token):
    """Genera y descarga el PDF del dashboard de monitoreo (alertas recientes + reportes DMARC recibidos)."""
    get_owned_domain_or_404(access_token)
    data = get_dashboard_data(access_token)
    try:
        context = {**data, "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")}
        pdf_bytes = build_dashboard_pdf_bytes(context)
    except Exception as error:
        return render_template("partials/error.html", message=f"No se pudo generar el PDF: {error}"), 500
    filename = f"monitoreo-dmarc-{data['monitored'].domain}.pdf"
    return Response(
        pdf_bytes,
        mimetype="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@app.route("/monitoreo/<access_token>/toggle", methods=["POST"])
@login_required
def monitoring_toggle(access_token):
    """htmx: activa o desactiva el monitoreo de un dominio (no borra su historial) y devuelve el
    fragmento de estado actualizado — no recarga la página. El toast de confirmación se dispara
    con un <script> dentro del propio fragmento (partials/monitoring_toggle_status.html) — NO por
    el header HX-Trigger: ese evento se dispara sobre el <form> que hizo la petición, y ese <form>
    queda desconectado del DOM justo cuando se reemplaza #toggle-status-region (swap outerHTML),
    así que nunca llega a burbujear hasta un listener en document.body."""
    get_owned_domain_or_404(access_token)
    activar = request.form.get("activar") == "1"
    monitored, error = set_active(access_token, activar)
    data = get_dashboard_data(access_token)
    if error == "limit_reached":
        limit = get_max_domains(monitored.user_id)
        return render_template(
            "partials/monitoring_toggle_status.html",
            monitored=monitored, reports=data["reports"],
            toggle_message=f"No se pudo activar: alcanzaste el límite de {limit} dominios activos de tu plan.",
            toggle_toast_type="error",
        )
    return render_template(
        "partials/monitoring_toggle_status.html",
        monitored=monitored, reports=data["reports"],
        toggle_message=f"Dominio {'activado' if activar else 'desactivado'} correctamente.",
        toggle_toast_type="success" if activar else "warning",
    )


@app.route("/webhooks/dmarc-aggregate/<secret>", methods=["POST"])
def webhook_dmarc_aggregate(secret):
    """Recibe el JSON de un reporte DMARC agregado ya parseado por parsedmarc (salida 'webhook' de su config)."""
    if not DMARC_WEBHOOK_SECRET or not secrets.compare_digest(secret, DMARC_WEBHOOK_SECRET):
        abort(404)  # 404 en vez de 401: no delatar que la ruta existe a quien no trae el secreto
    payload = request.get_json(silent=True) or {}
    try:
        ingest_aggregate_report(payload)
    except Exception as error:
        # Nunca devolver 500 acá: un payload inesperado no debe hacer que
        # parsedmarc reintente indefinidamente la misma entrega.
        db.session.rollback()
        print(f"[webhook_dmarc_aggregate] error procesando payload: {error}")
    return jsonify({"status": "ok"}), 200


@app.route("/webhooks/dmarc-forensic/<secret>", methods=["POST"])
def webhook_dmarc_forensic(secret):
    """Recibe el JSON de un reporte forense (RUF) ya parseado por parsedmarc (salida 'webhook' -> failure_url)."""
    if not DMARC_WEBHOOK_SECRET or not secrets.compare_digest(secret, DMARC_WEBHOOK_SECRET):
        abort(404)  # 404 en vez de 401: no delatar que la ruta existe a quien no trae el secreto
    payload = request.get_json(silent=True) or {}
    try:
        ingest_forensic_report(payload)
    except Exception as error:
        # Nunca devolver 500 acá: un payload inesperado no debe hacer que
        # parsedmarc reintente indefinidamente la misma entrega.
        db.session.rollback()
        print(f"[webhook_dmarc_forensic] error procesando payload: {error}")
    return jsonify({"status": "ok"}), 200


def _run_recheck_domains_job():
    """Corre jobs/recheck_domains.py dentro del mismo proceso web (ver start_scheduler())."""
    from jobs.recheck_domains import main as recheck_domains_main  # import diferido: evita ciclo con este módulo
    try:
        recheck_domains_main()
    except Exception as error:
        db.session.rollback()
        print(f"[scheduler] error en recheck_domains: {error}")


def _run_deactivate_expired_trials_job():
    """Corre jobs/deactivate_expired_trials.py dentro del mismo proceso web (ver start_scheduler())."""
    from jobs.deactivate_expired_trials import main as deactivate_expired_trials_main  # import diferido
    try:
        deactivate_expired_trials_main()
    except Exception as error:
        db.session.rollback()
        print(f"[scheduler] error en deactivate_expired_trials: {error}")


def start_scheduler():
    """Programa la vigilancia DNS periódica (antes un Railway Cron aparte, servicio 'recheck-domains-cron')
    y la desactivación de dominios con plan vencido, para correr dentro de este mismo proceso — sólo
    válido mientras el servicio corra una única instancia (sin réplicas), o los jobs se dispararían
    una vez por instancia."""
    from apscheduler.schedulers.background import BackgroundScheduler

    interval_hours = float(os.environ.get("RECHECK_DOMAINS_INTERVAL_HOURS", "12"))
    trials_interval_hours = float(os.environ.get("CHECK_TRIALS_INTERVAL_HOURS", "6"))
    scheduler = BackgroundScheduler(timezone="UTC")
    scheduler.add_job(_run_recheck_domains_job, "interval", hours=interval_hours, next_run_time=datetime.now(timezone.utc))
    scheduler.add_job(_run_deactivate_expired_trials_job, "interval", hours=trials_interval_hours, next_run_time=datetime.now(timezone.utc))
    scheduler.start()


if __name__ == "__main__":
    # Railway (y la mayoría de PaaS) inyectan el puerto real en $PORT y sólo
    # enrutan tráfico a 0.0.0.0 — escuchar en 127.0.0.1:5000 fijo no es alcanzable
    # desde afuera del contenedor.
    debug_mode = os.environ.get("FLASK_DEBUG", "false").lower() == "true"

    # Con el reloader de Flask activo (debug_mode), este bloque se ejecuta dos
    # veces (proceso "watcher" + proceso worker real) — sólo arrancar el
    # scheduler en el worker real, o quedarían dos corriendo en paralelo.
    if not debug_mode or os.environ.get("WERKZEUG_RUN_MAIN") == "true":
        start_scheduler()
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=debug_mode)
