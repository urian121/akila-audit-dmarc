import os
import secrets
from datetime import datetime, timezone

from dotenv import load_dotenv
from flask import Flask, Response, abort, jsonify, redirect, render_template, request, url_for
from flask_login import LoginManager, current_user, login_required, login_user, logout_user

from models import DomainSnapshot, User, db
from services.ai_summary import generate_summary
from services.auth_service import authenticate, register_user, update_email, update_password
from services.card_builder import DMARC_POLICY_LABELS, build_cards, build_risks, build_summary
from services.checkdmarc_service import build_dns_screen_data, run_check
from services.domain_health_analysis import generate_health_analysis
from services.pdf_service import build_dashboard_pdf_bytes, build_pdf_bytes
from utils.dmarc_builder import build_dmarc_value
from services.monitoring_service import get_compliance_overview, get_compliance_protocol_status, get_dashboard_data, get_dmarc_report_detail, get_domain_by_token, get_impact_analysis, get_report_breakdown, get_subdomain_breakdown, get_trends_data, list_domain_alerts, list_domain_senders, list_domains, list_dmarc_reports, register_domain, set_active, verify_dns, verify_tls_rpt
from services.forensic_reports_service import ingest_forensic_report
from services.reports_service import ingest_aggregate_report
from utils.domain_validation import is_valid_domain

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
def check(domain):
    """API JSON pública (sin sesión, a propósito): ejecuta la auditoría del dominio indicado y la devuelve completa."""
    custom_selector = request.args.get("selector")
    result = run_check(domain, custom_selector)
    return jsonify(result)


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

    login_user(user)
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

    monitored, created = register_domain(domain, owner_email, current_user.id)
    if monitored is None:
        return render_template(
            "monitoring/register.html",
            error="Ese dominio ya está siendo monitoreado por otra cuenta.",
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
def monitoring_dns(access_token):
    """Vuelve a mostrar las instrucciones de DNS (host/tipo/valor) de un dominio ya registrado."""
    monitored = get_domain_by_token(access_token)
    if monitored is None:
        return render_template("partials/error.html", message="No se encontró ese dashboard."), 404
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
def monitoring_verify_dns(access_token):
    """htmx: vuelve a consultar el DNS en vivo y guarda si ya se publicó la casilla de monitoreo en el rua=."""
    monitored = verify_dns(access_token, DMARC_REPORTS_MAILBOX)
    if monitored is None:
        return render_template("partials/error.html", message="No se encontró ese dashboard."), 404
    return render_template("partials/dns_verify_status.html", monitored=monitored)


@app.route("/monitoreo/<access_token>/verificar-tls-rpt", methods=["POST"])
def monitoring_verify_tls_rpt(access_token):
    """htmx: vuelve a consultar el DNS en vivo y guarda si ya se publicó la casilla de monitoreo en el rua= de TLS-RPT."""
    monitored = verify_tls_rpt(access_token, DMARC_REPORTS_MAILBOX)
    if monitored is None:
        return render_template("partials/error.html", message="No se encontró ese dashboard."), 404
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
    monitored = get_domain_by_token(access_token)
    if not monitored or monitored.user_id != current_user.id:
        abort(404)
    rango = request.args.get("rango", "30d")
    if rango not in TRENDS_RANGE_DAYS:
        rango = "30d"
    trend_data = get_trends_data(monitored, TRENDS_RANGE_DAYS[rango])
    policy_label = DMARC_POLICY_LABELS.get(trend_data["dmarc_policy"], (trend_data["dmarc_policy"] or "Desconocida", None))[0]
    report_breakdown = get_report_breakdown(monitored, TRENDS_RANGE_DAYS[rango])
    impact = get_impact_analysis(monitored, TRENDS_RANGE_DAYS[rango])
    impact["current_policy_label"] = DMARC_POLICY_LABELS.get(impact["current_policy"], (impact["current_policy"] or "Desconocida", None))[0]
    return render_template(
        "monitoring/trends.html",
        domains=list_domains(current_user.id),
        monitored=monitored,
        rango=rango,
        trend_data=trend_data,
        impact=impact,
        policy_label=policy_label,
        report_breakdown=report_breakdown,
    )


@app.route("/tendencias/<access_token>/protocolo", methods=["GET"])
@login_required
def trends_protocol_status(access_token):
    """Fragmento htmx: chequeo de DNS en vivo (mismo pipeline que el checker de '/'), cargado aparte
    de trends_domain para no bloquear la carga inicial de Tendencias con una consulta de DNS lenta."""
    monitored = get_domain_by_token(access_token)
    if not monitored or monitored.user_id != current_user.id:
        abort(404)
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
    monitored = get_domain_by_token(access_token)
    if not monitored or monitored.user_id != current_user.id:
        abort(404)
    rango = request.args.get("rango", "30d")
    if rango not in TRENDS_RANGE_DAYS:
        rango = "30d"
    days = TRENDS_RANGE_DAYS[rango]
    trend_data = get_trends_data(monitored, days)
    impact = get_impact_analysis(monitored, days)
    report_breakdown = get_report_breakdown(monitored, days)
    analysis = None
    if trend_data["has_data"]:
        analysis = generate_health_analysis(monitored, trend_data, impact, report_breakdown)
    return render_template("partials/ai_health_analysis.html", analysis=analysis, monitored=monitored)


@app.route("/monitoreo/<access_token>/alertas", methods=["GET"])
def monitoring_dashboard_alerts(access_token):
    """Fragmento htmx: tabla de alertas del dominio, filtrada/paginada — separada de
    monitoring_dashboard por el mismo motivo que monitoring_dashboard_senders."""
    monitored = get_domain_by_token(access_token)
    if monitored is None:
        return render_template("partials/error.html", message="No se encontró ese dashboard."), 404

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
def monitoring_dashboard_senders(access_token):
    """Fragmento htmx: tabla de remitentes reales del dominio, filtrada/paginada — separada de
    monitoring_dashboard para que cambiar un filtro solo recalcule la tabla, no toda la página
    (alertas, desglose por subdominio, reportes forenses)."""
    monitored = get_domain_by_token(access_token)
    if monitored is None:
        return render_template("partials/error.html", message="No se encontró ese dashboard."), 404

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
def monitoring_dashboard(access_token):
    """Dashboard privado de un dominio monitoreado: remitentes reales (agrupados y filtrables) y alertas generadas."""
    data = get_dashboard_data(access_token)
    if data is None:
        return render_template("partials/error.html", message="No se encontró ese dashboard."), 404

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
def monitoring_dashboard_pdf(access_token):
    """Genera y descarga el PDF del dashboard de monitoreo (alertas recientes + reportes DMARC recibidos)."""
    data = get_dashboard_data(access_token)
    if data is None:
        return render_template("partials/error.html", message="No se encontró ese dashboard."), 404
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
def monitoring_toggle(access_token):
    """htmx: activa o desactiva el monitoreo de un dominio (no borra su historial) y devuelve el
    fragmento de estado actualizado — no recarga la página. El toast de confirmación se dispara
    con un <script> dentro del propio fragmento (partials/monitoring_toggle_status.html) — NO por
    el header HX-Trigger: ese evento se dispara sobre el <form> que hizo la petición, y ese <form>
    queda desconectado del DOM justo cuando se reemplaza #toggle-status-region (swap outerHTML),
    así que nunca llega a burbujear hasta un listener en document.body."""
    activar = request.form.get("activar") == "1"
    monitored = set_active(access_token, activar)
    if monitored is None:
        return render_template("partials/error.html", message="No se encontró ese dashboard."), 404

    data = get_dashboard_data(access_token)
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


def start_scheduler():
    """Programa la vigilancia DNS periódica (antes un Railway Cron aparte, servicio 'recheck-domains-cron')
    para correr dentro de este mismo proceso — sólo válido mientras el servicio corra una única instancia
    (sin réplicas), o el job se dispararía una vez por instancia."""
    from apscheduler.schedulers.background import BackgroundScheduler

    interval_hours = float(os.environ.get("RECHECK_DOMAINS_INTERVAL_HOURS", "12"))
    scheduler = BackgroundScheduler(timezone="UTC")
    scheduler.add_job(_run_recheck_domains_job, "interval", hours=interval_hours, next_run_time=datetime.now(timezone.utc))
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
