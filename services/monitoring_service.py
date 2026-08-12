import re
from concurrent.futures import ThreadPoolExecutor
from datetime import timedelta

from sqlalchemy import case, func, or_

from models import Alert, AggregateRecord, AggregateReport, DomainSnapshot, ForensicReport, MonitoredDomain, User, UserPlan, db
from models.user import DEFAULT_MAX_DOMAINS
from models.monitoring import utcnow
from services.card_builder import DMARC_POLICY_LABELS, build_summary
from services.checkdmarc_service import dns_has_mailbox_in_rua, dns_has_mailbox_in_tls_rpt_rua, run_check

# Mismo texto armado en detect_unknown_senders() (reports_service.py) — si se
# cambia esa frase, ajustar este patrón también, o el agrupado deja de reconocer
# el nombre del remitente y todo cae en "remitente sin identificar".
_UNKNOWN_SENDER_ORG_PATTERN = re.compile(r"^Correo enviado desde (.+?) \(")


def get_max_domains(user_id):
    """Límite de dominios ACTIVOS que puede tener este usuario, o None si no tiene límite.

    Los administradores no tienen límite (`None`) — son quienes administran la herramienta, no
    tiene sentido pedirles un plan para usar su propia cuenta. Para el resto: el de su UserPlan si
    tiene uno asignado y no venció, o DEFAULT_MAX_DOMAINS si no tiene uno o si ya venció (vuelve
    sola al default, no bloquea todo — ver comentario en UserPlan.expires_at).

    Todo caller debe tratar `None` como "sin límite" (no comparar directo con `>=`) — ver
    register_domain()/set_active() más abajo."""
    user = User.query.get(user_id)
    if user and user.is_admin:
        return None
    plan = UserPlan.query.filter_by(user_id=user_id).first()
    if not plan or (plan.expires_at and plan.expires_at < utcnow()):
        return DEFAULT_MAX_DOMAINS
    return plan.max_domains


def get_user_plan_form_data(user_id):
    """Valores actuales del plan de un usuario, para precargar el formulario de edición del admin
    — el default si todavía no tiene una fila propia en UserPlan."""
    plan = UserPlan.query.filter_by(user_id=user_id).first()
    if not plan:
        return {"max_domains": DEFAULT_MAX_DOMAINS, "expires_at_input": "", "is_expired": False}
    is_expired = bool(plan.expires_at and plan.expires_at < utcnow())
    return {
        "max_domains": plan.max_domains,
        "expires_at_input": plan.expires_at.strftime("%Y-%m-%d") if plan.expires_at else "",
        "is_expired": is_expired,
    }


def update_user_plan(user_id, max_domains, expires_at):
    """Crea o actualiza (upsert) el plan de un usuario — sólo lo llama el admin desde
    /admin/usuarios/<id>/plan. `expires_at` ya viene como datetime (o None para sin vencimiento),
    parseado por la ruta. Devuelve (plan, error)."""
    if not User.query.get(user_id):
        return None, "No se encontró ese usuario."
    if max_domains < 1:
        return None, "El límite debe ser un número entero de al menos 1."

    plan = UserPlan.query.filter_by(user_id=user_id).first()
    if not plan:
        plan = UserPlan(user_id=user_id)
        db.session.add(plan)
    plan.max_domains = max_domains
    plan.expires_at = expires_at
    db.session.commit()
    return plan, None


def count_active_domains(user_id):
    """Cuántos dominios tiene este usuario con is_active=True ahora mismo — lo que cuenta contra su límite."""
    return MonitoredDomain.query.filter_by(user_id=user_id, is_active=True).count()


def register_domain(domain, owner_email, user_id):
    """Da de alta un dominio para monitoreo continuo bajo `user_id`; si ya estaba registrado por el
    mismo usuario pero inactivo, lo reactiva. Antes de crear una fila nueva o reactivar una pausada
    (ambos casos suman un dominio activo) valida el límite de su plan — reactivar uno que ya está
    activo (re-envío del mismo formulario) no cuenta de nuevo.

    Devuelve (monitored, created, error). `error` es None si salió bien, "other_user" si el dominio
    ya está registrado por otra cuenta, o "limit_reached" si el usuario ya está en su límite de
    dominios activos (`monitored` viene None en ambos casos de error).
    """
    limit = get_max_domains(user_id)
    existing = MonitoredDomain.query.filter_by(domain=domain).first()
    if existing:
        if existing.user_id != user_id:
            return None, False, "other_user"
        if not existing.is_active:
            if limit is not None and count_active_domains(user_id) >= limit:
                return None, False, "limit_reached"
            existing.is_active = True
            db.session.commit()
        return existing, False, None

    if limit is not None and count_active_domains(user_id) >= limit:
        return None, False, "limit_reached"
    monitored = MonitoredDomain(domain=domain, owner_email=owner_email, user_id=user_id)
    db.session.add(monitored)
    db.session.commit()
    return monitored, True, None


def get_domain_by_token(access_token):
    """Busca un dominio monitoreado por su access_token (None si no existe)."""
    return MonitoredDomain.query.filter_by(access_token=access_token).first()


def verify_dns(access_token, mailbox):
    """Vuelve a consultar el DNS en vivo y guarda si ya se publicó la casilla de monitoreo en el rua=. Devuelve None si el token no existe."""
    monitored = get_domain_by_token(access_token)
    if not monitored:
        return None
    monitored.dns_verified = dns_has_mailbox_in_rua(monitored.domain, mailbox)
    monitored.dns_verified_at = utcnow()
    db.session.commit()
    return monitored


def verify_tls_rpt(access_token, mailbox):
    """Vuelve a consultar el DNS en vivo y guarda si ya se publicó la casilla de monitoreo en el rua= de TLS-RPT. Devuelve None si el token no existe."""
    monitored = get_domain_by_token(access_token)
    if not monitored:
        return None
    monitored.tls_rpt_verified = dns_has_mailbox_in_tls_rpt_rua(monitored.domain, mailbox)
    monitored.tls_rpt_verified_at = utcnow()
    db.session.commit()
    return monitored


def set_active(access_token, is_active):
    """Activa o desactiva el monitoreo de un dominio (no borra su historial).

    Devuelve (monitored, error). `monitored` es None sólo si el token no existe. Si se intenta
    activar y el usuario ya está en su límite de dominios activos, no lo activa y devuelve el
    `monitored` sin cambios junto con error="limit_reached" (dominios sin dueño —`user_id` nulo,
    legado de antes del login— no tienen plan que hacer cumplir, se activan sin chequeo)."""
    monitored = MonitoredDomain.query.filter_by(access_token=access_token).first()
    if not monitored:
        return None, None
    if is_active and not monitored.is_active and monitored.user_id is not None:
        limit = get_max_domains(monitored.user_id)
        if limit is not None and count_active_domains(monitored.user_id) >= limit:
            return monitored, "limit_reached"
    monitored.is_active = is_active
    db.session.commit()
    return monitored, None


def list_domains(user_id):
    """Devuelve los dominios registrados para monitoreo por este usuario, más recientes primero."""
    return MonitoredDomain.query.filter_by(user_id=user_id).order_by(MonitoredDomain.created_at.desc()).all()


def get_dashboard_data(access_token):
    """Arma los datos del dashboard privado de un dominio monitoreado (None si el token no existe)."""
    monitored = get_domain_by_token(access_token)
    if not monitored:
        return None
    alerts = monitored.alerts.order_by(Alert.created_at.desc()).limit(50).all()
    reports = monitored.aggregate_reports.order_by(AggregateReport.received_at.desc()).limit(20).all()
    forensic_reports = monitored.forensic_reports.order_by(ForensicReport.received_at.desc()).limit(20).all()
    return {"monitored": monitored, "alerts": alerts, "reports": reports, "forensic_reports": forensic_reports}


_MESES_ES = [
    "enero", "febrero", "marzo", "abril", "mayo", "junio",
    "julio", "agosto", "septiembre", "octubre", "noviembre", "diciembre",
]


def get_trends_data(monitored, days):
    """Arma volumen pass/fail por día y tasa de cumplimiento de los últimos `days` días,
    a partir de los reportes DMARC agregados reales ya recibidos para este dominio.
    Rellena los días sin reporte con 0 (compliance_series con None ese día, para no
    dibujar un 0% falso donde en realidad no hubo tráfico que medir).

    Una sola consulta SQL agregada (GROUP BY día) en vez de recorrer reporte por reporte
    en Python — antes disparaba una query de records por cada AggregateReport (N+1),
    notable con varias decenas de informes."""
    cutoff = utcnow() - timedelta(days=days)
    daily_rows = (
        db.session.query(
            func.date(AggregateReport.date_begin).label("day"),
            func.sum(case((AggregateRecord.dmarc_aligned.is_(True), AggregateRecord.count), else_=0)).label("passed"),
            func.sum(case((AggregateRecord.dmarc_aligned.is_(False), AggregateRecord.count), else_=0)).label("failed"),
        )
        .join(AggregateReport, AggregateRecord.report_id == AggregateReport.id)
        .filter(AggregateReport.monitored_domain_id == monitored.id, AggregateReport.date_begin >= cutoff)
        .group_by(func.date(AggregateReport.date_begin))
        .all()
    )
    daily = {row.day: {"pass": row.passed or 0, "fail": row.failed or 0} for row in daily_rows if row.day}

    today = utcnow().date()
    labels, pass_series, fail_series, compliance_series = [], [], [], []
    for offset in range(days - 1, -1, -1):
        day = today - timedelta(days=offset)
        bucket = daily.get(day, {"pass": 0, "fail": 0})
        total = bucket["pass"] + bucket["fail"]
        labels.append(day.strftime("%Y-%m-%d"))
        pass_series.append(bucket["pass"])
        fail_series.append(bucket["fail"])
        compliance_series.append(round(bucket["pass"] / total * 100, 1) if total else None)

    total_pass = sum(pass_series)
    total_fail = sum(fail_series)
    total = total_pass + total_fail

    last_snapshot = monitored.snapshots.order_by(DomainSnapshot.checked_at.desc()).first()
    dmarc_policy = (last_snapshot.raw_data or {}).get("dmarc_policy") if last_snapshot else None

    return {
        "labels": labels,
        "pass_series": pass_series,
        "fail_series": fail_series,
        "compliance_series": compliance_series,
        "has_data": total > 0,
        "total_pass": total_pass,
        "total_fail": total_fail,
        "total": total,
        "pass_rate": round(total_pass / total * 100, 1) if total else None,
        "dmarc_policy": dmarc_policy,
        "period_label": f"{_MESES_ES[today.month - 1]} {today.year}",
    }


def get_report_breakdown(monitored, days):
    """Arma el desglose para los gráficos extra de Tendencias: organizaciones que reportaron
    (por volumen, top 5 + 'Otros') y resultados de política SPF/DKIM (pass/fail), de los
    reportes DMARC agregados de los últimos `days` días.

    No incluye 'auth results' en bruto (pass/fail/softfail/neutral) porque hoy solo guardamos
    el booleano de alineación (spf_aligned/dkim_aligned, derivado de policy_evaluated) — el
    valor crudo de auth_results no se captura al ingerir el reporte (reports_service.py)."""
    cutoff = utcnow() - timedelta(days=days)
    base = (
        db.session.query(AggregateRecord)
        .join(AggregateReport, AggregateRecord.report_id == AggregateReport.id)
        .filter(AggregateReport.monitored_domain_id == monitored.id, AggregateReport.date_begin >= cutoff)
    )

    org_rows = (
        db.session.query(AggregateReport.org_name, func.sum(AggregateRecord.count).label("count"))
        .join(AggregateRecord, AggregateRecord.report_id == AggregateReport.id)
        .filter(AggregateReport.monitored_domain_id == monitored.id, AggregateReport.date_begin >= cutoff)
        .group_by(AggregateReport.org_name)
        .order_by(func.sum(AggregateRecord.count).desc())
        .all()
    )
    top_orgs = [{"name": r.org_name or "Desconocido", "count": r.count or 0} for r in org_rows[:5]]
    other_total = sum(r.count or 0 for r in org_rows[5:])
    if other_total:
        top_orgs.append({"name": "Otros", "count": other_total})

    spf_pass, spf_fail, dkim_pass, dkim_fail = base.with_entities(
        func.coalesce(func.sum(case((AggregateRecord.spf_aligned.is_(True), AggregateRecord.count), else_=0)), 0),
        func.coalesce(func.sum(case((AggregateRecord.spf_aligned.is_(False), AggregateRecord.count), else_=0)), 0),
        func.coalesce(func.sum(case((AggregateRecord.dkim_aligned.is_(True), AggregateRecord.count), else_=0)), 0),
        func.coalesce(func.sum(case((AggregateRecord.dkim_aligned.is_(False), AggregateRecord.count), else_=0)), 0),
    ).one()

    return {
        "orgs": top_orgs,
        "has_orgs": bool(top_orgs),
        "spf_pass": spf_pass,
        "spf_fail": spf_fail,
        "has_spf": (spf_pass + spf_fail) > 0,
        "dkim_pass": dkim_pass,
        "dkim_fail": dkim_fail,
        "has_dkim": (dkim_pass + dkim_fail) > 0,
    }


def get_subdomain_breakdown(monitored, days=30):
    """Agrupa el volumen/cumplimiento de los reportes DMARC agregados de los últimos `days` días por
    `header_from` — el dominio o subdominio real que aparece en el "De:" de cada correo, no necesariamente
    el dominio raíz que se registró para monitoreo (ej. facturacion.midominio.com puede reportar aparte de
    midominio.com). Registros sin `header_from` (reportes viejos) caen bajo el dominio raíz. Ordenado por
    volumen descendente — el remitente más activo primero.

    Agregado con una sola consulta SQL (GROUP BY) en vez de Python — mismo motivo que get_trends_data."""
    cutoff = utcnow() - timedelta(days=days)
    name_expr = case(
        (
            AggregateRecord.header_from.isnot(None) & (AggregateRecord.header_from != ""),
            func.lower(AggregateRecord.header_from),
        ),
        else_=monitored.domain.lower(),
    )
    rows = (
        db.session.query(
            name_expr.label("name"),
            func.sum(case((AggregateRecord.dmarc_aligned.is_(True), AggregateRecord.count), else_=0)).label("passed"),
            func.sum(case((AggregateRecord.dmarc_aligned.is_(False), AggregateRecord.count), else_=0)).label("failed"),
        )
        .join(AggregateReport, AggregateRecord.report_id == AggregateReport.id)
        .filter(AggregateReport.monitored_domain_id == monitored.id, AggregateReport.date_begin >= cutoff)
        .group_by(name_expr)
        .all()
    )

    breakdown = []
    for row in rows:
        passed, failed = row.passed or 0, row.failed or 0
        total = passed + failed
        if not total:
            continue
        breakdown.append({
            "name": row.name,
            "total": total,
            "pass": passed,
            "fail": failed,
            "compliance_rate": round(passed / total * 100, 1),
        })
    breakdown.sort(key=lambda g: g["total"], reverse=True)
    return breakdown


_POLICY_STEPS = ["none", "quarantine", "reject"]


def get_impact_analysis(monitored, days=30):
    """Arma el 'estado actual' y el 'análisis de impacto' de reforzar la política DMARC de este dominio,
    a partir de los reportes agregados reales de los últimos `days` días.

    Los emisores afectados son los mismos sin importar si el objetivo es cuarentena o rechazo — ambos
    activan sobre el mismo correo que hoy no alinea SPF ni DKIM (dmarc_aligned=False implica que ninguno
    de los dos alineó, es la definición de DMARC), solo cambia qué se hace con ese correo. Por eso no hay
    un cálculo separado por objetivo, la tabla de afectados es una sola.

    Agregado con consultas SQL (GROUP BY) en vez de recorrer report.records en Python por cada informe —
    mismo motivo que get_trends_data/get_subdomain_breakdown."""
    cutoff = utcnow() - timedelta(days=days)
    base = (
        db.session.query(AggregateRecord)
        .join(AggregateReport, AggregateRecord.report_id == AggregateReport.id)
        .filter(AggregateReport.monitored_domain_id == monitored.id, AggregateReport.date_begin >= cutoff)
    )

    total_pass, total_fail, unique_sources = base.with_entities(
        func.coalesce(func.sum(case((AggregateRecord.dmarc_aligned.is_(True), AggregateRecord.count), else_=0)), 0),
        func.coalesce(func.sum(case((AggregateRecord.dmarc_aligned.is_(False), AggregateRecord.count), else_=0)), 0),
        func.count(func.distinct(AggregateRecord.source_ip)),
    ).one()

    total_reports = (
        db.session.query(func.count(AggregateReport.id))
        .filter(AggregateReport.monitored_domain_id == monitored.id, AggregateReport.date_begin >= cutoff)
        .scalar()
    ) or 0

    total = total_pass + total_fail

    last_snapshot = monitored.snapshots.order_by(DomainSnapshot.checked_at.desc()).first()
    current_policy = (last_snapshot.raw_data or {}).get("dmarc_policy") if last_snapshot else None
    policy_step = _POLICY_STEPS.index(current_policy) if current_policy in _POLICY_STEPS else 0

    return {
        "has_data": total > 0,
        "total_reports": total_reports,
        "total_messages": total,
        "total_fail": total_fail,
        "pass_rate": round(total_pass / total * 100, 1) if total else None,
        "unique_sources": unique_sources,
        "current_policy": current_policy,
        "policy_step": policy_step,
        "ready_to_enforce": (total_pass / total * 100 if total else 0) >= 95,
    }


def list_affected_senders(monitored, days=30, q="", page=1, per_page=20):
    """Lista paginada y filtrable (por IP u organización) de los emisores que fallaron DMARC (ni
    SPF ni DKIM alinearon) en los últimos `days` días — la tabla detrás de "Emisores que se verían
    afectados" en el análisis de impacto de Tendencias. Antes era una lista completa sin paginar,
    recortada a los primeros 20 en el template; con dominios de tráfico alto hay decenas.

    SPF y DKIM siempre se muestran "Fallido" para cada fila acá — no hace falta calcularlo aparte,
    es la definición misma del filtro (dmarc_aligned=False implica que ninguno de los dos alineó)."""
    cutoff = utcnow() - timedelta(days=days)
    query = (
        db.session.query(
            AggregateRecord.source_ip,
            func.max(AggregateRecord.source_asn_org).label("source_asn_org"),
            func.sum(AggregateRecord.count).label("count"),
        )
        .join(AggregateReport, AggregateRecord.report_id == AggregateReport.id)
        .filter(
            AggregateReport.monitored_domain_id == monitored.id,
            AggregateReport.date_begin >= cutoff,
            AggregateRecord.dmarc_aligned.is_(False),
        )
    )
    if q:
        like = f"%{q.strip().lower()}%"
        query = query.filter(or_(
            func.lower(AggregateRecord.source_asn_org).like(like),
            func.lower(AggregateRecord.source_ip).like(like),
        ))
    rows = query.group_by(AggregateRecord.source_ip).order_by(func.sum(AggregateRecord.count).desc()).all()

    items = [
        {"source_ip": r.source_ip, "source_asn_org": r.source_asn_org or "Desconocido", "count": r.count}
        for r in rows
    ]

    total_items = len(items)
    per_page = max(1, per_page)
    total_pages = max(1, (total_items + per_page - 1) // per_page)
    page = min(max(1, page), total_pages)
    start = (page - 1) * per_page

    return {
        "items": items[start:start + per_page],
        "total_items": total_items,
        "page": page,
        "total_pages": total_pages,
    }


COMPLIANCE_PASS_THRESHOLD = 95  # mismo umbral que el color verde en la tabla — un informe "aprobado" no puede verse ámbar/rojo.


def list_dmarc_reports(user_id, days=30, estado="todos", q="", page=1, per_page=20):
    """Lista paginada de reportes DMARC agregados de TODOS los dominios monitoreados del usuario
    (no de uno solo, a diferencia de get_trends_data), con volumen y % de cumplimiento de cada uno.

    Agrega los AggregateRecord de cada reporte con una sola consulta SQL (GROUP BY report_id) en vez
    de una consulta de records por reporte — antes N+1 hacía que cada filtro tardara notablemente con
    varias decenas de informes.

    `estado`: 'aprobado' (cumplimiento >= COMPLIANCE_PASS_THRESHOLD, el mismo umbral que pinta la celda
    en verde — antes usaba exactamente 100%, lo que hacía que informes en verde (ej. 99.8%) aparecieran
    bajo "Con fallas", contradiciendo su propio color), 'con_fallas' (por debajo del umbral), 'todos'
    (sin filtrar). `days=None` = sin límite de fecha. `q` busca por reportero, dominio o ID de informe."""
    totals = (
        db.session.query(
            AggregateRecord.report_id.label("report_id"),
            func.sum(AggregateRecord.count).label("total"),
            func.sum(case((AggregateRecord.dmarc_aligned.is_(True), AggregateRecord.count), else_=0)).label("passed"),
            func.min(AggregateRecord.header_from).label("header_from"),
        )
        .group_by(AggregateRecord.report_id)
        .subquery()
    )

    query = (
        db.session.query(AggregateReport, MonitoredDomain, totals.c.total, totals.c.passed, totals.c.header_from)
        .join(MonitoredDomain, AggregateReport.monitored_domain_id == MonitoredDomain.id)
        .outerjoin(totals, totals.c.report_id == AggregateReport.id)
        .filter(MonitoredDomain.user_id == user_id)
    )
    if days:
        query = query.filter(AggregateReport.date_begin >= utcnow() - timedelta(days=days))
    if q:
        like = f"%{q.strip().lower()}%"
        query = query.filter(or_(
            db.func.lower(AggregateReport.org_name).like(like),
            db.func.lower(AggregateReport.report_id).like(like),
            db.func.lower(MonitoredDomain.domain).like(like),
        ))
    query = query.order_by(AggregateReport.received_at.desc())

    items = []
    for report, monitored, total, passed, header_from in query.all():
        total = total or 0
        passed = passed or 0
        compliance_rate = round(passed / total * 100, 1) if total else None
        items.append({
            "report": report,
            "monitored": monitored,
            "domain_shown": header_from or monitored.domain,
            "total": total,
            "compliance_rate": compliance_rate,
        })

    if estado == "aprobado":
        items = [i for i in items if i["compliance_rate"] is not None and i["compliance_rate"] >= COMPLIANCE_PASS_THRESHOLD]
    elif estado == "con_fallas":
        items = [i for i in items if i["compliance_rate"] is None or i["compliance_rate"] < COMPLIANCE_PASS_THRESHOLD]

    total_items = len(items)
    per_page = max(1, per_page)
    total_pages = max(1, (total_items + per_page - 1) // per_page)
    page = min(max(1, page), total_pages)
    start = (page - 1) * per_page

    return {
        "items": items[start:start + per_page],
        "total_items": total_items,
        "page": page,
        "total_pages": total_pages,
    }


def get_dmarc_report_detail(report_id, user_id):
    """Detalle de un reporte DMARC agregado puntual: metadata + desglose SPF/DKIM + lista de registros.
    Valida que el reporte pertenezca a un dominio monitoreado del usuario logueado (None si no)."""
    report = (
        db.session.query(AggregateReport)
        .join(MonitoredDomain, AggregateReport.monitored_domain_id == MonitoredDomain.id)
        .filter(AggregateReport.id == report_id, MonitoredDomain.user_id == user_id)
        .first()
    )
    if not report:
        return None

    records = report.records.order_by(AggregateRecord.count.desc()).all()
    total = sum(r.count or 0 for r in records)
    passed = sum(r.count or 0 for r in records if r.dmarc_aligned)
    domain_shown = records[0].header_from if records and records[0].header_from else report.domain_ref.domain

    return {
        "report": report,
        "monitored": report.domain_ref,
        "domain_shown": domain_shown,
        "records": records,
        "total": total,
        "compliance_rate": round(passed / total * 100, 1) if total else None,
        "only_spf": sum(r.count or 0 for r in records if r.spf_aligned and not r.dkim_aligned),
        "only_dkim": sum(r.count or 0 for r in records if r.dkim_aligned and not r.spf_aligned),
        "both_failed": sum(r.count or 0 for r in records if not r.spf_aligned and not r.dkim_aligned),
    }


def list_domain_alerts(monitored, days=30, tipo="todos", q="", page=1, per_page=20):
    """Lista paginada y filtrable de alertas de este dominio, en una sola tabla: alertas de
    'remitente desconocido' agrupadas por organización (para no repetir una fila por cada IP del
    mismo remitente reincidente), y el resto de los tipos (cambio de política/SPF/selectores DKIM)
    sin agrupar — son poco frecuentes y no tienen el mismo problema de IPs repetidas.

    A diferencia de list_domain_senders, la agrupación por organización se hace en Python, no en SQL:
    el nombre de organización no es una columna propia, está embebido en Alert.message (ver
    _UNKNOWN_SENDER_ORG_PATTERN) — agruparlo en SQL implicaría un regex en la base. Sigue siendo
    seguro: detect_unknown_senders() (reports_service.py) ya evita re-alertar la misma IP dos veces,
    así que el volumen de alertas de un solo dominio no crece sin límite.

    `days=None` = sin límite de fecha. `tipo`: 'remitente_desconocido' / 'cambio_configuracion' /
    'todos'. `q` busca por organización, mensaje o IP."""
    cutoff = None if days is None else utcnow() - timedelta(days=days)
    query = Alert.query.filter_by(monitored_domain_id=monitored.id)
    if cutoff is not None:
        query = query.filter(Alert.created_at >= cutoff)
    alerts = query.order_by(Alert.created_at.desc()).all()

    groups_by_org = {}
    rows = []
    for alert in alerts:
        if alert.kind != Alert.KIND_UNKNOWN_SENDER:
            rows.append({
                "kind": alert.kind,
                "kind_label": alert.kind_label,
                "detail": alert.message,
                "ips": [],
                "count": 1,
                "last_seen": alert.created_at,
            })
            continue
        match = _UNKNOWN_SENDER_ORG_PATTERN.match(alert.message)
        org = match.group(1) if match else "remitente sin identificar"
        groups_by_org.setdefault(org, []).append(alert)

    for org, org_alerts in groups_by_org.items():
        org_alerts.sort(key=lambda a: a.created_at, reverse=True)
        ips = list(dict.fromkeys(a.related_ip for a in org_alerts if a.related_ip))
        rows.append({
            "kind": Alert.KIND_UNKNOWN_SENDER,
            "kind_label": Alert.KIND_LABELS[Alert.KIND_UNKNOWN_SENDER],
            "detail": org,
            "ips": ips,
            "count": len(org_alerts),
            "last_seen": org_alerts[0].created_at,
        })

    if tipo == "remitente_desconocido":
        rows = [r for r in rows if r["kind"] == Alert.KIND_UNKNOWN_SENDER]
    elif tipo == "cambio_configuracion":
        rows = [r for r in rows if r["kind"] != Alert.KIND_UNKNOWN_SENDER]

    if q:
        needle = q.strip().lower()
        rows = [
            r for r in rows
            if needle in r["detail"].lower() or any(needle in ip.lower() for ip in r["ips"])
        ]

    rows.sort(key=lambda r: r["last_seen"], reverse=True)

    total_items = len(rows)
    per_page = max(1, per_page)
    total_pages = max(1, (total_items + per_page - 1) // per_page)
    page = min(max(1, page), total_pages)
    start = (page - 1) * per_page

    return {
        "items": rows[start:start + per_page],
        "total_items": total_items,
        "page": page,
        "total_pages": total_pages,
    }


def list_domain_senders(monitored, days=30, estado="todos", q="", page=1, per_page=20):
    """Lista paginada y filtrable de remitentes reales que enviaron correo en nombre de este dominio,
    agrupados por IP — mismo dato que antes se mostraba repetido reporte por reporte (una IP que
    reapareció en 10 informes salía 10 veces), ahora una fila por IP con su volumen total y tasa de
    SPF/DKIM en el rango elegido.

    Agregado con una sola consulta SQL (GROUP BY source_ip) — mismo motivo que get_trends_data/
    list_dmarc_reports, evitar recorrer report.records en Python. El filtro `estado` (post-agregación,
    en Python) es liviano porque ya opera sobre remitentes únicos, no sobre records crudos — mismo
    patrón que list_dmarc_reports().

    "con_fallas" se define sobre `dmarc_aligned` (SPF **o** DKIM alineado, ya calculado al ingerir el
    reporte — services/reports_service.py), no sobre spf_aligned/dkim_aligned por separado: DMARC pasa
    si cualquiera de los dos alinea, así que un remitente con SPF 100% y DKIM roto nunca falló DMARC de
    verdad (es el mismo correo que se dejaría pasar igual con política en quarantine/reject) y no debe
    aparecer como "con fallas" aunque DKIM sí haya fallado.

    `days=None` = sin límite de fecha. `q` busca por organización (ASN) o IP."""
    cutoff = None if days is None else utcnow() - timedelta(days=days)

    query = (
        db.session.query(
            AggregateRecord.source_ip,
            func.max(AggregateRecord.source_asn_org).label("source_asn_org"),
            func.max(AggregateRecord.source_country).label("source_country"),
            func.sum(AggregateRecord.count).label("total"),
            func.sum(case((AggregateRecord.spf_aligned.is_(True), AggregateRecord.count), else_=0)).label("spf_pass"),
            func.sum(case((AggregateRecord.spf_aligned.is_(False), AggregateRecord.count), else_=0)).label("spf_fail"),
            func.sum(case((AggregateRecord.dkim_aligned.is_(True), AggregateRecord.count), else_=0)).label("dkim_pass"),
            func.sum(case((AggregateRecord.dkim_aligned.is_(False), AggregateRecord.count), else_=0)).label("dkim_fail"),
            func.sum(case((AggregateRecord.dmarc_aligned.is_(False), AggregateRecord.count), else_=0)).label("dmarc_fail"),
            func.min(AggregateReport.date_begin).label("first_seen"),
            func.max(AggregateReport.date_begin).label("last_seen"),
        )
        .join(AggregateReport, AggregateRecord.report_id == AggregateReport.id)
        .filter(AggregateReport.monitored_domain_id == monitored.id)
    )
    if cutoff is not None:
        query = query.filter(AggregateReport.date_begin >= cutoff)
    if q:
        like = f"%{q.strip().lower()}%"
        query = query.filter(or_(
            func.lower(AggregateRecord.source_asn_org).like(like),
            func.lower(AggregateRecord.source_ip).like(like),
        ))
    rows = query.group_by(AggregateRecord.source_ip).all()

    items = []
    for row in rows:
        spf_total = row.spf_pass + row.spf_fail
        dkim_total = row.dkim_pass + row.dkim_fail
        has_failures = (row.dmarc_fail or 0) > 0
        items.append({
            "source_ip": row.source_ip,
            "source_asn_org": row.source_asn_org or "sin identificar",
            "source_country": row.source_country,
            "total": row.total or 0,
            "spf_pass": row.spf_pass or 0,
            "spf_fail": row.spf_fail or 0,
            "spf_rate": round(row.spf_pass / spf_total * 100, 1) if spf_total else None,
            "dkim_pass": row.dkim_pass or 0,
            "dkim_fail": row.dkim_fail or 0,
            "dkim_rate": round(row.dkim_pass / dkim_total * 100, 1) if dkim_total else None,
            "first_seen": row.first_seen,
            "last_seen": row.last_seen,
            "has_failures": has_failures,
        })

    if estado == "con_fallas":
        items = [i for i in items if i["has_failures"]]
    elif estado == "sin_fallas":
        items = [i for i in items if not i["has_failures"]]

    items.sort(key=lambda i: i["total"], reverse=True)

    total_items = len(items)
    per_page = max(1, per_page)
    total_pages = max(1, (total_items + per_page - 1) // per_page)
    page = min(max(1, page), total_pages)
    start = (page - 1) * per_page

    return {
        "items": items[start:start + per_page],
        "total_items": total_items,
        "page": page,
        "total_pages": total_pages,
    }


def get_compliance_overview(user_id, days=30):
    """Arma el resumen de cumplimiento de TODOS los dominios monitoreados del usuario: política DMARC
    actual, pass_rate de los últimos `days` días, y si "cumple" — política >= quarantine Y pass_rate >=
    COMPLIANCE_PASS_THRESHOLD (mismo umbral que ya usa list_dmarc_reports() para marcar un informe
    'aprobado': un solo criterio de cumplimiento en toda la app, no dos números distintos). Sin datos
    de tráfico en el período: 'no_data', no 'attention' — no hay evidencia de que algo esté mal, sólo
    de que no hubo/no llegó tráfico que medir (misma idea que compliance_series en get_trends_data).

    Agregado en lote — una consulta para el pass/fail de todos los dominios y otra para la última
    política de cada uno — en vez de llamar get_impact_analysis() un dominio a la vez: mismo motivo que
    get_trends_data/list_dmarc_reports, evitar N+1 con muchos dominios monitoreados."""
    domains = list_domains(user_id)
    if not domains:
        return []

    domain_ids = [d.id for d in domains]
    cutoff = utcnow() - timedelta(days=days)

    totals_rows = (
        db.session.query(
            AggregateReport.monitored_domain_id.label("domain_id"),
            func.sum(case((AggregateRecord.dmarc_aligned.is_(True), AggregateRecord.count), else_=0)).label("passed"),
            func.sum(case((AggregateRecord.dmarc_aligned.is_(False), AggregateRecord.count), else_=0)).label("failed"),
        )
        .join(AggregateRecord, AggregateRecord.report_id == AggregateReport.id)
        .filter(AggregateReport.monitored_domain_id.in_(domain_ids), AggregateReport.date_begin >= cutoff)
        .group_by(AggregateReport.monitored_domain_id)
        .all()
    )
    totals_by_domain = {row.domain_id: (row.passed or 0, row.failed or 0) for row in totals_rows}

    # Última política conocida por dominio: subquery con el checked_at más reciente de cada uno,
    # join de vuelta contra DomainSnapshot para traer su raw_data completo.
    latest_ids = (
        db.session.query(
            DomainSnapshot.monitored_domain_id.label("domain_id"),
            func.max(DomainSnapshot.checked_at).label("max_checked_at"),
        )
        .filter(DomainSnapshot.monitored_domain_id.in_(domain_ids))
        .group_by(DomainSnapshot.monitored_domain_id)
        .subquery()
    )
    latest_snapshots = (
        db.session.query(DomainSnapshot)
        .join(
            latest_ids,
            (DomainSnapshot.monitored_domain_id == latest_ids.c.domain_id)
            & (DomainSnapshot.checked_at == latest_ids.c.max_checked_at),
        )
        .all()
    )
    policy_by_domain = {s.monitored_domain_id: (s.raw_data or {}).get("dmarc_policy") for s in latest_snapshots}

    quarantine_step = _POLICY_STEPS.index("quarantine")
    overview = []
    for domain in domains:
        passed, failed = totals_by_domain.get(domain.id, (0, 0))
        total = passed + failed
        pass_rate = round(passed / total * 100, 1) if total else None
        policy = policy_by_domain.get(domain.id)
        policy_step = _POLICY_STEPS.index(policy) if policy in _POLICY_STEPS else 0

        if total == 0:
            status = "no_data"
        elif policy_step >= quarantine_step and pass_rate >= COMPLIANCE_PASS_THRESHOLD:
            status = "ok"
        else:
            status = "attention"

        overview.append({
            "monitored": domain,
            "current_policy": policy,
            "policy_label": DMARC_POLICY_LABELS.get(policy, (policy or "Sin registro DMARC", None))[0],
            "pass_rate": pass_rate,
            "total": total,
            "status": status,
        })
    return overview


def get_compliance_protocol_status(domains):
    """Corre run_check() para cada dominio en paralelo (ThreadPoolExecutor — mismo patrón que
    build_extra_dns_instructions() en checkdmarc_service.py, pero paralelizando entre dominios en vez
    de entre protocolos de uno solo) y devuelve su resumen ok/warn/fail (build_summary); None para el
    que falló. Pensado para la columna 'DNS en vivo' de /cumplimiento — se carga aparte vía htmx (ver
    compliance_protocol_status en app.py) para no bloquear la carga inicial de la tabla con N consultas
    de DNS que pueden tardar varios segundos cada una."""
    if not domains:
        return {}

    def _check(domain):
        """Corre build_summary(run_check()) para un dominio; None si falla (nunca tumba el resto)."""
        try:
            return build_summary(run_check(domain.domain))
        except Exception as error:
            print(f"[compliance] no se pudo chequear el DNS de {domain.domain}: {error}")
            return None

    with ThreadPoolExecutor(max_workers=min(8, len(domains))) as executor:
        results = list(executor.map(_check, domains))
    return {domain.id: result for domain, result in zip(domains, results)}
