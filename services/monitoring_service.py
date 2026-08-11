import re
from concurrent.futures import ThreadPoolExecutor
from datetime import timedelta

from sqlalchemy import case, func, or_

from models import Alert, AggregateRecord, AggregateReport, DomainSnapshot, ForensicReport, MonitoredDomain, db
from models.monitoring import utcnow
from services.card_builder import DMARC_POLICY_LABELS, build_summary
from services.checkdmarc_service import dns_has_mailbox_in_rua, dns_has_mailbox_in_tls_rpt_rua, run_check

# Mismo texto armado en detect_unknown_senders() (reports_service.py) — si se
# cambia esa frase, ajustar este patrón también, o el agrupado deja de reconocer
# el nombre del remitente y todo cae en "remitente sin identificar".
_UNKNOWN_SENDER_ORG_PATTERN = re.compile(r"^Correo enviado desde (.+?) \(")


def register_domain(domain, owner_email, user_id):
    """Da de alta un dominio para monitoreo continuo bajo `user_id`; si ya estaba registrado por el mismo usuario pero inactivo, lo reactiva.

    Devuelve (None, False) si el dominio ya está registrado por otro usuario.
    """
    existing = MonitoredDomain.query.filter_by(domain=domain).first()
    if existing:
        if existing.user_id != user_id:
            return None, False
        if not existing.is_active:
            existing.is_active = True
            db.session.commit()
        return existing, False
    monitored = MonitoredDomain(domain=domain, owner_email=owner_email, user_id=user_id)
    db.session.add(monitored)
    db.session.commit()
    return monitored, True


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
    """Activa o desactiva el monitoreo de un dominio (no borra su historial). Devuelve None si el token no existe."""
    monitored = MonitoredDomain.query.filter_by(access_token=access_token).first()
    if not monitored:
        return None
    monitored.is_active = is_active
    db.session.commit()
    return monitored


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

    affected_rows = (
        base.filter(AggregateRecord.dmarc_aligned.is_(False))
        .with_entities(
            AggregateRecord.source_ip,
            func.max(AggregateRecord.source_asn_org).label("source_asn_org"),
            func.sum(AggregateRecord.count).label("count"),
        )
        .group_by(AggregateRecord.source_ip)
        .order_by(func.sum(AggregateRecord.count).desc())
        .all()
    )
    affected_senders = [
        {"source_ip": r.source_ip, "source_asn_org": r.source_asn_org or "Desconocido", "count": r.count}
        for r in affected_rows
    ]

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
        "affected_senders": affected_senders,
        "ready_to_enforce": (total_pass / total * 100 if total else 0) >= 95,
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


def group_unknown_sender_alerts(alerts):
    """Agrupa las alertas 'remitente desconocido' por organización remitente, para no mostrar una tarjeta por cada IP del mismo remitente repetido.

    Devuelve (grupos, otras_alertas): `otras_alertas` son los demás tipos (cambio de
    política/SPF/DKIM) — se muestran igual que antes, sin agrupar, porque son
    poco frecuentes y no tienen el mismo problema de IPs repetidas del mismo origen.
    Cada grupo trae: org, count, first_seen, last_seen, alerts (todas las de ese grupo).
    """
    groups_by_org = {}
    others = []
    for alert in alerts:
        if alert.kind != Alert.KIND_UNKNOWN_SENDER:
            others.append(alert)
            continue
        match = _UNKNOWN_SENDER_ORG_PATTERN.match(alert.message)
        org = match.group(1) if match else "remitente sin identificar"
        groups_by_org.setdefault(org, []).append(alert)

    groups = []
    for org, org_alerts in groups_by_org.items():
        org_alerts.sort(key=lambda a: a.created_at, reverse=True)
        groups.append({
            "org": org,
            "count": len(org_alerts),
            "last_seen": org_alerts[0].created_at,
            "first_seen": org_alerts[-1].created_at,
            "alerts": org_alerts,
        })
    groups.sort(key=lambda g: g["last_seen"], reverse=True)
    return groups, others


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
