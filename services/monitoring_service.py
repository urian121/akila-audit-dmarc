import re
from datetime import timedelta

from models import Alert, AggregateReport, DomainSnapshot, MonitoredDomain, db
from models.monitoring import utcnow
from services.checkdmarc_service import dns_has_mailbox_in_rua, dns_has_mailbox_in_tls_rpt_rua

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
    return {"monitored": monitored, "alerts": alerts, "reports": reports}


_MESES_ES = [
    "enero", "febrero", "marzo", "abril", "mayo", "junio",
    "julio", "agosto", "septiembre", "octubre", "noviembre", "diciembre",
]


def get_trends_data(monitored, days):
    """Arma volumen pass/fail por día y tasa de cumplimiento de los últimos `days` días,
    a partir de los reportes DMARC agregados reales ya recibidos para este dominio.
    Rellena los días sin reporte con 0 (compliance_series con None ese día, para no
    dibujar un 0% falso donde en realidad no hubo tráfico que medir)."""
    cutoff = utcnow() - timedelta(days=days)
    reports = monitored.aggregate_reports.filter(AggregateReport.date_begin >= cutoff).all()

    daily = {}
    for report in reports:
        if report.date_begin is None:
            continue
        bucket = daily.setdefault(report.date_begin.date(), {"pass": 0, "fail": 0})
        for record in report.records:
            amount = record.count or 0
            if record.dmarc_aligned:
                bucket["pass"] += amount
            else:
                bucket["fail"] += amount

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


def get_subdomain_breakdown(monitored, days=30):
    """Agrupa el volumen/cumplimiento de los reportes DMARC agregados de los últimos `days` días por
    `header_from` — el dominio o subdominio real que aparece en el "De:" de cada correo, no necesariamente
    el dominio raíz que se registró para monitoreo (ej. facturacion.midominio.com puede reportar aparte de
    midominio.com). Registros sin `header_from` (reportes viejos) caen bajo el dominio raíz. Ordenado por
    volumen descendente — el remitente más activo primero."""
    cutoff = utcnow() - timedelta(days=days)
    reports = monitored.aggregate_reports.filter(AggregateReport.date_begin >= cutoff).all()

    groups = {}
    for report in reports:
        for record in report.records:
            name = (record.header_from or monitored.domain).strip().lower()
            bucket = groups.setdefault(name, {"pass": 0, "fail": 0})
            amount = record.count or 0
            if record.dmarc_aligned:
                bucket["pass"] += amount
            else:
                bucket["fail"] += amount

    breakdown = []
    for name, bucket in groups.items():
        total = bucket["pass"] + bucket["fail"]
        if not total:
            continue
        breakdown.append({
            "name": name,
            "total": total,
            "pass": bucket["pass"],
            "fail": bucket["fail"],
            "compliance_rate": round(bucket["pass"] / total * 100, 1),
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
    """
    cutoff = utcnow() - timedelta(days=days)
    reports = monitored.aggregate_reports.filter(AggregateReport.date_begin >= cutoff).all()

    total_pass = total_fail = 0
    unique_sources = set()
    affected = {}
    for report in reports:
        for record in report.records:
            amount = record.count or 0
            unique_sources.add(record.source_ip)
            if record.dmarc_aligned:
                total_pass += amount
            else:
                total_fail += amount
                key = record.source_ip
                bucket = affected.setdefault(key, {
                    "source_ip": record.source_ip,
                    "source_asn_org": record.source_asn_org or "Desconocido",
                    "count": 0,
                })
                bucket["count"] += amount

    total = total_pass + total_fail
    affected_senders = sorted(affected.values(), key=lambda s: s["count"], reverse=True)

    last_snapshot = monitored.snapshots.order_by(DomainSnapshot.checked_at.desc()).first()
    current_policy = (last_snapshot.raw_data or {}).get("dmarc_policy") if last_snapshot else None
    policy_step = _POLICY_STEPS.index(current_policy) if current_policy in _POLICY_STEPS else 0

    return {
        "has_data": total > 0,
        "total_reports": len(reports),
        "total_messages": total,
        "total_fail": total_fail,
        "pass_rate": round(total_pass / total * 100, 1) if total else None,
        "unique_sources": len(unique_sources),
        "current_policy": current_policy,
        "policy_step": policy_step,
        "affected_senders": affected_senders,
        "ready_to_enforce": (total_pass / total * 100 if total else 0) >= 95,
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
