"""Ingesta de reportes forenses (RUF) de parsedmarc — paralelo a reports_service.py (que ingiere los
agregados/RUA). parsedmarc internamente los llama "failure reports" desde su v10 (RUF/"forensic" quedó
como alias de compatibilidad) — ver el webhook `failure_url` en config/parsedmarc.ini.example.

A diferencia del agregado, el payload de un reporte forense es un solo objeto plano por mensaje (no una
lista de records dentro de un reporte). Trae además `sample`/`parsed_sample` con el correo original
completo — a propósito, ese contenido NUNCA se guarda acá, ver ForensicReport en models/monitoring.py.
"""
from datetime import datetime, timezone

from models import ForensicReport, MonitoredDomain, db


def _parse_arrival_date(value):
    """Convierte arrival_date_utc ('YYYY-MM-DD HH:MM:SS', ya en UTC) a datetime; None si no se puede."""
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(str(value))
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


def _first_address(entries):
    """Primera dirección de una lista de direcciones ya parseadas por parsedmarc (dict con 'address'), o None."""
    for entry in entries or []:
        if entry.get("address"):
            return entry["address"]
    return None


def ingest_forensic_report(payload):
    """Guarda un reporte forense (RUF) ya parseado por parsedmarc — sólo metadata de triage, nunca el
    cuerpo/adjuntos/cabeceras completas del correo original (ver ForensicReport para la decisión de
    retención/PII). Devuelve None si el dominio no está registrado o tiene el monitoreo desactivado.

    Idempotente por (monitored_domain_id, message_id): mismo motivo que ingest_aggregate_report en
    reports_service.py — evita duplicar si el webhook recibe el mismo mensaje más de una vez.
    `message_id` viene vacío rarísima vez; ahí no hay forma de dedupear, se guarda igual."""
    domain = (payload.get("reported_domain") or "").strip().lower()
    monitored = MonitoredDomain.query.filter_by(domain=domain).first()
    if not monitored:
        return None  # el reporte es de un dominio que no está registrado con nosotros
    if not monitored.is_active:
        return None  # monitoreo desactivado: se ignora, no se guarda

    source = payload.get("source") or {}
    parsed_sample = payload.get("parsed_sample") or {}
    from_address = (parsed_sample.get("from") or {}).get("address")
    to_address = _first_address(parsed_sample.get("to"))
    message_id = parsed_sample.get("message_id")

    if message_id:
        existing = ForensicReport.query.filter_by(monitored_domain_id=monitored.id, message_id=message_id).first()
        if existing:
            return existing

    report = ForensicReport(
        monitored_domain_id=monitored.id,
        feedback_type=payload.get("feedback_type"),
        arrival_date=_parse_arrival_date(payload.get("arrival_date_utc")),
        source_ip=source.get("ip_address"),
        source_country=source.get("country"),
        source_asn_org=source.get("name"),
        source_reverse_dns=source.get("reverse_dns"),
        authentication_results=payload.get("authentication_results"),
        delivery_result=payload.get("delivery_result"),
        auth_failure=",".join(payload.get("auth_failure") or []),
        dkim_domain=payload.get("dkim_domain"),
        subject=parsed_sample.get("subject"),
        message_id=message_id,
        from_address=from_address,
        to_address=to_address,
        sample_headers_only=payload.get("sample_headers_only"),
    )
    db.session.add(report)
    db.session.commit()
    return report
