import re
from datetime import datetime

from checkdmarc import get_base_domain

from models import Alert, AggregateRecord, AggregateReport, MonitoredDomain, db
from services.checkdmarc_service import run_check


def _parse_datetime(value):
    """Convierte un string de fecha del payload de parsedmarc (o None) a datetime; None si no se puede."""
    if not value:
        return None
    try:
        return datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        return None


def _report_domain(payload):
    """Extrae el dominio (header_from) del payload de un reporte agregado ya parseado por parsedmarc."""
    records = payload.get("records") or []
    if records:
        header_from = (records[0].get("identifiers") or {}).get("header_from")
        if header_from:
            return header_from.strip().lower()
    published = payload.get("policy_published") or {}
    return (published.get("domain") or "").strip().lower()


def ingest_aggregate_report(payload):
    """Guarda un reporte DMARC agregado ya parseado por parsedmarc y revisa remitentes desconocidos.

    Idempotente por (monitored_domain_id, report_id): si el mismo reporte ya se guardó antes, lo
    devuelve tal cual en vez de crear un duplicado — necesario porque el webhook puede recibir el
    mismo reporte más de una vez (reintento de parsedmarc, o una config de mailbox que no mueve/
    borra el correo después de leerlo, ver AGENTS.md). `report_id` viene vacío rarísima vez (reporte
    mal formado); en ese caso no hay forma de dedupear, se guarda igual en vez de perderlo."""
    domain = _report_domain(payload)
    monitored = MonitoredDomain.query.filter_by(domain=domain).first()
    if not monitored:
        return None  # el reporte es de un dominio que no está registrado con nosotros
    if not monitored.is_active:
        return None  # monitoreo desactivado: se ignora, no se guarda ni se alerta

    meta = payload.get("report_metadata") or {}
    report_id = meta.get("report_id")
    if report_id:
        existing = AggregateReport.query.filter_by(monitored_domain_id=monitored.id, report_id=report_id).first()
        if existing:
            return existing

    report = AggregateReport(
        monitored_domain_id=monitored.id,
        org_name=meta.get("org_name"),
        report_id=report_id,
        date_begin=_parse_datetime(meta.get("begin_date")),
        date_end=_parse_datetime(meta.get("end_date")),
    )
    db.session.add(report)
    db.session.flush()  # necesitamos report.id para los AggregateRecord

    for record in payload.get("records") or []:
        source = record.get("source") or {}
        policy = record.get("policy_evaluated") or {}
        identifiers = record.get("identifiers") or {}
        db.session.add(AggregateRecord(
            report_id=report.id,
            source_ip=source.get("ip_address", ""),
            source_country=source.get("country"),
            source_asn=str(source["asn"]) if source.get("asn") else None,
            source_asn_org=source.get("name"),
            count=record.get("count", 0),
            disposition=policy.get("disposition"),
            dkim_aligned=policy.get("dkim") == "pass",
            spf_aligned=policy.get("spf") == "pass",
            dmarc_aligned=policy.get("dkim") == "pass" or policy.get("spf") == "pass",
            header_from=identifiers.get("header_from"),
        ))

    db.session.commit()
    try:
        # El reporte ya quedó guardado arriba; si esto falla (ej. timeout de
        # DNS al revisar el SPF actual), no debe tumbar la ingesta ni hacer
        # que el webhook responda 500 — parsedmarc podría reintentar de más.
        detect_unknown_senders(monitored)
    except Exception as error:
        print(f"[reports_service] no se pudo revisar remitentes de {monitored.domain}: {error}")
    return report


def _spf_allowed_targets(domain):
    """Extrae los valores declarados en el SPF del dominio (include/ip4/ip6/mx/a) vía run_check()."""
    data = run_check(domain)
    parsed = (data.get("spf") or {}).get("parsed") or {}
    return {m["value"] for m in parsed.get("mechanisms") or [] if m.get("value")}


def _base_domain_keyword(target):
    """Extrae la etiqueta principal del dominio base de un target de SPF (ej. '_spf.google.com' -> 'google')."""
    try:
        base = get_base_domain(target)
    except Exception:
        base = target
    return (base.split(".")[0] if base else "").lower()


def _words(text):
    """Separa un texto en palabras sueltas alfanuméricas, en minúsculas (para comparar nombres de organización)."""
    return set(re.findall(r"[a-z0-9]+", text.lower()))


def detect_unknown_senders(monitored):
    """Compara los remitentes reales de los últimos reportes contra el SPF declarado y alerta por IP nueva.

    Heurística simple para el MVP: compara el nombre de la organización del ASN contra
    los valores declarados en include:/mx:/a: por coincidencia de texto, no por rangos
    CIDR exactos de ip4:/ip6:. Suficiente para detectar remitentes claramente ajenos
    (ej. un proveedor nunca autorizado); no reemplaza una validación SPF completa.

    Dos formas de matchear texto, porque una sola no alcanza:
    1. Substring directo entre el nombre de organización y el target completo — cubre
       nombres de organización cortos que aparecen dentro de un hostname más largo
       (ej. org "Zoho" dentro de target "sender.zohobooks.com").
    2. Palabra clave del dominio base del target contra las palabras sueltas del nombre
       de organización — cubre nombres de organización largos/descriptivos que no son
       substring literal del target (ej. org "Google (Including Gmail and Google
       Workspace)" vs. target "_spf.google.com": ninguno es substring del otro, pero
       "google" es una palabra en ambos).
    """
    allowed = _spf_allowed_targets(monitored.domain)
    allowed_keywords = {_base_domain_keyword(target) for target in allowed}
    already_alerted_ips = {
        a.related_ip for a in monitored.alerts.filter_by(kind=Alert.KIND_UNKNOWN_SENDER) if a.related_ip
    }

    seen_ips = set()
    recent_reports = monitored.aggregate_reports.order_by(AggregateReport.received_at.desc()).limit(5)
    for report in recent_reports:
        for record in report.records:
            if record.source_ip in seen_ips or record.source_ip in already_alerted_ips:
                continue
            seen_ips.add(record.source_ip)

            org = (record.source_asn_org or "").strip()
            covered = bool(org) and (
                any(org.lower() in target.lower() or target.lower() in org.lower() for target in allowed)
                or bool(allowed_keywords & _words(org))
            )
            if not covered:
                db.session.add(Alert(
                    monitored_domain_id=monitored.id,
                    kind=Alert.KIND_UNKNOWN_SENDER,
                    related_ip=record.source_ip,
                    message=(
                        f"Correo enviado desde {org or 'un origen sin identificar'} "
                        f"({record.source_ip}), que no está en el SPF declarado."
                    ),
                ))

    db.session.commit()
