"""Convierte modelos de SQLAlchemy a dict listos para jsonify() — Fase 1 del plan de API (ver
API_PLAN.md). Una función por modelo, sin lógica de negocio: solo transformación de campos,
reusada por cualquier endpoint de /api/v1/... que necesite ese modelo."""


def _iso(value):
    """None-safe: un datetime se convierte a ISO 8601; None pasa tal cual."""
    return value.isoformat() if value else None


def serialize_monitored_domain(domain):
    return {
        "id": domain.id,
        "domain": domain.domain,
        "access_token": domain.access_token,
        "is_active": domain.is_active,
        "dns_verified": domain.dns_verified,
        "dns_verified_at": _iso(domain.dns_verified_at),
        "tls_rpt_verified": domain.tls_rpt_verified,
        "tls_rpt_verified_at": _iso(domain.tls_rpt_verified_at),
        "created_at": _iso(domain.created_at),
    }


def serialize_aggregate_record(record):
    return {
        "id": record.id,
        "source_ip": record.source_ip,
        "source_country": record.source_country,
        "source_asn": record.source_asn,
        "source_asn_org": record.source_asn_org,
        "count": record.count,
        "disposition": record.disposition,
        "dkim_aligned": record.dkim_aligned,
        "spf_aligned": record.spf_aligned,
        "dmarc_aligned": record.dmarc_aligned,
        "header_from": record.header_from,
    }


def serialize_aggregate_report(report, include_records=False):
    """`include_records=True` sólo cuando de verdad hace falta el detalle (ej. endpoint de detalle
    de un informe) — la lista de dominio/tendencias no lo necesita, evita mandar de más."""
    data = {
        "id": report.id,
        "org_name": report.org_name,
        "report_id": report.report_id,
        "date_begin": _iso(report.date_begin),
        "date_end": _iso(report.date_end),
        "received_at": _iso(report.received_at),
    }
    if include_records:
        data["records"] = [serialize_aggregate_record(r) for r in report.records]
    return data


def serialize_forensic_report(report):
    """Sólo la metadata de triage que ya persiste ForensicReport — nunca hubo (ni hay acá) cuerpo
    completo del correo, ver la nota de privacidad en models/monitoring.py."""
    return {
        "id": report.id,
        "feedback_type": report.feedback_type,
        "arrival_date": _iso(report.arrival_date),
        "source_ip": report.source_ip,
        "source_country": report.source_country,
        "source_asn_org": report.source_asn_org,
        "source_reverse_dns": report.source_reverse_dns,
        "authentication_results": report.authentication_results,
        "delivery_result": report.delivery_result,
        "auth_failure": report.auth_failure,
        "dkim_domain": report.dkim_domain,
        "subject": report.subject,
        "message_id": report.message_id,
        "from_address": report.from_address,
        "to_address": report.to_address,
        "received_at": _iso(report.received_at),
    }


def serialize_alert(alert):
    return {
        "id": alert.id,
        "kind": alert.kind,
        "kind_label": alert.kind_label,
        "message": alert.message,
        "related_ip": alert.related_ip,
        "created_at": _iso(alert.created_at),
        "notified_at": _iso(alert.notified_at),
    }


def serialize_plan(plan):
    if plan is None:
        return None
    return {
        "name": plan.name,
        "label": plan.label,
        "max_domains": plan.max_domains,
        "price_usd": float(plan.price_usd),
        "trial_days": plan.trial_days,
    }


def serialize_user_plan(user_plan):
    if user_plan is None:
        return None
    return {
        "max_domains": user_plan.max_domains,
        "expires_at": _iso(user_plan.expires_at),
        "plan": serialize_plan(user_plan.plan),
    }


def serialize_paginated(paginated, item_serializer=None, date_keys=()):
    """Convierte el dict de utils/pagination.py:paginate() a JSON-safe, misma forma
    (items/total_items/page/total_pages) que ya consumen las tablas HTML — reusado por cada
    endpoint de /api/v1/... que devuelve una tabla paginada.

    `item_serializer`: para items que son objetos ORM (ej. AggregateReport), pasa cada uno por esa
    función. `date_keys`: para items que YA son dicts armados a mano (ej. list_domain_senders,
    con `datetime` sueltos adentro) — sólo convierte esas claves a ISO 8601, deja el resto igual.
    No pasar ambos a la vez, un tipo de item es de una forma o de la otra, nunca las dos."""
    items = paginated["items"]
    if item_serializer:
        items = [item_serializer(item) for item in items]
    elif date_keys:
        items = [{**item, **{key: _iso(item[key]) for key in date_keys if key in item}} for item in items]
    return {
        "items": items,
        "total_items": paginated["total_items"],
        "page": paginated["page"],
        "total_pages": paginated["total_pages"],
    }


def serialize_user(user):
    """Sólo campos públicos — nunca password_hash ni api_key_hash, ver AGENTS.md."""
    return {
        "id": user.id,
        "name": user.name,
        "email": user.email,
        "is_admin": user.is_admin,
        "created_at": _iso(user.created_at),
        "plan": serialize_user_plan(user.plan),
    }
