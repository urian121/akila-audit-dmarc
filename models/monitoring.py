import secrets
from datetime import datetime, timezone

from models import db


def generate_access_token():
    """Genera un token aleatorio para la URL privada del dashboard de un dominio monitoreado."""
    return secrets.token_urlsafe(24)


def utcnow():
    """Devuelve la fecha/hora actual en UTC (evita depender de la zona horaria del servidor)."""
    return datetime.now(timezone.utc)


class MonitoredDomain(db.Model):
    """Un dominio dado de alta para monitoreo continuo (vigilancia DNS + reportes DMARC)."""

    __tablename__ = "monitored_domains"

    id = db.Column(db.Integer, primary_key=True)
    # Nullable a propósito: quedaron 3 dominios reales registrados antes de que
    # existiera el login — se backfillean a mano una vez el dueño cree su cuenta.
    # Todo registro nuevo (register_domain()) siempre lo completa.
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=True, index=True)
    domain = db.Column(db.String(255), unique=True, nullable=False, index=True)
    owner_email = db.Column(db.String(255), nullable=False)
    access_token = db.Column(
        db.String(64), unique=True, nullable=False, default=generate_access_token, index=True
    )
    is_active = db.Column(db.Boolean, default=True, nullable=False)
    dns_verified = db.Column(db.Boolean, default=False, nullable=False)
    dns_verified_at = db.Column(db.DateTime(timezone=True), nullable=True)
    tls_rpt_verified = db.Column(db.Boolean, default=False, nullable=False)
    tls_rpt_verified_at = db.Column(db.DateTime(timezone=True), nullable=True)
    created_at = db.Column(db.DateTime(timezone=True), default=utcnow, nullable=False)

    snapshots = db.relationship(
        "DomainSnapshot", backref="domain_ref", lazy="dynamic", cascade="all, delete-orphan"
    )
    aggregate_reports = db.relationship(
        "AggregateReport", backref="domain_ref", lazy="dynamic", cascade="all, delete-orphan"
    )
    forensic_reports = db.relationship(
        "ForensicReport", backref="domain_ref", lazy="dynamic", cascade="all, delete-orphan"
    )
    alerts = db.relationship(
        "Alert", backref="domain_ref", lazy="dynamic", cascade="all, delete-orphan"
    )


class DomainSnapshot(db.Model):
    """Última foto del resultado de run_check() para un dominio, usada para detectar cambios de configuración."""

    __tablename__ = "domain_snapshots"

    id = db.Column(db.Integer, primary_key=True)
    monitored_domain_id = db.Column(
        db.Integer, db.ForeignKey("monitored_domains.id"), nullable=False, index=True
    )
    raw_data = db.Column(db.JSON, nullable=False)
    checked_at = db.Column(db.DateTime(timezone=True), default=utcnow, nullable=False)


class AggregateReport(db.Model):
    """Metadata de un reporte DMARC agregado (RUA) ya parseado por parsedmarc."""

    __tablename__ = "aggregate_reports"

    id = db.Column(db.Integer, primary_key=True)
    monitored_domain_id = db.Column(
        db.Integer, db.ForeignKey("monitored_domains.id"), nullable=False, index=True
    )
    org_name = db.Column(db.String(255))
    report_id = db.Column(db.String(255))
    date_begin = db.Column(db.DateTime(timezone=True))
    date_end = db.Column(db.DateTime(timezone=True))
    received_at = db.Column(db.DateTime(timezone=True), default=utcnow, nullable=False)

    records = db.relationship(
        "AggregateRecord", backref="report_ref", lazy="dynamic", cascade="all, delete-orphan"
    )


class AggregateRecord(db.Model):
    """Un registro dentro de un reporte agregado: una IP de origen y sus resultados de autenticación."""

    __tablename__ = "aggregate_records"

    id = db.Column(db.Integer, primary_key=True)
    report_id = db.Column(
        db.Integer, db.ForeignKey("aggregate_reports.id"), nullable=False, index=True
    )
    source_ip = db.Column(db.String(64), nullable=False, index=True)
    source_country = db.Column(db.String(8))
    source_asn = db.Column(db.String(32))
    source_asn_org = db.Column(db.String(255))
    count = db.Column(db.Integer, default=0)
    disposition = db.Column(db.String(32))
    dkim_aligned = db.Column(db.Boolean)
    spf_aligned = db.Column(db.Boolean)
    dmarc_aligned = db.Column(db.Boolean)
    header_from = db.Column(db.String(255))


class ForensicReport(db.Model):
    """Un reporte forense (RUF) de un mensaje individual que falló SPF/DKIM/DMARC — a diferencia de
    AggregateReport (resumen diario agregado por IP), llega casi en tiempo real, uno por mensaje.

    Decisión de retención/PII (ver AGENTS.md): sólo se guarda metadata de triage (asunto, remitente,
    resultado de la validación, origen). El payload de parsedmarc trae además `sample`/`parsed_sample`
    con el correo original completo (cuerpo, cabeceras, adjuntos) — eso NUNCA se persiste acá, a
    propósito, para no acumular contenido de correo real de terceros sin necesidad."""

    __tablename__ = "forensic_reports"

    id = db.Column(db.Integer, primary_key=True)
    monitored_domain_id = db.Column(
        db.Integer, db.ForeignKey("monitored_domains.id"), nullable=False, index=True
    )
    feedback_type = db.Column(db.String(64))
    arrival_date = db.Column(db.DateTime(timezone=True), nullable=True)
    source_ip = db.Column(db.String(64), index=True)
    source_country = db.Column(db.String(8))
    source_asn_org = db.Column(db.String(255))
    source_reverse_dns = db.Column(db.String(255))
    authentication_results = db.Column(db.Text)
    delivery_result = db.Column(db.String(64))
    auth_failure = db.Column(db.String(128))  # csv, ej. "dmarc,spf" — de FailureReport["auth_failure"]
    dkim_domain = db.Column(db.String(255))
    subject = db.Column(db.String(998))  # dato sensible: contenido real del correo, ver AGENTS.md
    message_id = db.Column(db.String(255))
    from_address = db.Column(db.String(255))
    to_address = db.Column(db.String(255))
    sample_headers_only = db.Column(db.Boolean, nullable=True)
    received_at = db.Column(db.DateTime(timezone=True), default=utcnow, nullable=False)


class Alert(db.Model):
    """Una alerta generada por vigilancia DNS (cambio de configuración) o de tráfico (remitente desconocido)."""

    __tablename__ = "alerts"

    KIND_POLICY_CHANGED = "policy_changed"
    KIND_SPF_CHANGED = "spf_changed"
    KIND_DKIM_SELECTOR_CHANGED = "dkim_selector_changed"
    KIND_UNKNOWN_SENDER = "unknown_sender"

    KIND_LABELS = {
        KIND_POLICY_CHANGED: "Cambio de política DMARC",
        KIND_SPF_CHANGED: "Cambio de registro SPF",
        KIND_DKIM_SELECTOR_CHANGED: "Cambio de selector DKIM",
        KIND_UNKNOWN_SENDER: "Remitente desconocido",
    }

    id = db.Column(db.Integer, primary_key=True)
    monitored_domain_id = db.Column(
        db.Integer, db.ForeignKey("monitored_domains.id"), nullable=False, index=True
    )
    kind = db.Column(db.String(32), nullable=False)
    message = db.Column(db.Text, nullable=False)
    related_ip = db.Column(db.String(64), nullable=True)
    created_at = db.Column(db.DateTime(timezone=True), default=utcnow, nullable=False)
    notified_at = db.Column(db.DateTime(timezone=True), nullable=True)

    @property
    def kind_label(self):
        """Traduce `kind` a un texto legible para mostrar en el dashboard, en vez del valor crudo interno."""
        return self.KIND_LABELS.get(self.kind, self.kind)
