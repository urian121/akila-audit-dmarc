from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()

# Se importa después de crear `db` a propósito: los modelos necesitan
# `db.Model`/`db.Column`, y este módulo ya queda registrado en sys.modules
# con `db` disponible antes de que monitoring.py haga "from models import db".
from models.monitoring import (  # noqa: E402
    Alert,
    AggregateReport,
    AggregateRecord,
    DomainSnapshot,
    ForensicReport,
    MonitoredDomain,
)
from models.user import Plan, User, UserPlan  # noqa: E402

__all__ = [
    "db",
    "MonitoredDomain",
    "DomainSnapshot",
    "AggregateReport",
    "AggregateRecord",
    "ForensicReport",
    "Alert",
    "User",
    "UserPlan",
    "Plan",
]
