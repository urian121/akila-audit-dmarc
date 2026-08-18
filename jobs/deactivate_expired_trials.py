"""Job que desactiva los dominios de usuarios cuyo plan venció sin pasar a uno nuevo — hoy en la
práctica, el trial gratis de 20 días sin pasar a Pago (todavía no hay cobro real, ver
services/monitoring_service.py:assign_plan()). Corre dentro del mismo proceso web vía APScheduler
(start_scheduler() en app.py), igual que jobs/recheck_domains.py — no es un servicio/cron aparte.

A diferencia de get_max_domains() (que solo bloquea *agregar* dominios nuevos cuando el plan ya
venció, sin tocar los que ya estaban activos), esto sí los apaga de verdad — es la pieza que hace
que "se desactivan solos" cuando se vence el trial, no solo "no podés sumar más".

Uso: python jobs/deactivate_expired_trials.py
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app import app  # noqa: E402
from models import MonitoredDomain, User, UserPlan, db  # noqa: E402
from models.monitoring import utcnow  # noqa: E402


def deactivate_expired_free_trials():
    """Busca UserPlan vencidos (de usuarios no-admin) y desactiva los dominios que ese usuario
    todavía tenga activos — reversible: reactivarlos vuelve a pasar por el chequeo de límite normal
    (get_max_domains), que ya vuelve sola al default una vez vencido el plan."""
    expired_plans = (
        UserPlan.query
        .join(User, UserPlan.user_id == User.id)
        .filter(User.is_admin.is_(False), UserPlan.expires_at.isnot(None), UserPlan.expires_at < utcnow())
        .all()
    )
    for user_plan in expired_plans:
        active_domains = MonitoredDomain.query.filter_by(user_id=user_plan.user_id, is_active=True).all()
        for domain in active_domains:
            domain.is_active = False
            print(f"[deactivate_expired_trials] {domain.domain} desactivado — plan vencido del usuario {user_plan.user_id}")
    if expired_plans:
        db.session.commit()


def main():
    """Corre deactivate_expired_free_trials() dentro del contexto de la app."""
    with app.app_context():
        try:
            deactivate_expired_free_trials()
        except Exception as error:
            db.session.rollback()
            print(f"[deactivate_expired_trials] error: {error}")


if __name__ == "__main__":
    main()
