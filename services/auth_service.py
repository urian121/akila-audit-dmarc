import hashlib
import secrets

from sqlalchemy import func, or_

from models import User, UserPlan, db
from models.monitoring import utcnow
from services.monitoring_service import assign_plan, get_max_domains
from utils.pagination import paginate


def register_user(name, email, password):
    """Crea una cuenta nueva; devuelve (user, error) — error es un string si el correo ya existe."""
    name = name.strip()
    email = email.strip().lower()
    if User.query.filter_by(email=email).first():
        return None, "Ya existe una cuenta con ese correo."
    user = User(name=name, email=email)
    user.set_password(password)
    db.session.add(user)
    db.session.commit()
    assign_plan(user.id, "free")  # toda cuenta nueva arranca en el plan Free (20 días de prueba)
    return user, None


def authenticate(email, password):
    """Verifica email + contraseña; devuelve el User si son correctos, None si no."""
    user = User.query.filter_by(email=email.strip().lower()).first()
    if user and user.check_password(password):
        return user
    return None


def update_email(user, name, new_email):
    """Actualiza el nombre y el correo de la cuenta; devuelve (ok, error) — error si falta el nombre, el correo no es válido, o ya está en uso por otra cuenta."""
    name = (name or "").strip()
    new_email = new_email.strip().lower()
    if not name:
        return False, "Ingresa tu nombre."
    if "@" not in new_email:
        return False, "Ingresa un correo válido."
    existing = User.query.filter(User.email == new_email, User.id != user.id).first()
    if existing:
        return False, "Ya existe otra cuenta con ese correo."
    user.name = name
    user.email = new_email
    db.session.commit()
    return True, None


def update_password(user, current_password, new_password):
    """Cambia la contraseña, verificando primero la actual; devuelve (ok, error)."""
    if not user.check_password(current_password):
        return False, "La contraseña actual no es correcta."
    if len(new_password) < 8:
        return False, "La nueva contraseña debe tener al menos 8 caracteres."
    user.set_password(new_password)
    db.session.commit()
    return True, None


def list_users(rol="todos", estado="todos", q="", page=1, per_page=20):
    """Lista paginada y filtrable de cuentas, para el panel de administración: rol (admin/cliente/
    todos), estado (activos/inactivos/todos), búsqueda por nombre o correo. Incluye cuántos
    dominios monitoreados tiene cada una.

    Sin agregación SQL en lote (a diferencia de monitoring_service.py) a propósito: esta tabla es de
    cuentas de la aplicación, no de reportes/records — un volumen muy chico, no hace falta."""
    query = User.query
    if rol == "admin":
        query = query.filter_by(is_admin=True)
    elif rol == "cliente":
        query = query.filter_by(is_admin=False)
    if estado == "activos":
        query = query.filter_by(is_active=True)
    elif estado == "inactivos":
        query = query.filter_by(is_active=False)
    if q:
        like = f"%{q.strip().lower()}%"
        query = query.filter(or_(func.lower(User.name).like(like), func.lower(User.email).like(like)))
    users = query.order_by(User.created_at.desc()).all()

    items = []
    for u in users:
        plan = UserPlan.query.filter_by(user_id=u.id).first()
        items.append({
            "user": u,
            "domain_count": u.domains.count(),
            "plan_max_domains": get_max_domains(u.id),
            "plan_expires_label": plan.expires_at.strftime("%d-%m-%Y") if plan and plan.expires_at else None,
            "plan_is_expired": bool(plan and plan.expires_at and plan.expires_at < utcnow()),
            "plan_label": plan.plan.label if plan and plan.plan_id else None,
        })

    return paginate(items, page, per_page)


def set_user_active(user_id, is_active, current_user_id):
    """Activa o desactiva una cuenta (no borra nada — reversible). Devuelve (user, error): error es
    None si salió bien, "self" si intentó desactivarse a sí mismo, o "last_admin" si es el último
    admin activo (ninguna de las dos está permitida, para no dejar la cuenta sin nadie que pueda
    revertirlo). `user` viene con los datos sin cambiar en ambos casos de error."""
    user = User.query.get(user_id)
    if not user:
        return None, None

    if not is_active:
        if user.id == current_user_id:
            return user, "self"
        if user.is_admin:
            other_active_admins = User.query.filter(
                User.is_admin.is_(True), User.is_active.is_(True), User.id != user.id
            ).count()
            if other_active_admins == 0:
                return user, "last_admin"

    user.is_active = is_active
    db.session.commit()
    return user, None


def generate_api_key(user_id):
    """Genera (o regenera) la API key de un usuario — self-service, desde /cuenta. Devuelve la key
    en texto plano UNA sola vez (nunca se puede volver a mostrar, solo queda guardado su hash) o
    None si el usuario no existe. Regenerar invalida la anterior de inmediato: solo se guarda un
    hash por usuario, la vieja key deja de matchear en cuanto se pisa."""
    user = User.query.get(user_id)
    if not user:
        return None
    raw_key = secrets.token_urlsafe(32)
    user.api_key_hash = hashlib.sha256(raw_key.encode()).hexdigest()
    user.api_key_active = True
    user.api_key_created_at = utcnow()
    db.session.commit()
    return raw_key


def set_api_key_active(user_id, is_active):
    """Activa o desactiva la API key de un usuario (no la borra — reversible). Solo la puede tocar
    un admin, ver /admin/usuarios/<id>. Devuelve (user, error): error="no_key" si el usuario
    todavía no generó ninguna."""
    user = User.query.get(user_id)
    if not user:
        return None, None
    if not user.api_key_hash:
        return user, "no_key"
    user.api_key_active = is_active
    db.session.commit()
    return user, None


def get_user_by_api_key(raw_key):
    """Resuelve qué usuario es dueño de esta API key — None si no existe, está desactivada, o la
    cuenta entera está desactivada. Usado por @require_api_key en app.py, no por el login web."""
    if not raw_key:
        return None
    key_hash = hashlib.sha256(raw_key.encode()).hexdigest()
    user = User.query.filter_by(api_key_hash=key_hash).first()
    if not user or not user.api_key_active or not user.is_active:
        return None
    return user
