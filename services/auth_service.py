from models import User, db


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
