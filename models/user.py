from flask_login import UserMixin
from werkzeug.security import check_password_hash, generate_password_hash

from models import db
from models.monitoring import utcnow

# Límite de dominios activos para cualquier usuario (no-admin) sin una fila propia en UserPlan —
# evita tener que crear/backfillear una fila por usuario para que el límite ya funcione. Un cliente
# nuevo arranca en 1; para darle más, el admin le edita el plan desde /admin/usuarios. Ver UserPlan
# más abajo, y get_max_domains() en services/monitoring_service.py para la excepción de admins
# (sin límite, ver ese mismo comentario).
DEFAULT_MAX_DOMAINS = 1


class User(UserMixin, db.Model):
    """Una cuenta que puede iniciar sesión para registrar y ver sus propios dominios monitoreados."""

    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(255), nullable=True)
    email = db.Column(db.String(255), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(255), nullable=False)
    created_at = db.Column(db.DateTime(timezone=True), default=utcnow, nullable=False)
    # is_admin: quién puede ver/administrar el panel de usuarios (services/auth_service.py:list_users()).
    # is_active: si la cuenta puede iniciar sesión — sobreescribe a propósito la property por
    # default (siempre True) de UserMixin; es el patrón que la propia documentación de Flask-Login
    # recomienda para tener una cuenta desactivable de verdad.
    is_admin = db.Column(db.Boolean, nullable=False, default=False)
    is_active = db.Column(db.Boolean, nullable=False, default=True)
    # Nulo = todavía nunca inició sesión (ej. una cuenta recién creada). Se actualiza en cada login
    # exitoso (ver auth_login() en app.py) — no en cada request, solo al loguearse.
    last_login_at = db.Column(db.DateTime(timezone=True), nullable=True)

    domains = db.relationship("MonitoredDomain", backref="owner", lazy="dynamic")
    plan = db.relationship("UserPlan", backref="user", uselist=False, cascade="all, delete-orphan")

    def set_password(self, password):
        """Genera y guarda el hash de la contraseña — nunca se guarda en texto plano."""
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        """Verifica una contraseña contra el hash guardado."""
        return check_password_hash(self.password_hash, password)


class Plan(db.Model):
    """Catálogo de planes disponibles — hoy 2 filas fijas, sembradas a mano una sola vez (ver
    AGENTS.md): "free" (1 dominio, prueba de 20 días) y "paid" (5 dominios, USD 12/mes). No hay
    self-service para crear planes nuevos desde la UI; si hiciera falta un tercero, se agrega con
    una fila más acá, a mano.

    Todavía NO hay cobro real (sin pasarela integrada) — `price_usd` es informativo nada más, y
    pasar a "paid" hoy es una acción manual del admin desde /admin/usuarios, no un checkout real."""

    __tablename__ = "plans"

    id = db.Column(db.Integer, primary_key=True)
    # slug estable en inglés (referenciado en código, ej. assign_plan(user_id, "free")) — no
    # renombrar sin actualizar services/monitoring_service.py.
    name = db.Column(db.String(50), unique=True, nullable=False)
    label = db.Column(db.String(100), nullable=False)  # nombre en español para mostrar en la UI
    max_domains = db.Column(db.Integer, nullable=False)
    price_usd = db.Column(db.Numeric(10, 2), nullable=False, default=0)
    # Días de vigencia desde que se asigna el plan (None = sin vencimiento). Hoy solo "free" lo usa
    # (20 días de prueba); "paid" queda indefinido hasta que exista cobro real que lo renueve.
    trial_days = db.Column(db.Integer, nullable=True)


class UserPlan(db.Model):
    """Límite de dominios ACTIVOS que un usuario puede tener en monitoreo — funciona como un plan.

    Un usuario sin fila propia acá no está "sin plan": simplemente usa DEFAULT_MAX_DOMAINS (ver
    get_max_domains() en services/monitoring_service.py) — así no hace falta crear ni backfillear
    una fila por cada usuario existente para que el límite ya aplique.

    `max_domains`/`expires_at` son los campos que de verdad se hacen cumplir (get_max_domains() los
    lee directo) — `plan_id` es solo la referencia a qué plan del catálogo los originó, para
    mostrarlo en la UI y como acceso rápido de "asignar Free/Pago". Puede quedar `None` (asignación
    manual/vieja, de antes de que existiera el catálogo) sin que nada se rompa.

    Solo cuentan los dominios con is_active=True — desactivar uno libera un cupo para registrar u
    otro (decisión explícita: el límite es de "en uso ahora", no de "registrados alguna vez")."""

    __tablename__ = "user_plans"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), unique=True, nullable=False)
    plan_id = db.Column(db.Integer, db.ForeignKey("plans.id"), nullable=True)
    max_domains = db.Column(db.Integer, nullable=False, default=DEFAULT_MAX_DOMAINS)
    # expires_at nulo = sin vencimiento (permanente). Vencido: get_max_domains() en
    # services/monitoring_service.py vuelve sola a DEFAULT_MAX_DOMAINS, no bloquea todo — un
    # usuario con dominios ya activos por encima del nuevo límite no pierde ninguno de inmediato al
    # solo consultar el límite (eso lo revisa jobs/deactivate_expired_trials.py aparte, que si los
    # desactiva de verdad cuando el plan Free vence sin pasar a Pago).
    expires_at = db.Column(db.DateTime(timezone=True), nullable=True)
    created_at = db.Column(db.DateTime(timezone=True), default=utcnow, nullable=False)
    updated_at = db.Column(db.DateTime(timezone=True), default=utcnow, onupdate=utcnow, nullable=False)

    plan = db.relationship("Plan")
