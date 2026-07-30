from flask_login import UserMixin
from werkzeug.security import check_password_hash, generate_password_hash

from models import db
from models.monitoring import utcnow


class User(UserMixin, db.Model):
    """Una cuenta que puede iniciar sesión para registrar y ver sus propios dominios monitoreados."""

    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(255), nullable=True)
    email = db.Column(db.String(255), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(255), nullable=False)
    created_at = db.Column(db.DateTime(timezone=True), default=utcnow, nullable=False)

    domains = db.relationship("MonitoredDomain", backref="owner", lazy="dynamic")

    def set_password(self, password):
        """Genera y guarda el hash de la contraseña — nunca se guarda en texto plano."""
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        """Verifica una contraseña contra el hash guardado."""
        return check_password_hash(self.password_hash, password)
