# blueprints/__init__.py
from .auth import bp as auth_bp
from .disc import bp as disc_bp
from .found import bp as found_bp
from .missing import bp as missing_bp
from .admin import bp as admin_bp
from . import qr

__all__ = ['auth_bp', 'disc_bp', 'found_bp', 'missing_bp', 'admin_bp']