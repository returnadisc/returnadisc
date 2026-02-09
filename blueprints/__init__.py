"""Initiera alla blueprints."""
from .auth import bp as auth_bp
from .disc import bp as disc_bp
from .found import bp as found_bp
from .admin import bp as admin_bp
from .missing import bp as missing_bp

__all__ = ['auth_bp', 'disc_bp', 'found_bp', 'admin_bp', 'missing_bp']