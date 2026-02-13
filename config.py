"""Central konfigurationsfil."""
import os
from datetime import timedelta

from dotenv import load_dotenv

load_dotenv()


class Config:
    """Bas-konfiguration."""
    
    # Flask
    SECRET_KEY = os.environ.get('SECRET_KEY')
    if not SECRET_KEY:
        raise ValueError("SECRET_KEY måste sättas i miljövariabler!")
    
    PERMANENT_SESSION_LIFETIME = timedelta(days=30)
    
    # Säkerhet
    SESSION_COOKIE_SECURE = os.environ.get('FLASK_ENV') == 'production'
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = 'Lax'
    
    # Uploads
    MAX_CONTENT_LENGTH = 16 * 1024 * 1024  # 16MB max
    UPLOAD_FOLDER = 'static/uploads'
    ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'webp'}
    
    # Database
    DATABASE_PATH = os.environ.get('DATABASE_URL', 'database.db')
    
    # SendGrid
    SENDGRID_API_KEY = os.environ.get('SENDGRID_API_KEY', '')
    MAIL_DEFAULT_SENDER = "noreply@returnadisc.se"
    
    # URL:er - VIKTIGA FÖR PRODUKTION
    BASE_URL = os.environ.get('BASE_URL', 'http://localhost:5000')
    PUBLIC_URL = os.environ.get('PUBLIC_URL', BASE_URL)
    
    # Admin - sätts av subklasser
    ADMIN_KEY = None
    ADMIN_EMAIL = os.environ.get('ADMIN_EMAIL', 'admin@returnadisc.se')
    ADMIN_PASSWORD_HASH = None
    
    # QR/PDF
    QR_FOLDER = 'static/qr'
    PDF_FOLDER = 'static/pdfs'
    MAX_QR_PER_REQUEST = 30


class DevelopmentConfig(Config):
    """Utvecklings-konfig - tillåter säkra defaults."""
    DEBUG = True
    TESTING = False
    
    # Tillåt osäkra defaults i utveckling MEN logga varning
    _admin_key = os.environ.get('ADMIN_KEY', 'dev-admin-key-change-in-prod')
    if _admin_key == 'dev-admin-key-change-in-prod':
        import logging
        logging.warning("WARNING: Using default ADMIN_KEY in development!")
    ADMIN_KEY = _admin_key
    
    _admin_hash = os.environ.get('ADMIN_PASSWORD_HASH', '')
    if not _admin_hash:
        import logging
        logging.warning("WARNING: ADMIN_PASSWORD_HASH not set! Admin login disabled.")
        # Sätt en ogiltig hash så inloggning misslyckas men appen startar
        from werkzeug.security import generate_password_hash
        ADMIN_PASSWORD_HASH = generate_password_hash('invalid-fallback-do-not-use')
    else:
        ADMIN_PASSWORD_HASH = _admin_hash


class ProductionConfig(Config):
    """Produktions-konfig - kräver alla miljövariabler."""
    DEBUG = False
    TESTING = False
    SESSION_COOKIE_SECURE = True
    PERMANENT_SESSION_LIFETIME = timedelta(hours=12)
    
    # Hämta från miljövariabler
    ADMIN_KEY = os.environ.get('ADMIN_KEY')
    ADMIN_PASSWORD_HASH = os.environ.get('ADMIN_PASSWORD_HASH')
    
    def __init__(self):
        # Validera att alla krävda variabler är satta
        if not self.ADMIN_KEY:
            raise ValueError("ADMIN_KEY måste sättas i miljövariabler!")
        if not self.ADMIN_PASSWORD_HASH:
            raise ValueError("ADMIN_PASSWORD_HASH måste sättas i miljövariabler!")


config = {
    'development': DevelopmentConfig,
    'production': ProductionConfig,
    'default': DevelopmentConfig
}