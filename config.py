"""Central konfigurationsfil."""
import os
from datetime import timedelta, datetime

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
    
    # Email (Resend)
    RESEND_API_KEY = os.environ.get('RESEND_API_KEY', '')
    MAIL_DEFAULT_SENDER = "info@returnadisc.se"
    
    # Email (SMTP) - fallback
    EMAIL_ENABLED = os.environ.get('EMAIL_ENABLED', 'false').lower() == 'true'
    EMAIL_FROM = os.environ.get('EMAIL_FROM', 'info@returnadisc.se')
    SMTP_SERVER = os.environ.get('SMTP_SERVER', 'smtp.gmail.com')
    SMTP_PORT = int(os.environ.get('SMTP_PORT', 587))
    EMAIL_USER = os.environ.get('EMAIL_USER', 'info@returnadisc.se')
    EMAIL_PASSWORD = os.environ.get('EMAIL_PASSWORD', '')
    
    # URL:er
    BASE_URL = os.environ.get('BASE_URL', 'http://localhost:5000')
    PUBLIC_URL = os.environ.get('PUBLIC_URL', BASE_URL)
    
    # Admin
    ADMIN_KEY = os.environ.get('ADMIN_KEY')
    ADMIN_EMAIL = os.environ.get('ADMIN_EMAIL', 'info@returnadisc.se')
    ADMIN_PASSWORD_HASH = os.environ.get('ADMIN_PASSWORD_HASH')
    
    # QR/PDF
    QR_FOLDER = 'static/qr'
    PDF_FOLDER = 'static/pdfs'
    MAX_QR_PER_REQUEST = 30
    
    # === INTERNATIONALISERING ===
    # Domäner
    DOMAIN_SE = 'returnadisc.se'
    DOMAIN_COM = 'returnadisc.com'
    
    # Valutor
    CURRENCY_SE = 'sek'
    CURRENCY_COM = 'usd'
    
    # Priser (i ören/cents)
    PREMIUM_PRICE_SEK = 3900  # 39 SEK
    PREMIUM_PRICE_USD = 399   # $3.99
    
    # Lanseringsdatum
    PREMIUM_LAUNCH_DATE = datetime(2026, 7, 1)
    
    @classmethod
    def is_launch_period(cls) -> bool:
        """Kolla om vi fortfarande är i lanseringsperioden."""
        return datetime.now() < cls.PREMIUM_LAUNCH_DATE
    
    @classmethod
    def get_premium_price(cls, currency='sek'):
        """Hämta aktuellt pris baserat på valuta."""
        if cls.is_launch_period():
            return 0
        return cls.PREMIUM_PRICE_USD if currency == 'usd' else cls.PREMIUM_PRICE_SEK
    
    @classmethod
    def get_currency(cls, domain):
        """Hämta valuta baserat på domän."""
        if cls.DOMAIN_COM in domain:
            return cls.CURRENCY_COM
        return cls.CURRENCY_SE


class DevelopmentConfig(Config):
    """Utvecklings-konfig."""
    DEBUG = True
    TESTING = False
    
    _admin_key = os.environ.get('ADMIN_KEY', 'dev-admin-key-change-in-prod')
    if _admin_key == 'dev-admin-key-change-in-prod':
        import logging
        logging.warning("WARNING: Using default ADMIN_KEY in development!")
    
    ADMIN_KEY = _admin_key
    ADMIN_EMAIL = 'info@returnadisc.se'
    ADMIN_PASSWORD_HASH = os.environ.get(
        'ADMIN_PASSWORD_HASH',
        'scrypt:32768:8:1$Te18cVzCiLyvdNJH$da5c98b8ce33d3cdab4eb8436c5bb29c0ae183f51f2e395f9f9c220a917dbfaf48a2f45fb9393315d757eb2e3ff58de8af0a6f9aa1bd6b1f8e3765be06404679'
    )


class ProductionConfig(Config):
    """Produktions-konfig."""
    DEBUG = False
    TESTING = False
    SESSION_COOKIE_SECURE = True
    PERMANENT_SESSION_LIFETIME = timedelta(hours=12)
    
    ADMIN_KEY = os.environ.get('ADMIN_KEY')
    ADMIN_EMAIL = os.environ.get('ADMIN_EMAIL', 'info@returnadisc.se')
    ADMIN_PASSWORD_HASH = os.environ.get('ADMIN_PASSWORD_HASH')
    
    if not ADMIN_PASSWORD_HASH:
        raise ValueError("ADMIN_PASSWORD_HASH must be set in production")


config = {
    'development': DevelopmentConfig,
    'production': ProductionConfig,
    'default': DevelopmentConfig
}