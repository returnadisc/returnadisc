"""Central konfigurationsfil."""
import os
from datetime import timedelta, datetime

from dotenv import load_dotenv
from werkzeug.security import generate_password_hash

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
    MAIL_DEFAULT_SENDER = "info@returnadisc.se"
    
    # Email (SMTP)
    EMAIL_ENABLED = os.environ.get('EMAIL_ENABLED', 'false').lower() == 'true'
    EMAIL_FROM = os.environ.get('EMAIL_FROM', 'info@returnadisc.se')
    SMTP_SERVER = os.environ.get('SMTP_SERVER', 'smtp.gmail.com')
    SMTP_PORT = int(os.environ.get('SMTP_PORT', 587))
    EMAIL_USER = os.environ.get('EMAIL_USER', 'info@returnadisc.se')
    EMAIL_PASSWORD = os.environ.get('EMAIL_PASSWORD', '')
    
    # URL:er - VIKTIGA FÖR PRODUKTION
    BASE_URL = os.environ.get('BASE_URL', 'http://localhost:5000')
    PUBLIC_URL = os.environ.get('PUBLIC_URL', BASE_URL)
    
    # Admin
    ADMIN_KEY = os.environ.get('ADMIN_KEY', 'dev-admin-key-change-in-prod')
    ADMIN_EMAIL = os.environ.get('ADMIN_EMAIL', 'admin@returnadisc.se')
    ADMIN_PASSWORD_HASH = generate_password_hash('scrypt:32768:8:1$ZxXcL46IYbKNUWjR$28a576262227c23c3af11e6b19ceee04c4c535ad5b29d3d5a507dd172b307ba0c8cd3e3a78b6178ab782924cb2d2809cefcf95f453de378e863e6ba13f76aaa4')
    
    # QR/PDF
    QR_FOLDER = 'static/qr'
    PDF_FOLDER = 'static/pdfs'
    MAX_QR_PER_REQUEST = 30
    
    # Premium-kampanj (gratis fram till 1 juli)
    PREMIUM_LAUNCH_DATE = datetime(2026, 7, 1)
    PREMIUM_PRICE_SEK = 39
    
    @classmethod
    def is_launch_period(cls) -> bool:
        """Kolla om vi fortfarande är i lanseringsperioden (gratis premium)."""
        return datetime.now() < cls.PREMIUM_LAUNCH_DATE
    
    @classmethod
    def get_premium_price(cls) -> int:
        """Hämta aktuellt pris (0 under lansering)."""
        return 0 if cls.is_launch_period() else cls.PREMIUM_PRICE_SEK


class DevelopmentConfig(Config):
    """Utvecklings-konfig - tillåter säkra defaults."""
    DEBUG = True
    TESTING = False
    
    _admin_key = os.environ.get('ADMIN_KEY', 'dev-admin-key-change-in-prod')
    if _admin_key == 'dev-admin-key-change-in-prod':
        import logging
        logging.warning("WARNING: Using default ADMIN_KEY in development!")
    ADMIN_KEY = _admin_key
    
    ADMIN_EMAIL = 'admin@returnadisc.se'
    ADMIN_PASSWORD_HASH = generate_password_hash('scrypt:32768:8:1$ZxXcL46IYbKNUWjR$28a576262227c23c3af11e6b19ceee04c4c535ad5b29d3d5a507dd172b307ba0c8cd3e3a78b6178ab782924cb2d2809cefcf95f453de378e863e6ba13f76aaa4')
    


class ProductionConfig(Config):
    """Produktions-konfig."""
    DEBUG = False
    TESTING = False
    SESSION_COOKIE_SECURE = True
    PERMANENT_SESSION_LIFETIME = timedelta(hours=12)
    
    ADMIN_KEY = os.environ.get('ADMIN_KEY', 'dev-admin-key-change-in-prod')
    ADMIN_EMAIL = os.environ.get('ADMIN_EMAIL', 'admin@returnadisc.se')
    ADMIN_PASSWORD_HASH = os.environ.get('ADMIN_PASSWORD_HASH') or generate_password_hash('scrypt:32768:8:1$ZxXcL46IYbKNUWjR$28a576262227c23c3af11e6b19ceee04c4c535ad5b29d3d5a507dd172b307ba0c8cd3e3a78b6178ab782924cb2d2809cefcf95f453de378e863e6ba13f76aaa4')


config = {
    'development': DevelopmentConfig,
    'production': ProductionConfig,
    'default': DevelopmentConfig
}