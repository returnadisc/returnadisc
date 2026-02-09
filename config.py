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
    # BASE_URL = för appen (localhost vid utveckling, returnadisc.se i produktion)
    BASE_URL = os.environ.get('BASE_URL', 'http://localhost:5000')
    
    # PUBLIC_URL = för bilder i mail (samma som BASE_URL i produktion)
    PUBLIC_URL = os.environ.get('PUBLIC_URL', BASE_URL)
    
    # Admin
    ADMIN_KEY = os.environ.get('ADMIN_KEY', 'admin123')
    ADMIN_EMAIL = os.environ.get('ADMIN_EMAIL', 'admin@returnadisc.se')
    ADMIN_PASSWORD_HASH = os.environ.get('ADMIN_PASSWORD_HASH', '')
    
    # QR/PDF
    QR_FOLDER = 'static/qr'
    PDF_FOLDER = 'static/pdfs'
    MAX_QR_PER_REQUEST = 30


class DevelopmentConfig(Config):
    """Utvecklings-konfig."""
    DEBUG = True
    TESTING = False


class ProductionConfig(Config):
    """Produktions-konfig."""
    DEBUG = False
    TESTING = False
    SESSION_COOKIE_SECURE = True


config = {
    'development': DevelopmentConfig,
    'production': ProductionConfig,
    'default': DevelopmentConfig
}