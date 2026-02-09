"""ReturnaDisc - Flask-applikation."""
import os
import logging

from flask import Flask, request
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

from config import config
from database import db
from blueprints import auth_bp, disc_bp, found_bp, admin_bp, missing_bp

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


def create_app(config_name=None):
    """Application factory."""
    if config_name is None:
        config_name = os.environ.get('FLASK_ENV', 'development')

    app = Flask(__name__)
    app.config.from_object(config[config_name])

    # Säkerhet: Rate limiting
    limiter = Limiter(
        app=app,
        key_func=get_remote_address,
        default_limits=["200 per day", "50 per hour"]
    )

    # Säkerhet: Stricter limits for auth endpoints
    limiter.limit("5 per minute")(auth_bp)

    # Initiera databas
    db.init_tables()

    # Skapa folders om de inte finns
    for folder in [
        app.config['UPLOAD_FOLDER'],
        app.config['QR_FOLDER'],
        app.config['PDF_FOLDER']
    ]:
        os.makedirs(folder, exist_ok=True)

    # Registrera blueprints
    app.register_blueprint(auth_bp)
    app.register_blueprint(disc_bp)
    app.register_blueprint(found_bp)
    app.register_blueprint(admin_bp)
    app.register_blueprint(missing_bp)

    # Global error handlers
    @app.errorhandler(404)
    def not_found(error):
        return "Sidan finns inte", 404

    @app.errorhandler(500)
    def internal_error(error):
        logger.error(f"Server error: {error}")
        return "Ett fel uppstod", 500

    # Context processor
    @app.context_processor
    def inject_globals():
        from flask import session
        return {
            'current_user': db.get_user_by_id(session.get('user_id')),
            'base_url': app.config.get(
                'BASE_URL',
                request.host_url.rstrip('/')
            )
        }

    return app


# Skapa app-instans
app = create_app()

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=app.config.get('DEBUG', False))
