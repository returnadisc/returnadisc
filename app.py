"""Flask-applikation för ReturnADisc."""
import os
import logging
from datetime import datetime
from flask import Flask, render_template, request, session, g
from config import config
from blueprints import qr
from blueprints import missing


# Konfigurera logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


def create_app(config_name=None):
    """Applikationsfabrik."""
    if config_name is None:
        config_name = os.environ.get('FLASK_ENV', 'development')
    
    BASE_DIR = os.path.dirname(os.path.abspath(__file__))

    app = Flask(
        __name__,
        static_folder=os.path.join(BASE_DIR, "static"),
        template_folder=os.path.join(BASE_DIR, "templates")
    )

    app.config.from_object(config[config_name])
    
    # Säkerställ att SECRET_KEY är satt
    if not app.config.get('SECRET_KEY'):
        raise ValueError("SECRET_KEY måste sättas!")
    
    # === INTERNATIONALISERING: Detektera domän och språk ===
    @app.before_request
    def detect_domain():
        """Kör före varje request för att se vilken domän som besöks."""
        host = request.headers.get('Host', '').lower()
        
        if 'returnadisc.com' in host:
            g.domain = 'returnadisc.com'
            g.language = 'en'
            g.currency = 'usd'
            g.is_com = True
        else:
            g.domain = 'returnadisc.se'
            g.language = 'sv'
            g.currency = 'sek'
            g.is_com = False
        
        # Gör tillgängligt i templates
        app.jinja_env.globals['lang'] = g.language
        app.jinja_env.globals['currency'] = g.currency
        app.jinja_env.globals['is_com'] = g.is_com
    
    # Importera och registrera blueprints
    from blueprints import auth, disc, admin, found, missing, premium
    
    app.register_blueprint(auth.bp)
    app.register_blueprint(disc.bp)
    app.register_blueprint(admin.bp)
    app.register_blueprint(found.bp)
    app.register_blueprint(missing.bp)
    app.register_blueprint(premium.bp)
    app.register_blueprint(qr.bp)
    
    # Debug: Skriv ut alla registrerade endpoints
    with app.app_context():
        for rule in app.url_map.iter_rules():
            print(f"Endpoint: {rule.endpoint}")
    
    # Skapa databastabeller
    with app.app_context():
        from database import db
        db.init_tables()
        logger.info("Databasen initialiserad")
    
    # Global template variables
    @app.context_processor
    def inject_globals():
        return {
            'now': datetime.now(),
            'app_name': 'ReturnADisc',
            'lang': g.get('language', 'sv'),
            'currency': g.get('currency', 'sek'),
            'is_com': g.get('is_com', False)
        }
    
    # Error handlers
    @app.errorhandler(404)
    def not_found(error):
        return render_template('errors/404.html'), 404
    
    @app.errorhandler(500)
    def internal_error(error):
        return render_template('errors/500.html'), 500
    
    # Logga alla requests i development
    if app.config.get('DEBUG'):
        @app.before_request
        def log_request():
            logger.info(f"{request.method} {request.path} - {request.remote_addr}")
    
    logger.info(f"Applikationen startad i {config_name}-läge")
    return app


# Skapa app-instansen
app = create_app()

if __name__ == '__main__':
    port = int(os.environ.get("PORT", 5000))
    app.run(host='0.0.0.0', port=port)