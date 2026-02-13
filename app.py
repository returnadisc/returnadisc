"""ReturnaDisc - Flask-applikation."""
import os
import sys
import logging

from flask import Flask, request, render_template, g, session

# Lägg till projektmappen i path
project_root = os.path.dirname(os.path.abspath(__file__))
if project_root not in sys.path:
    sys.path.insert(0, project_root)

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


def create_app():
    """Skapa Flask-applikation."""
    from config import config
    
    env = os.environ.get('FLASK_ENV', 'development')
    if env not in config:
        env = 'development'
    
    app = Flask(__name__)
    app.config.from_object(config[env])
    
    # Initiera databas
    from database import db
    db.init_tables()
    
    # Skapa foldrar
    for folder in ['UPLOAD_FOLDER', 'QR_FOLDER', 'PDF_FOLDER']:
        path = app.config.get(folder)
        if path:
            os.makedirs(path, exist_ok=True)
    
    # ============================================================================
    # REGISTRERA BLUEPRINTS - NU ENKLARE!
    # ============================================================================
    
    from blueprints import auth_bp, disc_bp, found_bp, missing_bp, admin_bp
    
    app.register_blueprint(auth_bp)
    app.register_blueprint(disc_bp)
    app.register_blueprint(found_bp)
    app.register_blueprint(missing_bp, url_prefix='/missing')
    app.register_blueprint(admin_bp, url_prefix='/admin')
    
    logger.info("✓ All blueprints registered")
    
    # Logga alla routes
    logger.info("Registered routes:")
    for rule in app.url_map.iter_rules():
        if rule.endpoint != 'static':
            logger.info(f"  {rule.endpoint}: {rule.rule}")
    
    # ============================================================================
    # ERROR HANDLERS
    # ============================================================================
    
    @app.errorhandler(404)
    def handle_404(error):
        user = None
        user_id = session.get('user_id')
        if user_id:
            user = db.get_user_by_id(user_id)
        return render_template('errors/404.html', current_user=user), 404
    
    @app.errorhandler(500)
    def handle_500(error):
        logger.error(f"Server error: {error}", exc_info=True)
        user = None
        user_id = session.get('user_id')
        if user_id:
            user = db.get_user_by_id(user_id)
        return render_template('errors/500.html', current_user=user), 500
    
    # ============================================================================
    # CONTEXT PROCESSOR
    # ============================================================================
    
    @app.context_processor
    def inject_globals():
        user = None
        user_id = session.get('user_id')
        if user_id:
            user = db.get_user_by_id(user_id)
        return {
            'current_user': user,
            'is_logged_in': user is not None
        }
    
    # ============================================================================
    # REQUEST LOGGING
    # ============================================================================
    
    @app.before_request
    def log_request():
        g.start_time = __import__('time').time()
    
    @app.after_request
    def log_response(response):
        if hasattr(g, 'start_time'):
            duration = f" ({(__import__('time').time() - g.start_time)*1000:.1f}ms)"
        else:
            duration = ""
        logger.info(f"{request.method} {request.path} - {response.status_code}{duration}")
        return response
    
    return app


app = create_app()


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=app.config.get('DEBUG', False))