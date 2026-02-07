"""Admin-funktioner."""
import logging
from flask import Blueprint, render_template, request, redirect, url_for, flash, session, send_file

from database import db
from utils import generate_qr_id, generate_qr_pdf  # ÄNDRAT: generate_disc_id -> generate_qr_id
from config import Config

logger = logging.getLogger(__name__)

bp = Blueprint('admin', __name__, url_prefix='/admin')


def check_admin():
    """Kolla om användaren är admin."""
    if not session.get('is_admin'):
        return False
    if session.get('admin_email') != Config.ADMIN_EMAIL:
        return False
    return True


@bp.route('/login', methods=['GET', 'POST'])
def login():
    """Admin login."""
    if request.method == 'POST':
        email = request.form.get('email', '').strip().lower()
        password = request.form.get('password', '').strip()
        
        from werkzeug.security import check_password_hash
        
        if (email == Config.ADMIN_EMAIL and 
            check_password_hash(Config.ADMIN_PASSWORD_HASH, password)):
            session['is_admin'] = True
            session['admin_email'] = email
            flash('Inloggad som admin.', 'success')
            return redirect(url_for('admin.dashboard'))
        
        flash('Fel inloggningsuppgifter.', 'error')
        logger.warning(f"Failed admin login from: {request.remote_addr}")
    
    return render_template('admin/login.html')


@bp.route('/')
def dashboard():
    """Admin dashboard."""
    if not check_admin():
        return redirect(url_for('admin.login'))
    
    stats = db.get_stats()
    return render_template('admin/dashboard.html', stats=stats)


@bp.route('/create', methods=['GET'])
def create_qr():
    """Skapa QR-koder (admin)."""
    if not check_admin():
        return redirect(url_for('admin.login'))
    
    return render_template('admin/create_qr.html')


@bp.route('/qr-pdf', methods=['POST'])
def qr_pdf():
    """Generera QR-PDF."""
    if not check_admin():
        return redirect(url_for('admin.login'))
    
    count = int(request.form.get('count', 10))
    pdf_path = generate_qr_pdf(count, Config.PUBLIC_URL)  # Använd PUBLIC_URL
    
    logger.info(f"Admin generated {count} QR codes")
    
    return send_file(pdf_path, as_attachment=True)


@bp.route('/reset', methods=['POST'])
def reset_db():
    """Nollställ databasen."""
    if not check_admin():
        return redirect(url_for('admin.login'))
    
    confirm = request.form.get('confirm')
    if confirm != 'DELETE EVERYTHING':
        flash('Skriv "DELETE EVERYTHING" för att bekräfta.', 'error')
        return redirect(url_for('admin.dashboard'))
    
    db.reset_database()
    logger.warning("Database was reset by admin!")
    flash('Databasen är nollställd.', 'warning')
    
    return redirect(url_for('admin.dashboard'))


@bp.route('/logout')
def logout():
    """Admin logout."""
    session.pop('is_admin', None)
    session.pop('admin_email', None)
    flash('Utloggad.', 'info')
    return redirect(url_for('auth.index'))