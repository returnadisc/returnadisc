"""Admin-funktioner."""
import logging
from flask import Blueprint, render_template, request, redirect, url_for, flash, session, send_file

from database import db
<<<<<<< HEAD
from utils import generate_random_qr_id, generate_qr_pdf
=======
from utils import generate_qr_id, generate_qr_pdf  # ÄNDRAT: generate_disc_id -> generate_qr_id
>>>>>>> 9429973fcd56ea78bdf3b3958182bb9ff21391be
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
        
<<<<<<< HEAD
        if email == 'admin@returnadisc.se' and password == 'admin123':
=======
        from werkzeug.security import check_password_hash
        
        if (email == Config.ADMIN_EMAIL and 
            check_password_hash(Config.ADMIN_PASSWORD_HASH, password)):
>>>>>>> 9429973fcd56ea78bdf3b3958182bb9ff21391be
            session['is_admin'] = True
            session['admin_email'] = email
            flash('Inloggad som admin.', 'success')
            return redirect(url_for('admin.dashboard'))
        
        flash('Fel inloggningsuppgifter.', 'error')
        logger.warning(f"Failed admin login from: {request.remote_addr}")
    
<<<<<<< HEAD
    return render_template('login(1).html')
=======
    return render_template('admin/login.html')
>>>>>>> 9429973fcd56ea78bdf3b3958182bb9ff21391be


@bp.route('/')
def dashboard():
    """Admin dashboard."""
    if not check_admin():
        return redirect(url_for('admin.login'))
    
    stats = db.get_stats()
<<<<<<< HEAD
    return render_template('dashboard(1).html', stats=stats)
=======
    return render_template('admin/dashboard.html', stats=stats)
>>>>>>> 9429973fcd56ea78bdf3b3958182bb9ff21391be


@bp.route('/create', methods=['GET'])
def create_qr():
    """Skapa QR-koder (admin)."""
    if not check_admin():
        return redirect(url_for('admin.login'))
    
<<<<<<< HEAD
    return render_template('create_qr(1).html')
=======
    return render_template('admin/create_qr.html')
>>>>>>> 9429973fcd56ea78bdf3b3958182bb9ff21391be


@bp.route('/qr-pdf', methods=['POST'])
def qr_pdf():
    """Generera QR-PDF."""
    if not check_admin():
        return redirect(url_for('admin.login'))
    
    count = int(request.form.get('count', 10))
<<<<<<< HEAD
    pdf_path = generate_qr_pdf(count, Config.PUBLIC_URL)
=======
    pdf_path = generate_qr_pdf(count, Config.PUBLIC_URL)  # Använd PUBLIC_URL
>>>>>>> 9429973fcd56ea78bdf3b3958182bb9ff21391be
    
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
<<<<<<< HEAD
    return redirect(url_for('auth.index'))
    
    
@bp.route('/reset/<secret>')
def emergency_reset(secret):
    if secret == 'hemlig-nyckel-123':
        from werkzeug.security import generate_password_hash
        new_hash = generate_password_hash('admin123')
        return f"Nytt lösenord: nytt-lösenord"
    return "Fel"
     
    
@bp.route('/qr-codes')
def list_qr_codes():
    """Lista alla QR-koder och ägare."""
    if not session.get('is_admin'):
        return redirect(url_for('admin.login'))
    
    with db.get_connection() as conn:
        cur = conn.cursor()
        cur.execute("""
            SELECT q.qr_id, q.is_active, q.activated_at, 
                   u.name, u.email, u.created_at
            FROM qr_codes q
            LEFT JOIN users u ON q.user_id = u.id
            ORDER BY q.created_at DESC
        """)
        qr_codes = [dict(row) for row in cur.fetchall()]
    
    return render_template('qr_codes.html', qr_codes=qr_codes)
=======
    return redirect(url_for('auth.index'))
>>>>>>> 9429973fcd56ea78bdf3b3958182bb9ff21391be
