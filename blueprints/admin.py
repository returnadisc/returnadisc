"""Admin-funktioner."""
import logging
from flask import Blueprint, render_template, request, redirect, url_for, flash, session, send_file

from database import db
from utils import generate_random_qr_id, generate_qr_pdf
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
        
        if email == 'admin@returnadisc.se' and password == 'admin123':
            session['is_admin'] = True
            session['admin_email'] = email
            flash('Inloggad som admin.', 'success')
            return redirect(url_for('admin.dashboard'))
        
        flash('Fel inloggningsuppgifter.', 'error')
        logger.warning(f"Failed admin login from: {request.remote_addr}")
    
    return render_template('admin/admin_login.html')


@bp.route('/')
def dashboard():
    """Admin dashboard."""
    if not check_admin():
        return redirect(url_for('admin.login'))
    
    stats = db.get_admin_stats()
    return render_template('admin/admin_dashboard.html', stats=stats)


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
    
    try:
        count = int(request.form.get('count', 10))
        if count < 1 or count > 30:
            flash('Antal måste vara mellan 1 och 30.', 'error')
            return redirect(url_for('admin.create_qr'))
        
        pdf_path = generate_qr_pdf(count, Config.PUBLIC_URL)
        
        logger.info(f"Admin generated {count} QR codes")
        flash(f'{count} QR-koder genererade!', 'success')
        
        return send_file(pdf_path, as_attachment=True, download_name=f'returnadisc-qr-batch-{count}st.pdf')
        
    except Exception as e:
        logger.error(f"PDF generation failed: {e}")
        flash(f'Fel vid generering: {str(e)}', 'error')
        return redirect(url_for('admin.create_qr'))


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
            SELECT q.qr_id, q.is_active, q.activated_at, q.total_scans,
                   u.name, u.email, u.created_at, u.last_login
            FROM qr_codes q
            LEFT JOIN users u ON q.user_id = u.id
            ORDER BY q.created_at DESC
        """)
        qr_codes = [dict(row) for row in cur.fetchall()]
    
    return render_template('admin/qr_codes.html', qr_codes=qr_codes)


@bp.route('/users')
def list_users():
    """Lista alla användare med detaljerad statistik."""
    if not session.get('is_admin'):
        return redirect(url_for('admin.login'))
    
    users = db.get_all_users_with_stats()
    return render_template('admin/users.html', users=users)