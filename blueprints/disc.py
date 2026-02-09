<<<<<<< HEAD
"""Disc/QR-hantering för inloggade användare."""
import logging
import os
from flask import Blueprint, render_template, request, flash, session, redirect, url_for, send_file

from database import db
from utils import generate_qr_pdf
from config import Config
=======
"""Dashboard och QR-hantering - NY med 1 QR per spelare."""
import logging
from datetime import datetime
from flask import Blueprint, render_template, request, redirect, url_for, flash, session, send_file

from database import db
from utils import generate_qr_pdf, Config
>>>>>>> 9429973fcd56ea78bdf3b3958182bb9ff21391be

logger = logging.getLogger(__name__)

bp = Blueprint('disc', __name__, url_prefix='')


<<<<<<< HEAD
@bp.route('/dashboard')
def dashboard():
    """Huvudsida för inloggade användare."""
    if 'user_id' not in session:
        flash('Logga in först.', 'error')
        return redirect(url_for('auth.login'))
    
    user = db.get_user_by_id(session['user_id'])
    if not user:
        session.clear()
        flash('Användare hittades inte.', 'error')
        return redirect(url_for('auth.login'))
    
    qr = db.get_user_qr(user['id'])
    stats = db.get_user_stats(user['id'])
    
    return render_template('disc/dashboard.html', 
                         user=user, 
                         qr=qr, 
                         stats=stats)


@bp.route('/download-qr/<qr_id>')
def download_qr(qr_id):
    """Ladda ner QR-kod som bild."""
    if 'user_id' not in session:
        flash('Logga in först.', 'error')
        return redirect(url_for('auth.login'))
    
    user = db.get_user_by_id(session['user_id'])
    qr = db.get_qr(qr_id)
    
    if not qr or qr['user_id'] != user['id']:
        flash('Åtkomst nekad.', 'error')
        return redirect(url_for('disc.dashboard'))
    
    qr_path = f"static/qr/qr_{qr_id}.png"
    if os.path.exists(qr_path):
        return send_file(qr_path, as_attachment=True, download_name=f"returnadisc-{qr_id}.png")
    
    flash('QR-kod hittades inte.', 'error')
    return redirect(url_for('disc.dashboard'))


@bp.route('/download-qr-pdf/<qr_id>')
def download_qr_pdf(qr_id):
    """Ladda ner QR-kod som PDF."""
    if 'user_id' not in session:
        flash('Logga in först.', 'error')
        return redirect(url_for('auth.login'))
    
    user = db.get_user_by_id(session['user_id'])
    qr = db.get_qr(qr_id)
    
    if not qr or qr['user_id'] != user['id']:
        flash('Åtkomst nekad.', 'error')
        return redirect(url_for('disc.dashboard'))
    
    try:
        pdf_path = generate_qr_pdf(qr_id, Config.PUBLIC_URL)
        return send_file(pdf_path, as_attachment=True, download_name=f"returnadisc-{qr_id}.pdf")
    except Exception as e:
        logger.error(f"PDF generation failed: {e}")
        flash('Kunde inte generera PDF.', 'error')
        return redirect(url_for('disc.dashboard'))
=======
def get_current_user():
    """Hämta inloggad användare."""
    user_id = session.get('user_id')
    if not user_id:
        return None
    return db.get_user_by_id(user_id)


@bp.before_request
def require_login():
    """Skydda routes."""
    if request.endpoint and 'dashboard' in request.endpoint:
        if not get_current_user():
            flash('Du måste logga in först.', 'warning')
            return redirect(url_for('auth.login', next=request.url))


@bp.route('/dashboard')
def dashboard():
    """NY Dashboard - Startsida för inloggade."""
    user = get_current_user()
    stats = db.get_user_stats(user['id'])
    qr = db.get_user_qr(user['id'])
    
    return render_template('disc/dashboard.html', user=user, stats=stats, qr=qr)


@bp.route('/activate-qr', methods=['GET', 'POST'])
def activate_qr_page():
    """Aktivera QR-kod från dashboard (inloggad)."""
    user = get_current_user()
    if not user:
        return redirect(url_for('auth.login'))
    
    # Kolla om redan har QR
    existing_qr = db.get_user_qr(user['id'])
    if existing_qr:
        flash('Du har redan en aktiv QR-kod!', 'info')
        return redirect(url_for('disc.dashboard'))
    
    # Förifyll om QR-ID kommer med i URL
    prefilled_qr = request.args.get('qr_id', '')
    
    if request.method == 'POST':
        qr_id = request.form.get('qr_id', '').strip().upper()
        qr = db.get_qr(qr_id)
        
        if not qr:
            flash('QR-koden finns inte.', 'error')
            return redirect(url_for('disc.activate_qr_page'))
        
        if qr['is_active']:
            flash('Denna QR-kod är redan aktiverad av någon annan.', 'error')
            return redirect(url_for('disc.activate_qr_page'))
        
        # Aktivera!
        db.activate_qr(qr_id, user['id'])
        flash('Din QR-kod är aktiverad! Sätt den på alla dina discar.', 'success')
        return redirect(url_for('disc.dashboard'))
    
    return render_template('disc/activate_qr_page.html', prefilled_qr=prefilled_qr)


@bp.route('/activate/<qr_id>', methods=['GET', 'POST'])
def activate_qr(qr_id):
    """Aktivera QR-kod vid scanning (gammal route, redirecta till ny)."""
    # Om inloggad, skicka till aktiveringssida med förifylld kod
    if session.get('user_id'):
        return redirect(url_for('disc.activate_qr_page', qr_id=qr_id))
    
    # Om inte inloggad, spara och skicka till login
    session['pending_qr_activation'] = qr_id
    flash('Logga in eller skapa konto för att aktivera denna QR-kod.', 'warning')
    return redirect(url_for('auth.login'))


@bp.route('/qr')
def view_qr():
    """Visa min QR-kod."""
    user = get_current_user()
    qr = db.get_user_qr(user['id'])
    
    if not qr:
        flash('Du har ingen QR-kod än. Aktivera en först.', 'warning')
        return redirect(url_for('disc.activate_qr_page'))
    
    qr_path = f"/static/qr/{qr['qr_id']}.png"
    return render_template('disc/view_qr.html', qr=qr, qr_path=qr_path)


# ENDAST FÖR TEST - tas bort senare
@bp.route('/create-qr', methods=['GET', 'POST'])
def create_qr():
    """Generera QR-koder - ENDAST ADMIN/TEST."""
    user = get_current_user()
    
    # TODO: Ändra till admin-only senare
    if request.method == 'POST':
        count = int(request.form.get('count', 1))
        
        if count > 30:
            flash('Max 30 per gång.', 'error')
            return redirect(url_for('disc.create_qr'))
        
        pdf_path = generate_qr_pdf(count, Config.PUBLIC_URL)
        logger.info(f"User {user['email']} created {count} QR codes")
        
        return send_file(pdf_path, as_attachment=True, 
                        download_name=f'returnadisc_qr_{datetime.now().strftime("%Y%m%d")}.pdf')
    
    return render_template('disc/create_qr.html')


@bp.route('/scan')
def scan():
    """QR-scanner."""
    return render_template('disc/scan.html')
>>>>>>> 9429973fcd56ea78bdf3b3958182bb9ff21391be
