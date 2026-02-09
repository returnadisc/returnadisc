"""Disc/QR-hantering för inloggade användare."""
import logging
import os
from flask import Blueprint, render_template, request, flash, session, redirect, url_for, send_file

from database import db
from utils import generate_qr_pdf
from config import Config

logger = logging.getLogger(__name__)

bp = Blueprint('disc', __name__, url_prefix='')


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
    missing_stats = db.get_user_missing_stats(user['id'])
    
    return render_template('disc/dashboard.html', 
                         user=user, 
                         qr=qr, 
                         stats=stats,
                         missing_stats=missing_stats)


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