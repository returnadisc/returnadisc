"""Missing discs - community karta för borttappade discar."""
import logging
from flask import Blueprint, render_template, request, redirect, url_for, flash, session, jsonify

from database import db
from utils import sanitize_input

logger = logging.getLogger(__name__)

bp = Blueprint('missing', __name__, url_prefix='/missing')


def login_required():
    """Kolla om användaren är inloggad."""
    if 'user_id' not in session:
        flash('Logga in först.', 'error')
        return False
    return True


def get_current_user():
    """Hämta inloggad användare."""
    if 'user_id' in session:
        return db.get_user_by_id(session['user_id'])
    return None


@bp.route('/')
def index():
    """Huvudsida - redirect till community-kartan."""
    if not login_required():
        return redirect(url_for('auth.login'))
    return redirect(url_for('missing.community_map'))


@bp.route('/map')
def community_map():
    """Community karta - alla saknade discar med filter."""
    if not login_required():
        return redirect(url_for('auth.login'))
    
    discs = db.get_all_missing_discs(status='missing')
    return render_template('missing/community_map.html', discs=discs)


@bp.route('/report', methods=['GET', 'POST'])
def report():
    """Rapportera saknad disc - nu med GET för formulär."""
    if not login_required():
        return redirect(url_for('auth.login'))
    
    user = get_current_user()
    
    if request.method == 'POST':
        disc_name = sanitize_input(request.form.get('disc_name', '')).strip()
        description = sanitize_input(request.form.get('description', '')).strip()
        course_name = sanitize_input(request.form.get('course_name', '')).strip()
        hole_number = sanitize_input(request.form.get('hole_number', '')).strip()
        latitude = request.form.get('latitude')
        longitude = request.form.get('longitude')
        
        if not disc_name or not description:
            flash('Fyll i alla obligatoriska fält.', 'error')
            return redirect(url_for('missing.report'))
        
        if not latitude or not longitude:
            flash('Välj plats på kartan.', 'error')
            return redirect(url_for('missing.report'))
        
        try:
            db.report_missing_disc(
                user_id=user['id'],
                disc_name=disc_name,
                description=description,
                latitude=float(latitude),
                longitude=float(longitude),
                course_name=course_name or None,
                hole_number=hole_number or None
            )
            flash('Din saknade disc är rapporterad!', 'success')
        except Exception as e:
            logger.error(f"Failed to report missing disc: {e}")
            flash('Ett fel uppstod.', 'error')
        
        return redirect(url_for('missing.community_map'))
    
    # GET - visa formulär
    return render_template('missing/report.html')


@bp.route('/my-discs')
def my_missing_discs():
    """Se egna saknade discar."""
    if not login_required():
        return redirect(url_for('auth.login'))
    
    user = get_current_user()
    discs = db.get_user_missing_discs(user['id'])
    return render_template('missing/my_discs.html', discs=discs)


@bp.route('/found/<int:disc_id>', methods=['POST'])
def mark_found(disc_id):
    """Markera disc som hittad."""
    if not login_required():
        return redirect(url_for('auth.login'))
    
    user = get_current_user()
    
    with db.get_connection() as conn:
        cur = conn.cursor()
        cur.execute("SELECT * FROM missing_discs WHERE id = ?", (disc_id,))
        row = cur.fetchone()
        
        if not row:
            flash('Disc hittades inte.', 'error')
            return redirect(url_for('missing.community_map'))
        
        disc = dict(row)
        
        if disc['user_id'] == user['id']:
            db.mark_disc_found(disc_id)
            flash('Grattis att du hittade din disc!', 'success')
        else:
            db.mark_disc_found(disc_id, found_by_user_id=user['id'])
            flash('Tack för att du hjälpte till!', 'success')
    
    return redirect(url_for('missing.community_map'))


@bp.route('/delete/<int:disc_id>', methods=['POST'])
def delete(disc_id):
    """Ta bort egen rapport."""
    if not login_required():
        return redirect(url_for('auth.login'))
    
    user = get_current_user()
    db.delete_missing_disc(disc_id, user['id'])
    flash('Rapport borttagen.', 'success')
    return redirect(url_for('missing.my_missing_discs'))
    
    
@bp.route('/found-via-map/<int:disc_id>')
def found_via_map(disc_id):
    """Redirect till rätt hittad-disc-flöde baserat på QR-kod."""
    if not login_required():
        return redirect(url_for('auth.login'))
    
    # Hämta discen för att hitta ägarens QR-kod
    with db.get_connection() as conn:
        cur = conn.cursor()
        cur.execute("""
            SELECT m.*, u.id as owner_id, q.qr_id 
            FROM missing_discs m
            JOIN users u ON m.user_id = u.id
            LEFT JOIN qr_codes q ON q.user_id = u.id
            WHERE m.id = ?
        """, (disc_id,))
        row = cur.fetchone()
        
        if not row:
            flash('Disc hittades inte.', 'error')
            return redirect(url_for('missing.community_map'))
        
        disc = dict(row)
        action = request.args.get('action', 'hide')
        
        # Redirect till found-blueprint med ägarens QR-kod
        if action == 'hide':
            return redirect(url_for('found.found_hide', qr_id=disc['qr_id']))
        elif action == 'note':
            return redirect(url_for('found.found_note', qr_id=disc['qr_id']))
        elif action == 'meet':
            return redirect(url_for('found.found_meet', qr_id=disc['qr_id']))
        
        return redirect(url_for('found.found_qr', qr_id=disc['qr_id']))
        
        
@bp.route('/confirm-found')
def confirm_found():
    """Bekräfta att hittad disc matchar saknad rapport."""
    if not login_required():
        return redirect(url_for('auth.login'))
    
    disc_id = request.args.get('disc_id')
    confirm = request.args.get('confirm')
    
    if confirm == 'yes' and disc_id:
        # Markera som hittad
        db.mark_disc_found(disc_id)
        flash('Bra jobbat! Din disc är markerad som hittad.', 'success')
    elif confirm == 'no' or confirm == 'none':
        flash('Noterat. Din saknade disc finns kvar på kartan.', 'info')
    
    return redirect(url_for('missing.my_missing_discs'))