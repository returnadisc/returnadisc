"""QR-kod hantering för användare - aktivera/inaktivera QR-koder."""
import logging
from functools import wraps
from typing import Callable

from flask import (
    Blueprint, render_template, request, flash, 
    session, redirect, url_for, g, jsonify
)

from database import db

logger = logging.getLogger(__name__)

bp = Blueprint('qr', __name__, url_prefix='/qr')


def login_required(f: Callable) -> Callable:
    """Decorator som kräver inloggning."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        user_id = session.get('user_id')
        if not user_id:
            flash('Logga in först.', 'error')
            return redirect(url_for('auth.login'))
        
        user = db.get_user_by_id(user_id)
        if not user:
            session.clear()
            flash('Användare hittades inte.', 'error')
            return redirect(url_for('auth.login'))
        
        g.user_id = user_id
        g.current_user = user
        return f(*args, **kwargs)
    return decorated_function


@bp.route('/manage')
@login_required
def manage():
    """Hantera alla QR-koder för användaren."""
    user_id = g.user_id
    
    # Hämta alla QR-koder för användaren
    all_qrs = db.get_user_qr_codes(user_id)
    
    # Separera aktiva och inaktiva
    active_qrs = [qr for qr in all_qrs if qr.get('is_enabled')]
    disabled_qrs = [qr for qr in all_qrs if not qr.get('is_enabled')]
    
    return render_template('qr/manage.html',
                         all_qrs=all_qrs,
                         active_qrs=active_qrs,
                         disabled_qrs=disabled_qrs,
                         user=g.current_user)


@bp.route('/activate', methods=['POST'])
@login_required
def activate():
    """Aktivera en ny QR-kod med kod (ej scanning)."""
    user_id = g.user_id
    qr_id = request.form.get('qr_id', '').strip().upper()
    
    if not qr_id:
        flash('Ange en QR-kod.', 'error')
        return redirect(url_for('qr.manage'))
    
    try:
        # Försök tilldela QR-koden till användaren
        db.assign_qr_to_user(qr_id, user_id)
        flash(f'QR-koden {qr_id} är nu aktiverad på ditt konto!', 'success')
        logger.info(f"Användare {user_id} aktiverade QR {qr_id}")
        
    except ValueError as e:
        flash(str(e), 'error')
    except Exception as e:
        logger.error(f"Fel vid aktivering av QR {qr_id}: {e}")
        flash('Ett fel uppstod. Försök igen.', 'error')
    
    return redirect(url_for('qr.manage'))


@bp.route('/toggle/<qr_id>', methods=['POST'])
@login_required
def toggle(qr_id):
    """Aktivera/inaktivera en specifik QR-kod."""
    user_id = g.user_id
    action = request.form.get('action', 'disable')
    
    try:
        enabled = (action == 'enable')
        success = db.toggle_qr_enabled(qr_id, user_id, enabled)
        
        if success:
            status = "aktiverad" if enabled else "inaktiverad"
            flash(f'QR-koden {qr_id} är nu {status}.', 'success')
        else:
            flash('Kunde inte uppdatera QR-koden. Kontrollera att du äger den.', 'error')
            
    except Exception as e:
        logger.error(f"Fel vid toggle av QR {qr_id}: {e}")
        flash('Ett fel uppstod.', 'error')
    
    return redirect(url_for('qr.manage'))


@bp.route('/api/list')
@login_required
def api_list():
    """API-endpoint för att lista QR-koder (JSON)."""
    user_id = g.user_id
    qrs = db.get_user_qr_codes(user_id)
    return jsonify([{
        'qr_id': qr['qr_id'],
        'is_active': qr['is_active'],
        'is_enabled': qr['is_enabled'],
        'total_scans': qr['total_scans'],
        'created_at': qr['created_at']
    } for qr in qrs])