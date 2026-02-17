"""Missing disc-hantering."""
import logging
from functools import wraps
from flask import (
    Blueprint, render_template, request, flash, 
    redirect, url_for, session, jsonify
)
from database import db

logger = logging.getLogger(__name__)

bp = Blueprint('missing', __name__, url_prefix='/missing')


# ============================================================================
# Decorators
# ============================================================================

def login_required(f):
    """Decorator som kräver inloggning."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Du måste vara inloggad för att se denna sida.', 'error')
            return redirect(url_for('auth.login'))
        return f(*args, **kwargs)
    return decorated_function


# ============================================================================
# Routes
# ============================================================================

@bp.route('/community-map')
@login_required
def community_map():
    """
    Community-karta - tillgänglig för alla inloggade.
    BAS: Ser bara egna discar på kartan
    PREMIUM: Ser alla discar (egna + andras)
    """
    user_id = session.get('user_id')
    
    # Kolla premium-status
    premium_status = db.get_user_premium_status(user_id)
    has_premium = premium_status.get('has_premium', False)
    
    # Hämta användarens egna discar (alla ser alltid sina egna)
    my_discs = db.get_user_missing_discs(user_id)
    
    # Hämta alla andras discar om premium, annars tom lista
    if has_premium:
        all_discs = db.get_all_missing_discs(status='missing')
        other_discs = [d for d in all_discs if d['user_id'] != user_id]
    else:
        other_discs = []
    
    return render_template('missing/community_map.html', 
                         my_discs=my_discs,
                         other_discs=other_discs,
                         has_premium=has_premium)


@bp.route('/report', methods=['GET', 'POST'])
@login_required
def report():
    """Rapportera saknad disc - tillgängligt för alla inloggade."""
    if request.method == 'POST':
        user_id = session.get('user_id')
        
        disc_name = request.form.get('disc_name', '').strip()
        description = request.form.get('description', '').strip()
        course_name = request.form.get('course_name', '').strip()
        hole_number = request.form.get('hole_number', '').strip()
        latitude = request.form.get('latitude')
        longitude = request.form.get('longitude')
        
        # Validering
        if not disc_name:
            flash('Ange ett namn på discen.', 'error')
            return redirect(url_for('missing.report'))
        
        if not latitude or not longitude:
            flash('Välj en plats på kartan.', 'error')
            return redirect(url_for('missing.report'))
        
        try:
            disc_id = db.report_missing_disc(
                user_id=user_id,
                disc_name=disc_name,
                description=description,
                latitude=float(latitude),
                longitude=float(longitude),
                course_name=course_name,
                hole_number=hole_number
            )
            
            logger.info(f"Disc {disc_id} rapporterad saknad av användare {user_id}")
            flash('Din disc är rapporterad som saknad!', 'success')
            return redirect(url_for('missing.community_map'))
            
        except Exception as e:
            logger.error(f"Fel vid rapportering av saknad disc: {e}")
            flash('Ett fel uppstod. Försök igen.', 'error')
            return redirect(url_for('missing.report'))
    
    return render_template('missing/report.html')


@bp.route('/my-discs')
@login_required
def my_discs():
    """Visa användarens egna saknade discar."""
    user_id = session.get('user_id')
    discs = db.get_user_missing_discs(user_id)
    return render_template('missing/my_discs.html', discs=discs)


@bp.route('/delete/<int:disc_id>', methods=['POST'])
@login_required
def delete_disc(disc_id):
    """Ta bort en rapporterad saknad disc."""
    user_id = session.get('user_id')
    
    try:
        success = db.delete_missing_disc(disc_id, user_id)
        if success:
            flash('Disc borttagen.', 'success')
        else:
            flash('Kunde inte ta bort discen.', 'error')
    except Exception as e:
        logger.error(f"Fel vid borttagning av disc {disc_id}: {e}")
        flash('Ett fel uppstod.', 'error')
    
    return redirect(url_for('missing.my_discs'))


@bp.route('/api/nearby')
@login_required
def nearby_discs():
    """API-endpoint för att hämta närliggande discar (för karta)."""
    try:
        user_id = session.get('user_id')
        lat = request.args.get('lat', type=float)
        lng = request.args.get('lng', type=float)
        radius = request.args.get('radius', default=10, type=float)
        
        if lat is None or lng is None:
            return jsonify({'error': 'Latitud och longitud krävs'}), 400
        
        # Kolla premium-status
        premium_status = db.get_user_premium_status(user_id)
        has_premium = premium_status.get('has_premium', False)
        
        # Hämta discar
        if has_premium:
            # Premium ser alla discar
            all_discs = db.get_all_missing_discs(status='missing')
        else:
            # BAS ser bara egna
            all_discs = db.get_user_missing_discs(user_id)
        
        # Filtrera efter avstånd
        import math
        
        def calculate_distance(lat1, lng1, lat2, lng2):
            R = 6371
            d_lat = math.radians(lat2 - lat1)
            d_lng = math.radians(lng2 - lng1)
            a = (math.sin(d_lat / 2) * math.sin(d_lat / 2) +
                 math.cos(math.radians(lat1)) * math.cos(math.radians(lat2)) *
                 math.sin(d_lng / 2) * math.sin(d_lng / 2))
            c = 2 * math.atan2(math.sqrt(a), math.sqrt(1 - a))
            return R * c
        
        nearby = []
        for disc in all_discs:
            if disc.get('latitude') and disc.get('longitude'):
                dist = calculate_distance(lat, lng, disc['latitude'], disc['longitude'])
                if dist <= radius:
                    disc['distance'] = round(dist, 2)
                    nearby.append(disc)
        
        nearby.sort(key=lambda x: x['distance'])
        
        return jsonify({
            'discs': nearby,
            'count': len(nearby),
            'has_premium': has_premium
        })
        
    except Exception as e:
        logger.error(f"Fel vid hämtning av närliggande discar: {e}")
        return jsonify({'error': 'Serverfel'}), 500