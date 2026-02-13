"""Missing discs - community karta för borttappade discar."""
import logging
from dataclasses import dataclass
from typing import Optional, List, Dict, Callable
from functools import wraps

from flask import (
    Blueprint, render_template, request, redirect, 
    url_for, flash, session, jsonify, g
)

from database import db, MissingDisc

logger = logging.getLogger(__name__)

bp = Blueprint('missing', __name__, url_prefix='/missing')


# ============================================================================
# Dataclasses
# ============================================================================

@dataclass
class ReportFormData:
    """Håller data från rapport-formulär."""
    disc_name: str
    description: str
    latitude: float
    longitude: float
    course_name: Optional[str] = None
    hole_number: Optional[str] = None
    
    @classmethod
    def from_form(cls, form: Dict) -> 'ReportFormData':
        """Skapa från formulär-data."""
        return cls(
            disc_name=form.get('disc_name', '').strip(),
            description=form.get('description', '').strip(),
            latitude=float(form.get('latitude', 0)),
            longitude=float(form.get('longitude', 0)),
            course_name=form.get('course_name', '').strip() or None,
            hole_number=form.get('hole_number', '').strip() or None
        )
    
    def validate(self) -> None:
        """Validera rapport-data."""
        if not self.disc_name or not self.description:
            raise ValueError("Fyll i alla obligatoriska fält.")
        
        if not self.latitude or not self.longitude:
            raise ValueError("Välj plats på kartan.")
        
        if not (-90 <= self.latitude <= 90) or not (-180 <= self.longitude <= 180):
            raise ValueError("Ogiltiga koordinater.")


# ============================================================================
# Services
# ============================================================================

class MissingDiscService:
    """Service för hantering av saknade discar."""
    
    def __init__(self, database):
        self.db = database
    
    def report(self, user_id: int, form_data: ReportFormData) -> int:
        """
        Rapportera ny saknad disc.
        
        Returns:
            ID för skapad rapport
        """
        disc = MissingDisc(
            user_id=user_id,
            disc_name=form_data.disc_name,
            description=form_data.description,
            latitude=form_data.latitude,
            longitude=form_data.longitude,
            course_name=form_data.course_name,
            hole_number=form_data.hole_number
        )
        
        return self.db.report_missing_disc(
            user_id=disc.user_id,
            disc_name=disc.disc_name,
            description=disc.description,
            latitude=disc.latitude,
            longitude=disc.longitude,
            course_name=disc.course_name,
            hole_number=disc.hole_number
        )
    
    def get_user_discs(self, user_id: int) -> List[Dict]:
        """Hämta användarens saknade discar."""
        return self.db.get_user_missing_discs(user_id)
    
    def get_community_map_data(self, status: str = 'missing') -> List[Dict]:
        """Hämta data för community-kartan."""
        return self.db.get_all_missing_discs(status)
    
    def mark_found(self, disc_id: int, user_id: int) -> bool:
        """
        Markera disc som hittad.
        
        Returns:
            True om lyckad, False om inte ägd av användaren
        """
        # Verifiera ägarskap
        user_discs = self.get_user_discs(user_id)
        disc_ids = [d['id'] for d in user_discs]
        
        if disc_id not in disc_ids:
            return False
        
        self.db.mark_disc_found(disc_id)
        return True
    
    def delete_report(self, disc_id: int, user_id: int) -> bool:
        """Ta bort egen rapport."""
        return self.db.delete_missing_disc(disc_id, user_id)
    
    def get_disc_for_redirect(self, disc_id: int, user_id: int) -> Optional[Dict]:
        """
        Hämta disc för redirect till hittad-flödet.
        
        Returns:
            Disc med ägar-info, eller None om inte finns/ägs av annan
        """
        all_discs = self.db.get_all_missing_discs('missing')
        disc = next((d for d in all_discs if d['id'] == disc_id), None)
        
        if not disc:
            return None
        
        # Hämta ägarens QR-kod
        owner_qr = self.db.get_user_qr(disc['user_id'])
        if owner_qr:
            disc['owner_qr_id'] = owner_qr['qr_id']
        
        return disc


class PermissionService:
    """Service för behörighetskontroller."""
    
    @staticmethod
    def require_login() -> Optional[Dict]:
        """
        Kontrollera att användare är inloggad.
        
        Returns:
            User dict om inloggad, None annars
        """
        user_id = session.get('user_id')
        if not user_id:
            return None
        
        user = db.get_user_by_id(user_id)
        if not user:
            session.clear()
            return None
        
        return user
    
    @staticmethod
    def get_current_user_id() -> Optional[int]:
        """Hämta inloggad användares ID."""
        return session.get('user_id')


# ============================================================================
# Decorators
# ============================================================================

def login_required(f: Callable) -> Callable:
    """Decorator som kräver inloggning."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        user = PermissionService.require_login()
        
        if not user:
            flash('Logga in först.', 'error')
            return redirect(url_for('auth.login'))
        
        # Sätt user i g för tillgång i routes
        g.current_user = user
        g.user_id = user['id']
        
        return f(*args, **kwargs)
    
    return decorated_function


def handle_form_errors(f: Callable) -> Callable:
    """Decorator som fångar formulärfel."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        try:
            return f(*args, **kwargs)
        except ValueError as e:
            flash(str(e), 'error')
            return redirect(request.url)
        except Exception as e:
            logger.error(f"Oväntat fel: {e}")
            flash('Ett fel uppstod.', 'error')
            return redirect(request.url)
    
    return decorated_function


# ============================================================================
# Routes - Huvudsida och Karta
# ============================================================================

@bp.route('/')
@login_required
def index():
    """Huvudsida - redirect till community-kartan."""
    return redirect(url_for('missing.community_map'))


@bp.route('/map')
@login_required
def community_map():
    """Community karta - alla saknade discar."""
    service = MissingDiscService(db)
    discs = service.get_community_map_data('missing')
    return render_template('missing/community_map.html', discs=discs)


# ============================================================================
# Routes - Rapportera
# ============================================================================

@bp.route('/report', methods=['GET', 'POST'])
@login_required
@handle_form_errors
def report():
    """Rapportera saknad disc."""
    service = MissingDiscService(db)
    
    if request.method == 'POST':
        form_data = ReportFormData.from_form(request.form)
        form_data.validate()
        
        service.report(g.user_id, form_data)
        
        flash('Din saknade disc är rapporterad!', 'success')
        return redirect(url_for('missing.community_map'))
    
    return render_template('missing/report.html')


# ============================================================================
# Routes - Mina Discar
# ============================================================================

@bp.route('/my-discs')
@login_required
def my_missing_discs():
    """Se egna saknade discar."""
    service = MissingDiscService(db)
    discs = service.get_user_discs(g.user_id)
    return render_template('missing/my_discs.html', discs=discs)


# ============================================================================
# Routes - Åtgärder på egna discar
# ============================================================================

@bp.route('/found/<int:disc_id>', methods=['POST'])
@login_required
def mark_found(disc_id):
    """Markera disc som hittad - ENDAST om man är ägaren."""
    service = MissingDiscService(db)
    
    if not service.mark_found(disc_id, g.user_id):
        flash('Du kan endast markera dina egna discar som hittade.', 'error')
        return redirect(url_for('missing.community_map'))
    
    flash('Grattis att du hittade din disc!', 'success')
    return redirect(url_for('missing.community_map'))


@bp.route('/delete/<int:disc_id>', methods=['POST'])
@login_required
def delete(disc_id):
    """Ta bort egen rapport."""
    service = MissingDiscService(db)
    
    if service.delete_report(disc_id, g.user_id):
        flash('Rapport borttagen.', 'success')
    else:
        flash('Kunde inte ta bort rapporten.', 'error')
    
    return redirect(url_for('missing.my_missing_discs'))


# ============================================================================
# Routes - Redirect till Hittad-flödet
# ============================================================================

@bp.route('/found-via-map/<int:disc_id>')
@login_required
def found_via_map(disc_id):
    """
    Redirect till rätt hittad-disc-flöde baserat på QR-kod.
    
    När någon hittar en disc via community-kartan, redirecta till
    found-Blueprintets flöde med ägarens QR-kod.
    """
    service = MissingDiscService(db)
    disc = service.get_disc_for_redirect(disc_id, g.user_id)
    
    if not disc:
        flash('Disc hittades inte.', 'error')
        return redirect(url_for('missing.community_map'))
    
    if not disc.get('owner_qr_id'):
        flash('Ägaren har ingen aktiv QR-kod.', 'error')
        return redirect(url_for('missing.community_map'))
    
    # Hämta önskad action från query param
    action = request.args.get('action', 'hide')
    qr_id = disc['owner_qr_id']
    
    # Redirect till rätt endpoint i found.py
    action_routes = {
        'hide': 'found.found_hide',
        'note': 'found.found_note',
        'meet': 'found.found_meet'
    }
    
    route = action_routes.get(action, 'found.found_qr')
    return redirect(url_for(route, qr_id=qr_id))


# ============================================================================
# Routes - Bekräfta Matchning
# ============================================================================

@bp.route('/confirm-found')
@login_required
def confirm_found():
    """
    Bekräfta att hittad disc matchar saknad rapport.
    
    Används när ägaren får mail om hittad disc och klickar på
    bekräftelse-länken.
    """
    disc_id = request.args.get('disc_id')
    confirm = request.args.get('confirm')
    
    if confirm == 'yes' and disc_id:
        try:
            disc_id_int = int(disc_id)
            
            # Verifiera ägarskap
            service = MissingDiscService(db)
            user_discs = service.get_user_discs(g.user_id)
            disc_ids = [d['id'] for d in user_discs]
            
            if disc_id_int not in disc_ids:
                flash('Du kan endast bekräfta dina egna discar.', 'error')
                return redirect(url_for('missing.my_missing_discs'))
            
            db.mark_disc_found(disc_id_int)
            flash('Bra jobbat! Din disc är markerad som hittad.', 'success')
            
        except ValueError:
            flash('Ogiltig disc ID.', 'error')
    
    elif confirm == 'no' or confirm == 'none':
        flash('Noterat. Din saknade disc finns kvar på kartan.', 'info')
    
    return redirect(url_for('missing.my_missing_discs'))


# ============================================================================
# API Endpoints (för framtida AJAX)
# ============================================================================

@bp.route('/api/discs')
@login_required
def api_get_discs():
    """API-endpoint för att hämta discar som JSON."""
    status = request.args.get('status', 'missing')
    service = MissingDiscService(db)
    discs = service.get_community_map_data(status)
    return jsonify({'discs': discs})


@bp.route('/api/my-stats')
@login_required
def api_get_my_stats():
    """API-endpoint för användarens statistik."""
    stats = db.get_user_missing_stats(g.user_id)
    return jsonify(stats)