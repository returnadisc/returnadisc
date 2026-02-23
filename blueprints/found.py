"""Flöde för när någon hittar en disc."""
import logging
import re
import os
from dataclasses import dataclass
from typing import Optional, List, Dict, Callable
from functools import wraps

from flask import (
    Blueprint, render_template, request, flash, 
    session, redirect, url_for, g, jsonify
)

from database import db
from utils import send_email_async, save_uploaded_photo, sanitize_input, send_email_with_attachment
from config import Config

logger = logging.getLogger(__name__)

bp = Blueprint('found', __name__, url_prefix='/found')


# ============================================================================
# Dataclasses
# ============================================================================

@dataclass
class FinderContact:
    """Kontaktuppgifter från upphittare."""
    email: Optional[str] = None
    phone: Optional[str] = None
    
    def validate(self) -> None:
        """Validera att minst en kontaktmetod finns."""
        if not self.email and not self.phone:
            raise ValueError("Ange antingen email eller telefonnummer.")
        
        if self.email and not self._is_valid_email(self.email):
            raise ValueError("Ogiltig email-adress.")
        
        if self.phone and not self._is_valid_phone(self.phone):
            raise ValueError("Ogiltigt telefonnummer. Ange minst 8 siffror.")
    
    @staticmethod
    def _is_valid_email(email: str) -> bool:
        pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        return bool(re.match(pattern, email))
    
    @staticmethod
    def _is_valid_phone(phone: str) -> bool:
        cleaned = re.sub(r'[\s\-\+\(\)]', '', phone)
        return cleaned.isdigit() and len(cleaned) >= 8


@dataclass
class LocationData:
    """Platsdata för hittad disc."""
    latitude: Optional[float] = None
    longitude: Optional[float] = None
    
    def is_valid(self) -> bool:
        """Kontrollera att koordinater är giltiga."""
        if self.latitude is None or self.longitude is None:
            return False
        return (-90 <= self.latitude <= 90) and (-180 <= self.longitude <= 180)
    
    def to_maps_link(self) -> Optional[str]:
        """Generera Google Maps-länk."""
        if not self.is_valid():
            return None
        return f"https://maps.google.com/?q={self.latitude},{self.longitude}"


@dataclass
class HandoverData:
    """Data för en handover/återlämning."""
    qr_id: str
    action: str
    note: Optional[str] = None
    finder_name: Optional[str] = None
    finder_user_id: Optional[int] = None
    photo_path: Optional[str] = None
    location: Optional[LocationData] = None


# ============================================================================
# Services
# ============================================================================

class LocationService:
    """Hantering av platsdata och validering."""
    
    @classmethod
    def parse_from_form(cls, form: Dict) -> LocationData:
        """Parsa platsdata från formulär."""
        lat = form.get('latitude')
        lng = form.get('longitude')
        
        location = LocationData()
        
        if lat and lng:
            try:
                location.latitude = float(lat)
                location.longitude = float(lng)
            except ValueError:
                pass
        
        return location
    
    @classmethod
    def validate_or_warn(cls, location: LocationData) -> tuple:
        """
        Validera koordinater och returnera (is_valid, should_warn).
        
        Returns:
            Tuple av (giltiga_koordinater, ska_varna_användaren)
        """
        if location.latitude is None and location.longitude is None:
            # Ingen plats angiven - OK men ingen plats sparas
            return None, False
        
        if location.is_valid():
            return location, False
        
        # Koordinater angivna men ogiltiga
        return None, True


class MatchingService:
    """Smart matchning av hittade discar mot saknade rapporter."""
    
    def __init__(self, database):
        self.db = database
    
    def find_match(
        self, 
        owner_id: int, 
        location: LocationData
    ) -> Optional[Dict]:
        """
        Hitta matchande saknad disc baserat på position.
        
        Returns:
            Dict med matchningsdata eller None
        """
        if not location.is_valid():
            return None
        
        match = self.db.find_matching_missing_disc(
            owner_id,
            location.latitude,
            location.longitude
        )
        
        if not match:
            return None
        
        # Formattera för template/email
        result = {
            'disc': match,
            'confidence': match.get('confidence', 'low'),
            'distance': match.get('distance', 0),
            'is_multiple': match.get('multiple', False)
        }
        
        if result['is_multiple']:
            result['options'] = match.get('matches', [])
        
        return result


class EmailTemplateService:
    """Generering av email-templates."""
    
    @classmethod
    def render_found_disc_email(
        cls,
        owner_name: str,
        match_data: Optional[Dict],
        note: Optional[str],
        photo_path: Optional[str],
        location: LocationData,
        base_url: str
    ) -> str:
        """Rendera HTML-email för 'disc hittad'."""
        sections = []
        
        # Header
        sections.append(f"<h2>🎉 Hej {owner_name}!</h2>")
        sections.append("<p>Någon har hittat och gömt en disc med din QR-kod.</p>")
        
        # Matchningssektion
        if match_data:
            sections.append(cls._render_match_section(match_data, base_url))
        
        # Information från upphittare
        sections.append(cls._render_finder_info(note, location, photo_path, base_url))
        
        # Footer
        sections.append(cls._render_footer(base_url))
        
        return ''.join(sections)  # Använd '' istället för '\n'
    
    @classmethod
    def _render_match_section(cls, match: Dict, base_url: str) -> str:
        """Rendera matchnings-information."""
        if match.get('is_multiple'):
            return cls._render_multiple_matches(match, base_url)
        return cls._render_single_match(match, base_url)
    
    
    @classmethod
    def _render_single_match(cls, match: Dict, base_url: str) -> str:
        """Rendera enskild match."""
        disc = match['disc']
        confidence = match['confidence']
        distance = match['distance']
        
        confidence_text = (
            "vi är ganska säkra på" if confidence == 'high' 
            else "vi tror det kan vara"
        )
        distance_text = (
            f" (ca {distance:.1f} km från där du rapporterade den saknad)" 
            if distance > 0 else ""
        )
        
        confirm_url = f"{base_url}/missing/confirm-found?disc_id={disc['id']}&confirm=yes"
        deny_url = f"{base_url}/missing/confirm-found?disc_id={disc['id']}&confirm=no"
        
        return f'''
        <div style="background:#d1fae5;padding:20px;border-radius:12px;margin:20px 0;">
            <h3>🎯 {confidence_text.title()} att det är din disc:</h3>
            <p style="font-size:1.3rem;font-weight:bold;color:#065f46;">{disc['disc_name']}</p>
            <p>Rapporterad saknad: {disc.get('course_name', 'Okänd bana')}{distance_text}</p>
            <div style="margin-top:15px;">
                <a href="{confirm_url}" 
                   style="padding:12px 24px;background:#10b981;color:white;text-decoration:none;border-radius:8px;display:inline-block;margin-right:10px;">
                   ✅ Ja, det är min {disc['disc_name']}!
                </a>
                <a href="{deny_url}" 
                   style="padding:12px 24px;background:#e5e7eb;color:#374151;text-decoration:none;border-radius:8px;display:inline-block;">
                   ❌ Nej, det är en annan
                </a>
            </div>
        </div>
        '''
    
    @classmethod
    def _render_multiple_matches(cls, match: Dict, base_url: str) -> str:
        """Rendera flera matchningar."""
        options = match.get('options', [])
        
        options_html = ''.join([
            f'<a href="{base_url}/missing/confirm-found?disc_id={opt["id"]}&confirm=yes" '
            f'style="padding:15px;margin:5px;background:#f3f4f6;border-radius:8px;text-decoration:none;color:#374151;display:block;">'
            f'<strong>{opt["disc_name"]}</strong> - {opt.get("course_name", "Okänd bana")} '
            f'(ca {opt.get("distance", 0):.1f} km bort)</a>'
            for opt in options[:3]
        ])
        
        return f'''
        <div style="background:#fef3c7;padding:20px;border-radius:12px;margin:20px 0;">
            <h3>🤔 Vilken av dina discar blev hittad?</h3>
            <p>Du har flera saknade discar i närheten. Välj vilken som hittades:</p>
            {options_html}
            <a href="{base_url}/missing/confirm-found?confirm=none" 
               style="padding:12px;margin-top:10px;background:#fee2e2;border-radius:8px;text-decoration:none;color:#991b1b;display:block;text-align:center;">
               Ingen av dessa - det är en annan disc
            </a>
        </div>
        '''
    
    @classmethod
    def _render_finder_info(
        cls,
        note: Optional[str],
        location: LocationData,
        photo_path: Optional[str],
        base_url: str
    ) -> str:
        """Rendera information från upphittare."""
        sections = ["<h3>Information från upphittaren:</h3>"]
        
        # Meddelande
        sections.append(f"<p><strong>Meddelande:</strong> {note or 'Inget meddelande'}</p>")
        
        # Bild först om den finns
        if photo_path:
            sections.append(
                f'<div style="margin: 20px 0;">'
                f'<img src="cid:found_photo" style="max-width: 100%; max-height: 400px; border-radius: 8px; display: block;">'
                f'</div>'
            )
        
        # Google Maps-länk
        maps_link = location.to_maps_link()
        if maps_link:
            sections.append(
                f'<div style="margin: 20px 0;">'
                f'<a href="{maps_link}" style="padding: 12px 24px; background: #166534; color: white; text-decoration: none; border-radius: 8px; display: inline-block;">'
                f'Visa plats i Google Maps'
                f'</a>'
                f'</div>'
            )
        
        return ''.join(sections)  # Använd '' istället för '\n' för att undvika radbrytningar
    
    @classmethod
    def _render_footer(cls, base_url: str) -> str:
        """Rendera email-footer."""
        return f'''
        <hr style="margin:30px 0;border:none;border-top:1px solid #e5e7eb;">
        <p style="color:#6b7280;font-size:0.9rem;">
            Om du inte längre vill ha denna disc markerad som saknad, 
            <a href="{base_url}/missing/my-discs">klicka här för att hantera dina rapporter</a>.
        </p>
        '''


class NotificationService:
    """Hantering av notifikationer till ägare."""
    
    def __init__(self, template_service: EmailTemplateService):
        self.templates = template_service
    
    def send_found_notification(
        self,
        owner: Dict,
        match_data: Optional[Dict],
        handover_data: HandoverData
    ) -> None:
        """Skicka notifikation om hittad disc med bifogad bild."""
        if not owner or not owner.get('email'):
            logger.error(f"Cannot send email: owner or email missing")
            return
        
        # Bygg HTML
        html_content = self.templates.render_found_disc_email(
            owner_name=owner.get('name', 'Discgolfare'),
            match_data=match_data,
            note=handover_data.note,
            photo_path=handover_data.photo_path,
            location=handover_data.location or LocationData(),
            base_url=Config.PUBLIC_URL
        )
        
        # Förberedd bildhantering
        attachment_path = None
        attachment_cid = None
        
        if handover_data.photo_path:
            # Bygg full sökväg till bilden
            attachment_path = os.path.join(
                os.path.dirname(os.path.dirname(__file__)), 
                'static', 
                handover_data.photo_path
            )
            attachment_cid = 'found_photo'
            
            # Uppdatera HTML för att använda CID
            html_content = html_content.replace(
                f'/static/{handover_data.photo_path}',
                'cid:found_photo'
            )
        
        send_email_with_attachment(
            owner['email'],
            "🎉 Din disc har hittats! - ReturnaDisc",
            html_content,
            attachment_path=attachment_path,
            attachment_cid=attachment_cid
        )
    
    def send_simple_notification(
        self,
        owner: Dict,
        subject: str,
        body: str
    ) -> None:
        """Skicka enkel notifikation."""
        if not owner or not owner.get('email'):
            logger.error(f"Cannot send email: owner missing")
            return
        
        send_email_async(owner['email'], subject, f"<h2>{subject}</h2><p>{body}</p>")


class FoundDiscService:
    """Huvudservice för 'hittad disc'-flödet."""
    
    def __init__(self, database):
        self.db = database
        self.matcher = MatchingService(database)
        self.notifier = NotificationService(EmailTemplateService())
    
    def process_found_disc(self, qr_id: str) -> Dict:
        """
        Hantera när någon skannar en QR-kod.
        
        Returns:
            Dict med qr, owner, etc.
        """
        qr = self.db.get_qr(qr_id)
        
        if not qr:
            return {'status': 'not_found'}
        
        if not qr.get('is_active'):
            return {'status': 'not_active', 'qr_id': qr_id}
        
        # Öka räknare
        self.db.increment_qr_scans(qr_id)
        
        owner = self.db.get_user_by_id(qr.get('user_id')) if qr.get('user_id') else None
        
        return {
            'status': 'active',
            'qr': qr,
            'owner': owner,
            'qr_id': qr_id
        }
    
    def process_hide_disc(
        self,
        qr_id: str,
        form_data: Dict,
        photo_file: Optional
    ) -> HandoverData:
        """
        Hantera 'göm disc'-flödet.
        
        Returns:
            HandoverData med all information
        """
        # Validera och parsa plats
        location, should_warn = LocationService.validate_or_warn(
            LocationService.parse_from_form(form_data)
        )
        
        if should_warn:
            flash('Koordinaterna var ogiltiga och ignoreras. Platsen sparas inte.', 'warning')
        
        # Spara foto
        photo_path = save_uploaded_photo(photo_file)
        
        # Skapa handover
        handover = HandoverData(
            qr_id=qr_id,
            action='gömde',
            note=sanitize_input(form_data.get('note', '')),
            photo_path=photo_path,
            location=location
        )
        
        # Spara i databas
        self.db.create_handover(
            qr_id=handover.qr_id,
            action=handover.action,
            note=handover.note,
            photo_path=handover.photo_path,
            latitude=handover.location.latitude if handover.location else None,
            longitude=handover.location.longitude if handover.location else None
        )
        
        return handover
    
    def notify_owner(
        self,
        qr_id: str,
        handover_data: HandoverData
    ) -> None:
        """
        Skicka notifikation till ägare med smart matchning.
        """
        qr = self.db.get_qr(qr_id)
        if not qr:
            return
        
        owner = self.db.get_user_by_id(qr.get('user_id')) if qr.get('user_id') else None
        if not owner:
            logger.error(f"Owner missing for QR {qr_id}")
            return
        
        # Smart matchning om vi har platsdata
        match_data = None
        if handover_data.location and handover_data.location.is_valid():
            match_data = self.matcher.find_match(owner['id'], handover_data.location)
        
        # Skicka notifikation
        self.notifier.send_found_notification(owner, match_data, handover_data)
    
    def process_note(self, qr_id: str, note: str) -> None:
        """Hantera 'lämna meddelande'-flödet."""
        if not note:
            raise ValueError("Skriv ett meddelande.")
        
        sanitized = sanitize_input(note)
        
        # Spara handover
        self.db.create_handover(qr_id, 'meddelande', sanitized)
        
        # Notifiera ägare
        qr = self.db.get_qr(qr_id)
        if qr and qr.get('user_id'):
            owner = self.db.get_user_by_id(qr['user_id'])
            self.notifier.send_simple_notification(
                owner,
                "💬 Meddelande om din disc",
                sanitized
            )
    
    def process_meet_request(
        self,
        qr_id: str,
        form_data: Dict
    ) -> None:
        """Hantera 'begär möte'-flödet."""
        contact = FinderContact(
            email=form_data.get('finder_email', '').strip() or None,
            phone=form_data.get('finder_phone', '').strip() or None
        )
        contact.validate()
        
        note = sanitize_input(form_data.get('note', ''))
        
        # Formatera kontaktinfo
        contact_parts = []
        if contact.email:
            contact_parts.append(f"Email: {contact.email}")
        if contact.phone:
            contact_parts.append(f"Telefon: {contact.phone}")
        
        full_note = f"Kontakt: {' / '.join(contact_parts)}. Meddelande: {note}"
        
        # Spara handover
        self.db.create_handover(qr_id, 'möte', full_note)
        
        # Notifiera ägare
        qr = self.db.get_qr(qr_id)
        if qr and qr.get('user_id'):
            owner = self.db.get_user_by_id(qr['user_id'])
            
            html_content = f"""
            <h2>Någon vill mötas för att återlämna din disc</h2>
            <p><strong>Kontaktuppgifter:</strong></p>
            <p>{'<br>'.join(contact_parts)}</p>
            <p><strong>Meddelande:</strong> {note or 'Inget meddelande'}</p>
            <p>Tips: Svara snabbt för att underlätta återlämningen!</p>
            """
            
            send_email_async(owner['email'], "🤝 Mötesförfrågan för din disc", html_content)


class RateLimitService:
    """Hantering av rate limiting för manuella sökningar."""
    
    MAX_ATTEMPTS = 10
    SESSION_KEY_PREFIX = 'qr_lookup_attempts_'
    
    @classmethod
    def check_limit(cls, ip_address: str) -> bool:
        """Kontrollera om IP har överskridit gränsen."""
        key = f"{cls.SESSION_KEY_PREFIX}{ip_address}"
        attempts = session.get(key, 0)
        return attempts < cls.MAX_ATTEMPTS
    
    @classmethod
    def increment(cls, ip_address: str) -> None:
        """Öka räknaren för IP."""
        key = f"{cls.SESSION_KEY_PREFIX}{ip_address}"
        session[key] = session.get(key, 0) + 1


# ============================================================================
# Decorators
# ============================================================================

def require_valid_qr(f: Callable) -> Callable:
    """Decorator som validerar QR-kod och skickar till rätt sida om ogiltig."""
    @wraps(f)
    def decorated_function(qr_id, *args, **kwargs):
        service = FoundDiscService(db)
        result = service.process_found_disc(qr_id)
        
        if result['status'] == 'not_found':
            return render_template('found/not_found.html'), 404
        
        if result['status'] == 'not_active':
            flash(f'QR-koden {qr_id} är inte aktiverad. Skapa ett konto för att aktivera den.', 'info')
            return redirect(url_for('auth.signup_with_purchased_qr', qr_id=qr_id))
        
        # Lägg till qr och owner i kwargs
        kwargs['qr_data'] = result
        return f(qr_id, *args, **kwargs)
    
    return decorated_function


def handle_form_errors(f: Callable) -> Callable:
    """Decorator som fångar formulärfel och visar flash-meddelanden."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        try:
            return f(*args, **kwargs)
        except ValueError as e:
            flash(str(e), 'error')
            return redirect(request.url)
        except Exception as e:
            logger.error(f"Oväntat fel: {e}")
            flash('Ett fel uppstod. Försök igen.', 'error')
            return redirect(request.url)
    
    return decorated_function


# ============================================================================
# Routes
# ============================================================================

@bp.route('/<qr_id>', methods=['GET'])
def found_qr(qr_id):
    """Huvudsida för 'hittad disc'."""
    service = FoundDiscService(db)
    result = service.process_found_disc(qr_id)
    
    if result['status'] == 'not_found':
        return render_template('found/not_found.html'), 404
    
    if result['status'] == 'not_active':
        flash(f'QR-koden {qr_id} är inte aktiverad. Skapa ett konto för att aktivera den.', 'info')
        return redirect(url_for('auth.signup_with_purchased_qr', qr_id=qr_id))
    
    return render_template(
        'found/found.html',
        qr_id=qr_id,
        owner=result['owner']
    )


@bp.route('/<qr_id>/hide', methods=['GET', 'POST'])
@require_valid_qr
def found_hide(qr_id, qr_data=None):
    """Rapportera gömd disc med smart matchning."""
    if request.method == 'POST':
        return _handle_hide_post(qr_id)
    
    return render_template('found/hide.html', qr_id=qr_id)


@handle_form_errors
def _handle_hide_post(qr_id: str):
    """Hantera POST för hide-formuläret."""
    service = FoundDiscService(db)
    
    # Processa formulär
    handover = service.process_hide_disc(
        qr_id,
        request.form,
        request.files.get('photo')
    )
    
    # Notifiera ägare (asynkront)
    service.notify_owner(qr_id, handover)
    
    return render_template('found/thanks_hide.html')


@bp.route('/<qr_id>/note', methods=['GET', 'POST'])
@require_valid_qr
def found_note(qr_id, qr_data=None):
    """Lämna meddelande."""
    if request.method == 'POST':
        return _handle_note_post(qr_id)
    
    return render_template('found/note.html', qr_id=qr_id)


@handle_form_errors
def _handle_note_post(qr_id: str):
    """Hantera POST för note-formuläret."""
    service = FoundDiscService(db)
    
    note = request.form.get('note', '').strip()
    service.process_note(qr_id, note)
    
    return render_template('found/thanks_note.html')


@bp.route('/<qr_id>/meet', methods=['GET', 'POST'])
@require_valid_qr
def found_meet(qr_id, qr_data=None):
    """Begär möte."""
    if request.method == 'POST':
        return _handle_meet_post(qr_id)
    
    return render_template('found/meet_info.html', qr_id=qr_id)


@handle_form_errors
def _handle_meet_post(qr_id: str):
    """Hantera POST för meet-formuläret."""
    service = FoundDiscService(db)
    
    service.process_meet_request(qr_id, request.form)
    
    return render_template('found/thanks_meet.html')


@bp.route('/manual', methods=['GET', 'POST'])
def found_manual():
    """Sida för att manuellt skriva in QR-kod."""
    if request.method == 'POST':
        return _handle_manual_post()
    
    return render_template('found/found_manual.html')


def _handle_manual_post():
    """Hantera manuell inmatning av QR-kod."""
    qr_id = request.form.get('qr_id', '').strip().upper()
    
    if not qr_id:
        flash('Skriv in en kod.', 'error')
        return redirect(url_for('found.found_manual'))
    
    # Validera format
    if not re.match(r'^[A-Z0-9]{4,10}$', qr_id):
        flash('Ogiltigt format på koden.', 'error')
        return redirect(url_for('found.found_manual'))
    
    # Rate limiting
    ip = request.remote_addr
    if not RateLimitService.check_limit(ip):
        flash('För många försök. Försök igen senare.', 'error')
        return redirect(url_for('found.found_manual'))
    
    RateLimitService.increment(ip)
    
    # Kolla om koden finns
    qr = db.get_qr(qr_id)
    if not qr:
        flash(f'Ingen disc hittades med koden "{qr_id}". Kontrollera stavningen.', 'error')
        return redirect(url_for('found.found_manual'))
    
    # Omdirigera till vanliga flödet
    return redirect(url_for('found.found_qr', qr_id=qr_id))


# ============================================================================
# ROUTE FÖR DISC-BASERADE HITTELSER FRÅN KARTAN (NY)
# ============================================================================

@bp.route('/disc/<int:disc_id>', methods=['GET'])
def found_disc_by_id(disc_id):
    """
    Hantera upphittad disc från kartan - baserat på disc ID.
    Hittar ägarens QR-kod automatiskt och omdirigerar till rätt formulär.
    """
    action = request.args.get('action', 'hide')
    
    # Hämta alla saknade discar och hitta rätt
    all_discs = db.get_all_missing_discs(status='missing')
    target_disc = None
    
    for d in all_discs:
        if d.get('id') == disc_id:
            target_disc = d
            break
    
    if not target_disc:
        flash('Discen hittades inte.', 'error')
        return redirect(url_for('missing.community_map'))
    
    # Hämta ägarens första QR-kod
    owner_id = target_disc.get('user_id')
    if not owner_id:
        flash('Kunde inte hitta ägaren.', 'error')
        return redirect(url_for('missing.community_map'))
    
    owner_qr = db.get_user_qr(owner_id)
    
    if not owner_qr:
        flash('Ägaren har ingen aktiv QR-kod.', 'error')
        return redirect(url_for('missing.community_map'))
    
    qr_id = owner_qr.get('qr_id')
    
    # Omdirigera till rätt formulär baserat på action
    if action == 'hide':
        return redirect(url_for('found.found_hide', qr_id=qr_id))
    elif action == 'note':
        return redirect(url_for('found.found_note', qr_id=qr_id))
    elif action == 'meet':
        return redirect(url_for('found.found_meet', qr_id=qr_id))
    else:
        return redirect(url_for('found.found_hide', qr_id=qr_id))