"""Flöde för när någon hittar en disc."""
import logging
from flask import Blueprint, render_template, request, flash, session

from database import db
from utils import send_email_async, save_uploaded_photo, sanitize_input
from config import Config

logger = logging.getLogger(__name__)

bp = Blueprint('found', __name__, url_prefix='')


@bp.route('/found/<qr_id>', methods=['GET'])
def found_qr(qr_id):
    """Huvudsida för 'hittad disc'."""
    qr = db.get_qr(qr_id)
    
    if not qr:
        return render_template('found/not_found.html'), 404
    
    if not qr['is_active']:
        return render_template('found/not_active.html', qr_id=qr_id)
    
    db.increment_qr_scans(qr_id)
    owner = db.get_user_by_id(qr['user_id'])
    
    return render_template('found/found.html', qr_id=qr_id, owner=owner)


@bp.route('/found/<qr_id>/hide', methods=['GET', 'POST'])
def found_hide(qr_id):
    """Rapportera gömd disc."""
    qr = db.get_qr(qr_id)
    
    if not qr or not qr['is_active']:
        return render_template('found/not_active.html', qr_id=qr_id), 404
    
    owner = db.get_user_by_id(qr['user_id'])
    
    if request.method == 'POST':
        note = sanitize_input(request.form.get('note', ''))
        latitude = request.form.get('latitude')
        longitude = request.form.get('longitude')
        
        # Hantera foto
        photo = request.files.get('photo')
        photo_path = save_uploaded_photo(photo, qr_id)
        
        # Spara i databas
        db.create_handover(
            qr_id=qr_id,
            action='gömde',
            note=note,
            photo_path=photo_path,
            latitude=float(latitude) if latitude else None,
            longitude=float(longitude) if longitude else None
        )
        
        # Bygg mail
        base_url = Config.PUBLIC_URL
        
        # Bild
        image_html = ''
        if photo_path:
            photo_clean = photo_path.lstrip('/')
            image_url = f"{base_url}/{photo_clean}"
            
            image_html = f'''
            <p>📷 Bild från upphittaren:</p>
            <p><a href="{image_url}">Öppna bilden</a></p>
            <p><img src="{image_url}" style="max-width:100%;border-radius:8px;"></p>
            '''
        
        # Karta
        maps_link = ''
        if latitude and longitude:
            maps_link = f'<p><a href="https://maps.google.com/?q={latitude},{longitude}" style="padding:12px 24px;background:#10b981;color:white;text-decoration:none;border-radius:8px;">📍 Visa plats i Google Maps</a></p>'
        
        # Skicka mail
        send_email_async(
            to_email=owner['email'],
            subject=f"🎉 Din disc är hittad!",
            html_content=f'''
            <h2>Goda nyheter!</h2>
            <p>Någon har hittat din disc och gömt den på en säker plats.</p>
            <p><strong>Meddelande:</strong> {note or 'Inget meddelande'}</p>
            {maps_link}
            {image_html}
            '''
        )
        
        # Erbjud hero point om inte inloggad
        show_hero_offer = not session.get('user_id')
        
        return render_template('found/thanks.html', 
                             action='gömma', 
                             show_hero_offer=show_hero_offer)
    
    return render_template('found/hide.html', qr_id=qr_id)


@bp.route('/found/<qr_id>/note', methods=['GET', 'POST'])
def found_note(qr_id):
    """Lämna meddelande."""
    qr = db.get_qr(qr_id)
    
    if not qr or not qr['is_active']:
        return render_template('found/not_active.html', qr_id=qr_id), 404
    
    owner = db.get_user_by_id(qr['user_id'])
    
    if request.method == 'POST':
        note = sanitize_input(request.form.get('note', ''))
        
        if not note:
            flash('Skriv ett meddelande.', 'error')
            return redirect(url_for('found.found_note', qr_id=qr_id))
        
        db.create_handover(qr_id, 'meddelande', note)
        
        send_email_async(
            owner['email'],
            f"💬 Meddelande om din disc",
            f'<h2>Nytt meddelande</h2><p>{note}</p>'
        )
        
        return render_template('found/thanks.html', action='meddelande')
    
    return render_template('found/note.html', qr_id=qr_id)


@bp.route('/found/<qr_id>/meet', methods=['GET', 'POST'])
def found_meet(qr_id):
    """Begär möte - avråds."""
    qr = db.get_qr(qr_id)
    
    if not qr or not qr['is_active']:
        return render_template('found/not_active.html', qr_id=qr_id), 404
    
    return render_template('found/meet_info.html', qr_id=qr_id)