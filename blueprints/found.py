"""Flöde för när någon hittar en disc."""
import logging
<<<<<<< HEAD
from flask import Blueprint, render_template, request, flash, session, redirect, url_for
=======
from flask import Blueprint, render_template, request, flash, session
>>>>>>> 9429973fcd56ea78bdf3b3958182bb9ff21391be

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
<<<<<<< HEAD
    """Rapportera gömd disc med smart matchning."""
=======
    """Rapportera gömd disc."""
>>>>>>> 9429973fcd56ea78bdf3b3958182bb9ff21391be
    qr = db.get_qr(qr_id)
    
    if not qr or not qr['is_active']:
        return render_template('found/not_active.html', qr_id=qr_id), 404
    
    owner = db.get_user_by_id(qr['user_id'])
    
    if request.method == 'POST':
        note = sanitize_input(request.form.get('note', ''))
        latitude = request.form.get('latitude')
        longitude = request.form.get('longitude')
        
<<<<<<< HEAD
        photo = request.files.get('photo')
        photo_path = save_uploaded_photo(photo, qr_id)
        
        # Spara handover
=======
        # Hantera foto
        photo = request.files.get('photo')
        photo_path = save_uploaded_photo(photo, qr_id)
        
        # Spara i databas
>>>>>>> 9429973fcd56ea78bdf3b3958182bb9ff21391be
        db.create_handover(
            qr_id=qr_id,
            action='gömde',
            note=note,
            photo_path=photo_path,
            latitude=float(latitude) if latitude else None,
            longitude=float(longitude) if longitude else None
        )
        
<<<<<<< HEAD
        # Smart matchning
        match = None
        if latitude and longitude:
            match = db.find_matching_missing_disc(
                owner['id'],
                float(latitude),
                float(longitude)
            )
        
        # Skicka smart mail
        send_smart_found_email(owner, match, note, photo_path, latitude, longitude)
        
        return render_template('found/thanks.html', action='gömma')
=======
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
>>>>>>> 9429973fcd56ea78bdf3b3958182bb9ff21391be
    
    return render_template('found/hide.html', qr_id=qr_id)


<<<<<<< HEAD
def send_smart_found_email(owner, match, note, photo_path, lat, lng):
    """Skicka mail med smart gissning eller val."""
    base_url = Config.PUBLIC_URL
    
    # Bygg bild-HTML
    image_html = ''
    if photo_path:
        photo_clean = photo_path.lstrip('/')
        image_url = f"{base_url}/{photo_clean}"
        image_html = f'<p><img src="{image_url}" style="max-width:100%;border-radius:8px;margin:10px 0;"></p>'
    
    # Bygg karta-länk
    maps_link = ''
    if lat and lng:
        maps_link = f'<p><a href="https://maps.google.com/?q={lat},{lng}" style="padding:12px 24px;background:#10b981;color:white;text-decoration:none;border-radius:8px;display:inline-block;">📍 Visa plats i Google Maps</a></p>'
    
    # Bygg matchnings-HTML
    match_html = ''
    confirm_url = f"{base_url}/missing/confirm-found"
    
    if match and not match.get('multiple'):
        confidence_text = "vi är ganska säkra på" if match['confidence'] == 'high' else "vi tror det kan vara"
        distance_text = f" (ca {match['distance']:.1f} km från där du rapporterade den saknad)" if match.get('distance') else ""
        
        match_html = f'''
        <div style="background:#d1fae5;padding:20px;border-radius:12px;margin:20px 0;">
            <h3>🎯 {confidence_text.title()} att det är din disc:</h3>
            <p style="font-size:1.3rem;font-weight:bold;color:#065f46;">{match['disc_name']}</p>
            <p>Rapporterad saknad: {match['course_name'] or 'Okänd bana'}{distance_text}</p>
            <div style="margin-top:15px;">
                <a href="{confirm_url}?disc_id={match['id']}&confirm=yes" 
                   style="padding:12px 24px;background:#10b981;color:white;text-decoration:none;border-radius:8px;display:inline-block;margin-right:10px;">
                   ✅ Ja, det är min {match['disc_name']}!
                </a>
                <a href="{confirm_url}?disc_id={match['id']}&confirm=no" 
                   style="padding:12px 24px;background:#e5e7eb;color:#374151;text-decoration:none;border-radius:8px;display:inline-block;">
                   ❌ Nej, det är en annan
                </a>
            </div>
        </div>
        '''
    elif match and match.get('multiple'):
        options = ''.join([
            f'<a href="{confirm_url}?disc_id={m["id"]}&confirm=yes" '
            f'style="padding:15px;margin:5px;background:#f3f4f6;border-radius:8px;text-decoration:none;color:#374151;display:block;">'
            f'<strong>{m["disc_name"]}</strong> - {m["course_name"] or "Okänd bana"} '
            f'(ca {m["distance"]:.1f} km bort)</a>'
            for m in match['matches'][:3]
        ])
        
        match_html = f'''
        <div style="background:#fef3c7;padding:20px;border-radius:12px;margin:20px 0;">
            <h3>🤔 Vilken av dina discar blev hittad?</h3>
            <p>Du har flera saknade discar i närheten. Välj vilken som hittades:</p>
            {options}
            <a href="{confirm_url}?confirm=none" 
               style="padding:12px;margin-top:10px;background:#fee2e2;border-radius:8px;text-decoration:none;color:#991b1b;display:block;text-align:center;">
               Ingen av dessa - det är en annan disc
            </a>
        </div>
        '''
    else:
        all_missing = db.get_user_missing_discs(owner['id'])
        if all_missing:
            list_html = ''.join([
                f'<li>{d["disc_name"]} - {d["course_name"] or "Okänd bana"}</li>'
                for d in all_missing[:5]
            ])
            match_html = f'''
            <div style="background:#f3f4f6;padding:20px;border-radius:12px;margin:20px 0;">
                <h3>📋 Dina saknade discar:</h3>
                <ul>{list_html}</ul>
                <p><a href="{base_url}/missing/my-discs" style="color:#2563eb;">Hantera dina saknade discar →</a></p>
            </div>
            '''
    
    html_content = f'''
    <h2>🎉 Din disc har hittats!</h2>
    <p>Någon har hittat och gömt en disc med din QR-kod.</p>
    
    {match_html}
    
    <h3>📍 Information från upphittaren:</h3>
    <p><strong>Meddelande:</strong> {note or 'Inget meddelande'}</p>
    {maps_link}
    {image_html}
    
    <hr style="margin:30px 0;border:none;border-top:1px solid #e5e7eb;">
    <p style="color:#6b7280;font-size:0.9rem;">
        Om du inte längre vill ha denna disc markerad som saknad, 
        <a href="{base_url}/missing/my-discs">klicka här för att hantera dina rapporter</a>.
    </p>
    '''
    
    send_email_async(
        owner['email'],
        f"🎉 Din disc har hittats! - ReturnaDisc",
        html_content
    )


=======
>>>>>>> 9429973fcd56ea78bdf3b3958182bb9ff21391be
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
<<<<<<< HEAD
    """Begär möte."""
=======
    """Begär möte - avråds."""
>>>>>>> 9429973fcd56ea78bdf3b3958182bb9ff21391be
    qr = db.get_qr(qr_id)
    
    if not qr or not qr['is_active']:
        return render_template('found/not_active.html', qr_id=qr_id), 404
    
<<<<<<< HEAD
    owner = db.get_user_by_id(qr['user_id'])
    
    if request.method == 'POST':
        note = sanitize_input(request.form.get('note', ''))
        finder_email = request.form.get('finder_email', '').strip()
        finder_phone = request.form.get('finder_phone', '').strip()
        
        if not finder_email and not finder_phone:
            flash('Ange antingen email eller telefonnummer.', 'error')
            return redirect(url_for('found.found_meet', qr_id=qr_id))
        
        db.create_handover(
            qr_id=qr_id,
            action='möte',
            note=f"Kontakt: {finder_email or 'N/A'} / {finder_phone or 'N/A'}. Meddelande: {note}"
        )
        
        contact_info = []
        if finder_email:
            contact_info.append(f"Email: {finder_email}")
        if finder_phone:
            contact_info.append(f"Telefon: {finder_phone}")
        
        send_email_async(
            owner['email'],
            f"🤝 Mötesförfrågan för din disc",
            f"""
            <h2>Någon vill mötas för att återlämna din disc</h2>
            <p><strong>Kontaktuppgifter:</strong></p>
            <p>{'<br>'.join(contact_info)}</p>
            <p><strong>Meddelande:</strong> {note or 'Inget meddelande'}</p>
            <p>Tips: Svara snabbt för att underlätta återlämningen!</p>
            """
        )
        
        return render_template('found/thanks.html', action='mötesförfrågan')
    
=======
>>>>>>> 9429973fcd56ea78bdf3b3958182bb9ff21391be
    return render_template('found/meet_info.html', qr_id=qr_id)