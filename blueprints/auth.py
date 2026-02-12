"""Autentisering."""
import logging
from flask import Blueprint, render_template, request, redirect, url_for, flash, session
from werkzeug.security import generate_password_hash, check_password_hash

from database import db
from utils import send_email_async, generate_qr_pdf_for_order
from config import Config

logger = logging.getLogger(__name__)

bp = Blueprint('auth', __name__, url_prefix='')


@bp.route('/')
def index():
    """Startsida."""
    return render_template('index.html')


@bp.route('/how')
def how_it_works():
    """Så funkar det."""
    return render_template('how.html')


@bp.route('/buy-stickers')
def buy_stickers():
    """Köp stickers-sida."""
    return render_template('buy_stickers.html')


@bp.route('/signup', methods=['GET', 'POST'])
def signup():
    """Skapa konto med automatisk QR-kod."""
    if request.method == 'POST':
        name = request.form.get('name', '').strip()
        email = request.form.get('email', '').strip().lower()
        password = request.form.get('password', '').strip()
        
        if not all([name, email, password]):
            flash('Fyll i alla fält.', 'error')
            return redirect(url_for('auth.signup'))
        
        if len(password) < 6:
            flash('Lösenordet måste vara minst 6 tecken.', 'error')
            return redirect(url_for('auth.signup'))
        
        if db.get_user_by_email(email):
            flash('Det finns redan ett konto med den emailen.', 'error')
            return redirect(url_for('auth.signup'))
        
        try:
            password_hash = generate_password_hash(password)
            user_id, qr_id, qr_filename = db.create_user_with_qr(name, email, password_hash)
            session['user_id'] = user_id
            return redirect(url_for('disc.dashboard'))
            
        except Exception as e:
            logger.error(f"Failed to create user: {e}")
            flash('Ett fel uppstod.', 'error')
            return redirect(url_for('auth.signup'))
    
    return render_template('auth/signup.html')


@bp.route('/login', methods=['GET', 'POST'])
def login():
    """Logga in."""
    if request.method == 'POST':
        email = request.form.get('email', '').strip().lower()
        password = request.form.get('password', '').strip()
        
        user = db.get_user_by_email(email)
        
        if not user or not check_password_hash(user['password'], password):
            flash('Fel email eller lösenord.', 'error')
            return redirect(url_for('auth.login'))
        
        session['user_id'] = user['id']
        session.permanent = True
        
        # Uppdatera senaste inloggning
        db.update_last_login(user['id'])
        
        flash('Välkommen tillbaka!', 'success')
        return redirect(url_for('disc.dashboard'))
    
    return render_template('auth/login.html')


@bp.route('/logout')
def logout():
    """Logga ut."""
    session.clear()
    flash('Du är utloggad.', 'info')
    return redirect(url_for('auth.index'))


@bp.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    """Glömt lösenord."""
    if request.method == 'POST':
        email = request.form.get('email', '').strip().lower()
        
        user = db.get_user_by_email(email)
        if not user:
            flash('Om kontot finns har vi skickat en reset-länk.', 'info')
            return redirect(url_for('auth.login'))
        
        import secrets
        token = secrets.token_urlsafe(32)
        db.set_reset_token(email, token)
        
        reset_link = f"{Config.BASE_URL}/reset-password/{token}"
        send_email_async(
            email,
            'Återställ ditt lösenord - ReturnaDisc',
            f'<p>Klicka <a href="{reset_link}">här</a> för att återställa.</p>'
        )
        
        flash('Reset-länk skickad!', 'success')
        return redirect(url_for('auth.login'))
    
    return render_template('auth/forgot_password.html')


@bp.route('/reset-password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    """Återställ lösenord."""
    user = db.get_user_by_token(token)
    if not user:
        flash('Ogiltig länk.', 'error')
        return redirect(url_for('auth.login'))
    
    if request.method == 'POST':
        password = request.form.get('password', '').strip()
        
        if len(password) < 6:
            flash('Minst 6 tecken.', 'error')
            return redirect(url_for('auth.reset_password', token=token))
        
        password_hash = generate_password_hash(password)
        db.update_password(user['id'], password_hash)
        
        flash('Lösenord uppdaterat!', 'success')
        return redirect(url_for('auth.login'))
    
    return render_template('auth/reset_password.html', token=token)
    
       
    
    
# Lägg till dessa imports överst i auth.py om de inte redan finns:
import secrets
from flask import send_file
import os

# Lägg till dessa routes i auth.py (i Blueprint auth_bp):

@bp.route('/buy-stickers-checkout', methods=['POST'])
def buy_stickers_checkout():
    """Hantera checkout från buy_stickers sidan."""
    package = request.form.get('package')
    count = int(request.form.get('count', 10))
    
    # Spara i session för checkout-flödet
    session['order_package'] = package
    session['order_count'] = count
    session['order_price'] = 59 if package == 'start' else 99 if package == 'standard' else 179
    
    return redirect(url_for('auth.checkout'))

@bp.route('/checkout', methods=['GET', 'POST'])
def checkout():
    """Checkout-sida för beställning."""
    if request.method == 'POST':
        # Hämta formulärdata
        name = request.form.get('name', '').strip()
        email = request.form.get('email', '').strip().lower()
        phone = request.form.get('phone', '').strip()
        address = request.form.get('address', '').strip()
        postal_code = request.form.get('postal_code', '').strip()
        city = request.form.get('city', '').strip()
        package = request.form.get('package')
        count = int(request.form.get('count', 10))
        
        # Validera
        if not all([name, email, address, postal_code, city]):
            flash('Fyll i alla obligatoriska fält.', 'error')
            return redirect(url_for('auth.checkout'))
        
        # Generera QR-koder (men aktivera dem inte än!)
        from utils import generate_random_qr_id, create_qr_code
        
        qr_codes = []
        order_id = secrets.token_hex(8).upper()
        
        for _ in range(count):
            # Generera unik QR-kod
            max_attempts = 10
            for _ in range(max_attempts):
                qr_id = generate_random_qr_id()
                existing = db.get_qr(qr_id)
                if not existing:
                    break
            
            # Skapa QR i databasen (INAKTIVERAD)
            db.create_qr(qr_id)
            
            # Generera QR-bild
            qr_filename = create_qr_code(qr_id, None)  # None = ingen användare än
            
            qr_codes.append({
                'qr_id': qr_id,
                'qr_filename': qr_filename
            })
        
        # Spara order-info i session för bekräftelsesidan
        session['order_id'] = order_id
        session['order_qr_codes'] = [q['qr_id'] for q in qr_codes]
        session['order_email'] = email
        session['order_total'] = 59 if package == 'start' else 99 if package == 'standard' else 179
        
        # Skicka bekräftelsemail
        qr_list_html = ''.join([f'<li>{q["qr_id"]}</li>' for q in qr_codes])
        send_email_async(
            email,
            'Dina ReturnaDisc QR-koder är redo! - ReturnaDisc',
            f'''
            <h2>Tack för din beställning!</h2>
            <p>Ordernummer: <strong>#{order_id}</strong></p>
            <p>Dina QR-koder:</p>
            <ul>{qr_list_html}</ul>
            <p><strong>Viktigt:</strong> Dina QR-koder är ännu inte aktiverade. 
            Besök <a href="{Config.BASE_URL}/signup-with-qr/{order_id}">denna länk</a> 
            för att skapa konto och aktivera dem.</p>
            <p>Eller gå till returnadisc.se och klicka på "Jag har köpt stickers" när du vill aktivera.</p>
            '''
        )
        
        # Generera PDF
        try:
            from utils import generate_qr_pdf
            pdf_path = generate_qr_pdf_for_order(qr_codes, Config.PUBLIC_URL)
            session['order_pdf'] = pdf_path
        except Exception as e:
            logger.error(f"PDF generation failed: {e}")
        
        return redirect(url_for('auth.order_confirmation', order_id=order_id))
    
    # GET - visa formulär
    package = session.get('order_package', 'standard')
    count = session.get('order_count', 20)
    price = session.get('order_price', 99)
    
    package_names = {
        'start': 'Start (10 stickers)',
        'standard': 'Standard (20 stickers)',
        'pro': 'Pro (40 stickers)'
    }
    
    return render_template('auth/checkout.html', 
                         package=package,
                         package_name=package_names.get(package, 'Standard'),
                         sticker_count=count,
                         price=price)

@bp.route('/order-confirmation/<order_id>')
def order_confirmation(order_id):
    """Orderbekräftelse efter köp."""
    # Hämta från session eller databas
    stored_order_id = session.get('order_id')
    
    if stored_order_id != order_id:
        flash('Order hittades inte.', 'error')
        return redirect(url_for('auth.index'))
    
    qr_code_ids = session.get('order_qr_codes', [])
    qr_codes = []
    
    for qr_id in qr_code_ids:
        qr = db.get_qr(qr_id)
        if qr:
            qr_codes.append(qr)
    
    return render_template('auth/order_confirmation.html',
                         order_id=order_id,
                         qr_codes=qr_codes,
                         total_price=session.get('order_total', 0))

@bp.route('/download-order-pdf/<order_id>')
def download_order_pdf(order_id):
    """Ladda ner PDF för order."""
    stored_order_id = session.get('order_id')
    
    if stored_order_id != order_id:
        flash('Order hittades inte.', 'error')
        return redirect(url_for('auth.index'))
    
    pdf_path = session.get('order_pdf')
    
    if pdf_path and os.path.exists(pdf_path):
        return send_file(pdf_path, as_attachment=True, 
                        download_name=f'returnadisc-order-{order_id}.pdf')
    
    # Om PDF inte finns, generera ny
    qr_code_ids = session.get('order_qr_codes', [])
    qr_codes = []
    
    for qr_id in qr_code_ids:
        qr = db.get_qr(qr_id)
        if qr:
            qr_codes.append({'qr_id': qr_id})
    
    try:
        from utils import generate_qr_pdf_for_order
        pdf_path = generate_qr_pdf_for_order(qr_codes, Config.PUBLIC_URL)
        return send_file(pdf_path, as_attachment=True,
                        download_name=f'returnadisc-order-{order_id}.pdf')
    except Exception as e:
        logger.error(f"PDF generation failed: {e}")
        flash('Kunde inte generera PDF.', 'error')
        return redirect(url_for('auth.order_confirmation', order_id=order_id))

@bp.route('/signup-with-qr/<order_id>', methods=['GET', 'POST'])
def signup_with_qr(order_id):
    """Skapa konto och aktivera QR-kod från order."""
    # Verifiera order
    stored_order_id = session.get('order_id')
    
    # Om inte i session, kolla om vi kan hitta via email eller annan metod
    # För nu, använd första QR-koden från ordern
    qr_code_ids = session.get('order_qr_codes', [])
    
    if not qr_code_ids and stored_order_id != order_id:
        # Försök hitta order i databasen om vi har en order-tabell
        # Annars visa fel
        flash('Order hittades inte. Kontrollera din email för aktiveringslänk.', 'error')
        return redirect(url_for('auth.index'))
    
    # Hämta första QR-koden från ordern
    qr_id = qr_code_ids[0] if qr_code_ids else None
    
    if not qr_id:
        flash('Inga QR-koder hittades för denna order.', 'error')
        return redirect(url_for('auth.index'))
    
    qr = db.get_qr(qr_id)
    
    if not qr:
        flash('QR-kod hittades inte.', 'error')
        return redirect(url_for('auth.index'))
    
    if request.method == 'POST':
        name = request.form.get('name', '').strip()
        email = request.form.get('email', '').strip().lower()
        password = request.form.get('password', '').strip()
        submitted_qr_id = request.form.get('qr_id', '').strip().upper()
        
        if not all([name, email, password]):
            flash('Fyll i alla fält.', 'error')
            return redirect(url_for('auth.signup_with_qr', order_id=order_id))
        
        if len(password) < 6:
            flash('Lösenordet måste vara minst 6 tecken.', 'error')
            return redirect(url_for('auth.signup_with_qr', order_id=order_id))
        
        # Kolla om email redan finns
        existing_user = db.get_user_by_email(email)
        if existing_user:
            flash('Det finns redan ett konto med denna email. Logga in för att aktivera din QR-kod.', 'error')
            return redirect(url_for('auth.login'))
        
        try:
            # Skapa användare
            password_hash = generate_password_hash(password)
            user_id = db.create_user(name, email, password_hash)
            
            # Aktivera QR-koden
            db.activate_qr(submitted_qr_id or qr_id, user_id)
            
            # Logga in användaren
            session['user_id'] = user_id
            session.permanent = True
            
            flash('Välkommen! Din QR-kod är nu aktiverad.', 'success')
            return redirect(url_for('disc.dashboard'))
            
        except Exception as e:
            logger.error(f"Failed to create user and activate QR: {e}")
            flash('Ett fel uppstod. Försök igen.', 'error')
            return redirect(url_for('auth.signup_with_qr', order_id=order_id))
    
    return render_template('auth/signup_with_qr.html', 
                         order_id=order_id,
                         qr_code=qr)

@bp.route('/activate-later/<order_id>')
def activate_later(order_id):
    """Sida som förklarar hur man aktiverar senare."""
    return render_template('auth/activate_later.html', order_id=order_id)

@bp.route('/activate-existing', methods=['GET', 'POST'])
def activate_existing():
    """Aktivera QR-kod på befintligt konto."""
    if 'user_id' not in session:
        flash('Logga in först.', 'error')
        return redirect(url_for('auth.login'))
    
    if request.method == 'POST':
        qr_id = request.form.get('qr_id', '').strip().upper()
        
        if not qr_id:
            flash('Ange en QR-kod.', 'error')
            return redirect(url_for('auth.activate_existing'))
        
        qr = db.get_qr(qr_id)
        
        if not qr:
            flash('QR-koden hittades inte.', 'error')
            return redirect(url_for('auth.activate_existing'))
        
        if qr['is_active']:
            flash('Denna QR-kod är redan aktiverad.', 'error')
            return redirect(url_for('auth.activate_existing'))
        
        # Aktivera för nuvarande användare
        db.activate_qr(qr_id, session['user_id'])
        flash('Din QR-kod är nu aktiverad!', 'success')
        return redirect(url_for('disc.dashboard'))
    
    qr_id = request.args.get('qr_id', '')
    return render_template('auth/activate_qr_page.html', prefilled_qr=qr_id)