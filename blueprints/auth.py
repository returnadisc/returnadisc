"""Autentisering och användarhantering."""
import logging
import secrets
import os
import random
import re
from datetime import datetime
from dataclasses import dataclass
from typing import Optional, Dict, List, Callable
from functools import wraps

import stripe
from flask import (
    Blueprint, render_template, request, redirect, 
    url_for, flash, session, send_file, current_app
)
from werkzeug.security import generate_password_hash, check_password_hash

from database import db, Database, encryption
from utils import (
    send_email_async, generate_qr_pdf_for_order, 
    generate_random_qr_id, create_qr_code
)
from config import Config

logger = logging.getLogger(__name__)

# Stripe konfiguration
stripe.api_key = os.environ.get('STRIPE_SECRET_KEY')

bp = Blueprint('auth', __name__, url_prefix='')


# ============================================================================
# Exceptions
# ============================================================================

class AuthError(Exception):
    """Bas-exception för auth-fel."""
    pass


class ValidationError(AuthError):
    """Valideringsfel."""
    pass


class OrderError(AuthError):
    """Order-relaterat fel."""
    pass


# ============================================================================
# Dataclasses
# ============================================================================

@dataclass
class OrderData:
    """Håller order-information."""
    order_id: str
    package: str
    count: int
    price: float
    qr_codes: List[str]
    email: str
    pdf_path: Optional[str] = None
    
    def to_session(self) -> Dict:
        """Konvertera till session-dict."""
        return {
            'order_id': self.order_id,
            'order_package': self.package,
            'order_count': self.count,
            'order_price': self.price,
            'order_qr_codes': self.qr_codes,
            'order_email': self.email,
            'order_pdf': self.pdf_path
        }


@dataclass
class UserRegistration:
    """Håller registreringsdata."""
    name: str
    email: str
    password: str
    
    def validate(self) -> None:
        """Validera registreringsdata."""
        if not all([self.name, self.email, self.password]):
            raise ValidationError("Fyll i alla fält.")
        
        if len(self.password) < 6:
            raise ValidationError("Lösenordet måste vara minst 6 tecken.")
        
        # Validera email-format
        email_pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        if not re.match(email_pattern, self.email):
            raise ValidationError("Ogiltigt email-format.")


# ============================================================================
# Services
# ============================================================================

class SessionService:
    """Hantering av session-data."""
    
    ORDER_KEYS = [
        'order_id', 'order_package', 'order_count', 'order_price',
        'order_qr_codes', 'order_email', 'order_pdf'
    ]
    
    @classmethod
    def clear_order(cls) -> None:
        """Rensa all order-data från session."""
        for key in cls.ORDER_KEYS:
            session.pop(key, None)
    
    @classmethod
    def get_order(cls) -> Optional[OrderData]:
        """Hämta order från session."""
        order_id = session.get('order_id')
        if not order_id:
            return None
        
        return OrderData(
            order_id=order_id,
            package=session.get('order_package', 'standard'),
            count=session.get('order_count', 24),
            price=session.get('order_price', 99.0),
            qr_codes=session.get('order_qr_codes', []),
            email=session.get('order_email', ''),
            pdf_path=session.get('order_pdf')
        )
    
    @classmethod
    def save_order(cls, order: OrderData) -> None:
        """Spara order till session."""
        for key, value in order.to_session().items():
            session[key] = value
    
    @classmethod
    def validate_order_access(cls, order_id: str) -> bool:
        """Kontrollera att användaren har tillgång till order."""
        return session.get('order_id') == order_id and bool(session.get('order_qr_codes'))


class ValidationService:
    """Validering av input."""
    
    PACKAGE_CONFIG = {
        'start': {'count': 12, 'price': 59},
        'standard': {'count': 24, 'price': 99},
        'pro': {'count': 48, 'price': 179}
    }
    
    @classmethod
    def validate_package(cls, package: str) -> Dict:
        """Validera paket och returnera konfiguration."""
        if package not in cls.PACKAGE_CONFIG:
            raise ValidationError("Ogiltigt paket.")
        return cls.PACKAGE_CONFIG[package]


class QRGenerationService:
    """Generering av QR-koder för ordrar."""
    
    MAX_ATTEMPTS = 10
    
    def __init__(self, database: Database):
        self.db = database
    
    def generate_batch(self, count: int) -> List[Dict]:
        """Generera batch med QR-koder."""
        qr_codes = []
        
        for _ in range(count):
            qr_data = self._generate_single_qr()
            if qr_data:
                qr_codes.append(qr_data)
        
        if not qr_codes:
            raise OrderError("Inga QR-koder kunde skapas.")
        
        return qr_codes
    
    def _generate_single_qr(self) -> Optional[Dict]:
        """Generera en QR-kod med retry."""
        for attempt in range(self.MAX_ATTEMPTS):
            qr_id = generate_random_qr_id()
            
            if self.db.get_qr(qr_id):
                continue
            
            if not self.db.create_qr(qr_id):
                continue
            
            try:
                qr_filename = create_qr_code(qr_id, None)
                return {'qr_id': qr_id, 'qr_filename': qr_filename}
            except Exception as e:
                logger.error(f"Kunde inte skapa QR-bild för {qr_id}: {e}")
                continue
        
        return None


class AuthService:
    """Hantering av autentisering."""
    
    EMAIL_PATTERN = re.compile(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$')
    
    def __init__(self, database: Database):
        self.db = database
    
    def validate_email(self, email: str) -> str:
        """Validera och normalisera email."""
        email = email.lower().strip()
        if not self.EMAIL_PATTERN.match(email):
            raise ValidationError("Ogiltigt email-format.")
        return email
    
    def check_email_exists(self, email: str) -> bool:
        """Kontrollera om email redan finns (case-insensitive)."""
        normalized_email = email.lower().strip()
        existing = self.db.get_user_by_email(normalized_email)
        return existing is not None
    
    def register(self, name: str, email: str, password: str) -> int:
        """Registrera ny användare."""
        normalized_email = self.validate_email(email)
        
        if self.check_email_exists(normalized_email):
            raise ValidationError("Det finns redan ett konto med denna emailadress.")
        
        registration = UserRegistration(name, normalized_email, password)
        registration.validate()
        
        password_hash = generate_password_hash(password)
        return self.db.create_user(name, normalized_email, password_hash)
    
    def login(self, email: str, password: str) -> Optional[Dict]:
        """Logga in användare."""
        normalized_email = email.lower().strip()
        user = self.db.get_user_by_email(normalized_email)
        
        if not user:
            return None
        
        if not check_password_hash(user['password'], password):
            return None
        
        self.db.update_last_login(user['id'])
        return user


# ============================================================================
# Decorators
# ============================================================================

def handle_auth_errors(f: Callable) -> Callable:
    """Decorator som fångar auth-fel."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        try:
            return f(*args, **kwargs)
        except ValidationError as e:
            flash(str(e), 'error')
            return redirect(request.url)
        except AuthError as e:
            logger.warning(f"Auth error: {e}")
            flash(str(e), 'error')
            return redirect(request.url)
    return decorated_function


# ============================================================================
# Routes - Enkla sidor
# ============================================================================

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


@bp.route('/logout')
def logout():
    """Logga ut."""
    session.clear()
    flash('Du är utloggad.', 'info')
    return redirect(url_for('auth.index'))


# ============================================================================
# Routes - Autentisering
# ============================================================================

@bp.route('/signup', methods=['GET', 'POST'])
@handle_auth_errors
def signup():
    """Skapa konto med automatisk QR-kod."""
    if request.method == 'POST':
        name = request.form.get('name', '').strip()
        email = request.form.get('email', '').strip()
        password = request.form.get('password', '').strip()
        
        # Validera input
        if not all([name, email, password]):
            flash('Fyll i alla fält.', 'error')
            return redirect(url_for('auth.signup'))
        
        if len(password) < 6:
            flash('Lösenordet måste vara minst 6 tecken.', 'error')
            return redirect(url_for('auth.signup'))
        
        # Normalisera email
        normalized_email = email.lower().strip()
        
        # Kontrollera om email redan finns INNAN vi skapar något
        if db.get_user_by_email(normalized_email):
            flash('Det finns redan ett konto med denna emailadress. Logga in istället.', 'error')
            return redirect(url_for('auth.login'))
        
        # Validera email-format
        email_pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        if not re.match(email_pattern, normalized_email):
            flash('Ogiltigt email-format.', 'error')
            return redirect(url_for('auth.signup'))
        
        try:
            # Skapa användare med QR-kod
            user_id, qr_id, qr_filename = db.create_user_with_qr(
                name, normalized_email, generate_password_hash(password)
            )
            
            logger.info(f"Ny användare skapad: {user_id} med QR: {qr_id}")
            
        except Exception as e:
            logger.error(f"Failed to create user with QR: {e}")
            error_str = str(e).lower()
            if "unique" in error_str or "duplicate" in error_str or "integrity" in error_str:
                flash('Det finns redan ett konto med denna emailadress.', 'error')
                return redirect(url_for('auth.login'))
            flash('Ett fel uppstod vid skapande av konto.', 'error')
            return redirect(url_for('auth.signup'))
        
        # Logga in användaren automatiskt
        session['user_id'] = user_id
        
        flash('Välkommen! Ditt konto är skapat.', 'success')
        return redirect(url_for('disc.dashboard'))
    
    return render_template('auth/signup.html')


@bp.route('/login', methods=['GET', 'POST'])
@handle_auth_errors
def login():
    """Logga in."""
    if request.method == 'POST':
        email = request.form.get('email', '').strip().lower()
        password = request.form.get('password', '').strip()
        
        auth_service = AuthService(db)
        user = auth_service.login(email, password)
        
        if not user:
            flash('Fel email eller lösenord.', 'error')
            return redirect(url_for('auth.login'))
        
        session['user_id'] = user['id']
        session.permanent = True
        
        # Kontrollera och spara premium-status
        try:
            premium_status = db.get_user_premium_status(user['id'])
            session['has_premium'] = premium_status.get('has_premium', False)
        except Exception as e:
            logger.warning(f"Kunde inte hämta premium-status: {e}")
            session['has_premium'] = False
        
        flash('Välkommen tillbaka!', 'success')
        return redirect(url_for('disc.dashboard'))
    
    return render_template('auth/login.html')


@bp.route('/forgot-password', methods=['GET', 'POST'])
@handle_auth_errors
def forgot_password():
    """Glömt lösenord - skicka återställningslänk."""
    if request.method == 'POST':
        email = request.form.get('email', '').strip().lower()
        
        if not email:
            flash('Ange din email-adress.', 'error')
            return redirect(url_for('auth.forgot_password'))
        
        user = db.get_user_by_email(email)
        
        if user:
            reset_token = secrets.token_urlsafe(32)
            db.set_reset_token(email, reset_token)
            
            reset_url = url_for('auth.reset_password', token=reset_token, _external=True)
            
            subject = "Återställ ditt lösenord - ReturnaDisc"
            html_content = f"""
            <h2>Hej {user.get('name', '')}!</h2>
            <p>Du har begärt att återställa ditt lösenord.</p>
            <p>Klicka på länken nedan för att välja ett nytt lösenord:</p>
            <p><a href="{reset_url}" style="display: inline-block; background: #166534; color: white; padding: 12px 24px; text-decoration: none; border-radius: 8px;">Återställ lösenord</a></p>
            <p>Eller kopiera denna länk: {reset_url}</p>
            <p>Länken är giltig i 24 timmar.</p>
            <p>Om du inte begärt detta kan du ignorera detta mail.</p>
            <br>
            <p>Med vänliga hälsningar,<br>ReturnaDisc-teamet</p>
            """
            
            send_email_async(email, subject, html_content)
            logger.info(f"Password reset requested for: {email}")
        
        flash('Om det finns ett konto med den emailen har vi skickat en återställningslänk.', 'info')
        return redirect(url_for('auth.login'))
    
    return render_template('auth/forgot_password.html')


@bp.route('/reset-password/<token>', methods=['GET', 'POST'])
@handle_auth_errors
def reset_password(token):
    """Återställ lösenord med token."""
    user = db.get_user_by_token(token)
    
    if not user:
        flash('Ogiltig eller utgången länk. Begär en ny.', 'error')
        return redirect(url_for('auth.forgot_password'))
    
    if request.method == 'POST':
        password = request.form.get('password', '').strip()
        confirm_password = request.form.get('confirm_password', '').strip()
        
        if not password or len(password) < 6:
            flash('Lösenordet måste vara minst 6 tecken.', 'error')
            return redirect(request.url)
        
        if password != confirm_password:
            flash('Lösenorden matchar inte.', 'error')
            return redirect(request.url)
        
        password_hash = generate_password_hash(password)
        db.update_password(user['id'], password_hash)
        
        flash('Ditt lösenord har uppdaterats! Logga in med ditt nya lösenord.', 'success')
        return redirect(url_for('auth.login'))
    
    return render_template('auth/reset_password.html', token=token)


# ============================================================================
# Routes - Stripe Betalning
# ============================================================================

@bp.route('/checkout', methods=['GET', 'POST'])
def checkout():
    """Checkout med formulär för leveransadress INNAN Stripe."""
    if request.method == 'POST':
        # Steg 2: Formuläret är skickat, spara i session och gå till Stripe
        package = request.form.get('package')
        name = request.form.get('name', '').strip()
        email = request.form.get('email', '').strip().lower()
        phone = request.form.get('phone', '').strip()
        address = request.form.get('address', '').strip()
        postal_code = request.form.get('postal_code', '').strip()
        city = request.form.get('city', '').strip()
        
        # Validera
        if not all([package, name, email, address, postal_code, city]):
            flash('Fyll i alla obligatoriska fält.', 'error')
            return redirect(url_for('auth.checkout', package=package))
        
        # Spara i session
        session['checkout_package'] = package
        session['checkout_name'] = name
        session['checkout_email'] = email
        session['checkout_phone'] = phone
        session['checkout_address'] = address
        session['checkout_postal_code'] = postal_code
        session['checkout_city'] = city
        
        # Hämta paketinfo
        try:
            config = ValidationService.validate_package(package)
            count = config['count']
            price = config['price'] * 100  # Öre
        except ValidationError:
            flash('Ogiltigt paket.', 'error')
            return redirect(url_for('auth.buy_stickers'))
        
        # Skapa Stripe Checkout Session
        try:
            checkout_session = stripe.checkout.Session.create(
                payment_method_types=['card'],
                line_items=[{
                    'price_data': {
                        'currency': 'sek',
                        'product_data': {
                            'name': f'ReturnaDisc Stickers - {package.capitalize()}',
                            'description': f'{count} st QR-klistermärken',
                        },
                        'unit_amount': price,
                    },
                    'quantity': 1,
                }],
                mode='payment',
                # TA BORT shipping_address_collection - vi har redan adressen!
                success_url=request.host_url + 'order-confirmation-stripe?session_id={CHECKOUT_SESSION_ID}',
                cancel_url=request.host_url + 'buy-stickers',
                customer_email=email,  # Fyll i email automatiskt i Stripe
                metadata={
                    'package': package,
                    'count': str(count),
                    'customer_email': email,
                }
            )
            
            return redirect(checkout_session.url, code=303)
            
        except Exception as e:
            logger.error(f"Stripe checkout error: {e}")
            flash('Ett fel uppstod vid betalning. Försök igen.', 'error')
            return redirect(url_for('auth.buy_stickers'))
    
    # Steg 1: Visa formulär (GET)
    package = request.args.get('package', 'standard')
    
    try:
        config = ValidationService.validate_package(package)
    except ValidationError:
        flash('Ogiltigt paket.', 'error')
        return redirect(url_for('auth.buy_stickers'))
    
    package_names = {
        'start': 'Start (12 stickers)',
        'standard': 'Standard (24 stickers)',
        'pro': 'Pro (48 stickers)'
    }
    
    return render_template('auth/checkout_form.html',
                         package=package,
                         package_name=package_names.get(package, package),
                         sticker_count=config['count'],
                         price=config['price'])


@bp.route('/order-confirmation-stripe')
def order_confirmation_stripe():
    """Visa bekräftelse efter Stripe-betalning."""
    session_id = request.args.get('session_id')
    
    if not session_id:
        flash('Ingen order hittades', 'error')
        return redirect(url_for('auth.index'))
    
    try:
        checkout_session = stripe.checkout.Session.retrieve(session_id)
        
        if checkout_session.payment_status != 'paid':
            flash('Betalningen är inte slutförd', 'warning')
            return redirect(url_for('auth.buy_stickers'))
        
        # Hämta paketinfo från Stripe metadata
        package = checkout_session.metadata.get('package')
        count = int(checkout_session.metadata.get('count', 24))
        
        # ============================================================================
        # HÄMTA LEVERANSADRESS FRÅN SESSION (inte Stripe!)
        # ============================================================================
        shipping_name = session.get('checkout_name', '')
        shipping_email = session.get('checkout_email', '')
        shipping_phone = session.get('checkout_phone', '')
        shipping_address = session.get('checkout_address', '')
        shipping_postal_code = session.get('checkout_postal_code', '')
        shipping_city = session.get('checkout_city', '')
        shipping_country = 'SE'
        
        # Fallback till Stripe om session saknas (gammal order)
        if not shipping_name:
            if checkout_session.customer_details:
                shipping_name = getattr(checkout_session.customer_details, 'name', '') or ''
                shipping_email = getattr(checkout_session.customer_details, 'email', '') or ''
        
        # Debug
        logger.info(f"Order from session: {shipping_name}, {shipping_address}, {shipping_postal_code} {shipping_city}")
        
        # Hämta eller skapa användare
        user = db.get_user_by_email(shipping_email) if shipping_email else None
        user_id = None
        qr_id = None
        
        if user:
            user_id = user['id']
            user_qr = db.get_user_qr(user_id)
            if user_qr:
                qr_id = user_qr.get('qr_id')
        else:
            user_id = 0  # Temporär, uppdateras vid registrering
        
        # Beräkna pris
        package_prices = {'start': 59, 'standard': 99, 'pro': 179}
        total_amount = package_prices.get(package, 99)
        
        # Skapa order
        order_data = {
            'user_id': user_id,
            'qr_id': qr_id,
            'package_type': package,
            'quantity': count,
            'total_amount': total_amount,
            'currency': 'SEK',
            'status': 'paid',
            'payment_method': 'stripe',
            'payment_id': checkout_session.payment_intent,
            'shipping_name': shipping_name,
            'shipping_address': shipping_address,
            'shipping_postal_code': shipping_postal_code,
            'shipping_city': shipping_city,
            'shipping_country': shipping_country
        }
        
        try:
            order = db.create_order(order_data)
            order_number = order['order_number']
            logger.info(f"Order skapad: {order_number} för {shipping_email}")
        except Exception as e:
            logger.error(f"Kunde inte skapa order: {e}")
            date_str = datetime.now().strftime('%y%m%d')
            random_suffix = ''.join([str(random.randint(0, 9)) for _ in range(4)])
            order_number = f"RD-{date_str}-{random_suffix}"
        
        # Rensa session
        session.pop('checkout_package', None)
        session.pop('checkout_name', None)
        session.pop('checkout_email', None)
        session.pop('checkout_phone', None)
        session.pop('checkout_address', None)
        session.pop('checkout_postal_code', None)
        session.pop('checkout_city', None)
        
        # Skicka mail till admin
        admin_email = getattr(Config, 'ADMIN_EMAIL', None) or 'info@returnadisc.se'
        
        address_html = f"{shipping_name}<br>{shipping_address}<br>{shipping_postal_code} {shipping_city}"
        
        admin_html = f"""<h2>Ny betalning mottagen!</h2>
<p><strong>Order:</strong> #{order_number}</p>
<p><strong>Kund:</strong> {shipping_email}</p>
<p><strong>Telefon:</strong> {shipping_phone or '-'}</p>
<p><strong>Paket:</strong> {package} ({count} stickers)</p>
<p><strong>Betalat:</strong> {total_amount} kr</p>
<hr>
<p><strong>Leveransadress:</strong><br>{address_html}</p>
<hr>
<p><strong>QR-kod:</strong> {qr_id or 'Tilldelas vid registrering'}</p>
<p><a href="{Config.PUBLIC_URL}/admin/orders">Se alla ordrar i admin</a></p>"""
        
        try:
            send_email_async(admin_email, f"Ny order #{order_number}", admin_html)
        except Exception as e:
            logger.error(f"Kunde inte skicka admin-mail: {e}")
        
        # Skicka mail till kund
        customer_html = f"""<div style="font-family: Arial, sans-serif; max-width: 600px;">
<h2 style="color: #166534;">Hej {shipping_name}!</h2>
<p style="font-size: 16px;">Tack för din beställning hos <strong>ReturnaDisc</strong>.</p>
<p style="font-size: 16px;"><strong>Ditt ordernummer:</strong> #{order_number}</p>
<p style="font-size: 16px; background: #f0fdf4; padding: 15px; border-radius: 8px;">Dina QR-klistermärken skickas inom <strong>1-2 arbetsdagar</strong> till:</p>
<p style="font-size: 14px;">{shipping_name}<br>{shipping_address}<br>{shipping_postal_code} {shipping_city}</p>
<p style="font-size: 14px; color: #666;">Har du frågor? Kontakta oss på <a href="mailto:info@returnadisc.se">info@returnadisc.se</a></p>
<br>
<p style="font-size: 14px;">Med vänliga hälsningar,<br><strong>ReturnaDisc-teamet</strong></p>
</div>"""
        
        try:
            send_email_async(shipping_email, f"Din beställning #{order_number} är bekräftad", customer_html)
        except Exception as e:
            logger.error(f"Kunde inte skicka kundmail: {e}")
        
        return render_template('auth/order_confirmation_stripe.html', 
                             package=package,
                             count=count,
                             order_id=order_number,
                             email=shipping_email)
        
    except Exception as e:
        logger.error(f"Order confirmation error: {e}")
        flash('Ett fel uppstod', 'error')
        return redirect(url_for('auth.index'))


@bp.route('/download-qr/<qr_id>')
def download_qr(qr_id):
    """Ladda ner enskild QR-kod."""
    qr_folder = os.environ.get('QR_FOLDER', 'static/qr')
    filepath = os.path.join(qr_folder, f"qr_{qr_id}.png")
    
    if os.path.exists(filepath):
        return send_file(filepath, as_attachment=True, download_name=f'returnadisc_{qr_id}.png')
    else:
        flash(f'QR-kod {qr_id} hittades inte', 'error')
        return redirect(url_for('auth.index'))


@bp.route('/signup-with-qr', methods=['GET', 'POST'])
@handle_auth_errors
def signup_with_purchased_qr():
    """Skapa konto och aktivera köpt QR-kod."""
    if request.method == 'POST':
        qr_id = request.form.get('qr_id', '').strip().upper()
        name = request.form.get('name', '').strip()
        email = request.form.get('email', '').strip()
        password = request.form.get('password', '').strip()
        
        # Validera input
        if not all([qr_id, name, email, password]):
            flash('Fyll i alla fält.', 'error')
            return redirect(url_for('auth.signup_with_purchased_qr'))
        
        if len(password) < 6:
            flash('Lösenordet måste vara minst 6 tecken.', 'error')
            return redirect(url_for('auth.signup_with_purchased_qr'))
        
        # Normalisera email
        normalized_email = email.lower().strip()
        
        # Validera email-format
        email_pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        if not re.match(email_pattern, normalized_email):
            flash('Ogiltigt email-format.', 'error')
            return redirect(url_for('auth.signup_with_purchased_qr'))
        
        # Kontrollera att email inte redan finns
        if db.get_user_by_email(normalized_email):
            flash('Det finns redan ett konto med denna emailadress. Logga in istället.', 'error')
            return redirect(url_for('auth.login'))
        
        # Kontrollera att QR-koden finns och är inaktiv (ej tilldelad)
        qr = db.get_qr(qr_id)
        logger.info(f"Signup with QR: Hittade QR {qr_id}: {qr}")
        
        if not qr:
            flash(f'QR-koden "{qr_id}" hittades inte. Kontrollera att du skrivit rätt.', 'error')
            return redirect(url_for('auth.signup_with_purchased_qr'))
        
        if qr.get('user_id') or qr.get('is_active'):
            flash(f'QR-koden "{qr_id}" är redan aktiverad. Kontakta support om du behöver hjälp.', 'error')
            return redirect(url_for('auth.signup_with_purchased_qr'))
        
        try:
            # Skapa användare och aktivera QR i samma transaktion
            user_id = db.register_user_on_qr(qr_id, name, normalized_email, password)
            
            logger.info(f"Användare {user_id} skapad och QR {qr_id} aktiverad")
            
            # Verifiera att QR-koden verkligen aktiverades
            qr_check = db.get_qr(qr_id)
            logger.info(f"Verifiering efter aktivering: {qr_check}")
            
            # Logga in användaren
            session['user_id'] = user_id
            
            flash(f'Välkommen! Ditt konto är skapat och QR-koden {qr_id} är nu aktiverad.', 'success')
            return redirect(url_for('disc.dashboard'))
            
        except ValueError as e:
            logger.error(f"Valideringsfel vid skapande av konto med QR: {e}")
            flash(str(e), 'error')
            return redirect(url_for('auth.signup_with_purchased_qr'))
        except Exception as e:
            logger.error(f"Fel vid skapande av konto med QR: {e}")
            error_str = str(e).lower()
            if "unique" in error_str or "duplicate" in error_str or "integrity" in error_str:
                flash('Det finns redan ett konto med denna emailadress.', 'error')
                return redirect(url_for('auth.login'))
            flash('Ett fel uppstod. Försök igen eller kontakta support.', 'error')
            return redirect(url_for('auth.signup_with_purchased_qr'))
    
    return render_template('auth/signup_with_purchased_qr.html')