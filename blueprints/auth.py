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
            package=session.get('order_package', 'medium'),
            count=session.get('order_count', 12),
            price=session.get('order_price', 69.0),
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
    
    # UPPDATERADE PAKET: small, medium, large
    # Priser för .se (SEK) - OFÖRÄNDRADE
    PACKAGE_CONFIG_SE = {
        'small': {'count': 6, 'price': 49, 'price_id': None},  # 49 kr
        'medium': {'count': 12, 'price': 69, 'price_id': None},  # 69 kr
        'large': {'count': 24, 'price': 99, 'price_id': None}  # 99 kr
    }
    
    # Priser för .com (USD) - NYA
    PACKAGE_CONFIG_US = {
        'small': {'count': 6, 'price': 5.99, 'price_id': None},   # $5.99
        'medium': {'count': 12, 'price': 7.99, 'price_id': None},  # $7.99
        'large': {'count': 24, 'price': 9.99, 'price_id': None}   # $9.99
    }
    
    @classmethod
    def get_package_config(cls, package: str, domain: str = None) -> Dict:
        """Validera paket och returnera konfiguration baserat på domän."""
        if package not in cls.PACKAGE_CONFIG_SE:
            raise ValidationError("Ogiltigt paket.")
        
        # Om .com domän, använd USD-priser
        if domain and 'returnadisc.com' in domain.lower():
            return cls.PACKAGE_CONFIG_US[package]
        
        # Standard: .se priser
        return cls.PACKAGE_CONFIG_SE[package]


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
# Routes - Stripe Betalning (UPPDATERAD FÖR .COM/.SE)
# ============================================================================

@bp.route('/checkout', methods=['GET', 'POST'])
def checkout():
    """Checkout med formulär för leveransadress INNAN Stripe."""
    
    # Kolla om det är .com eller .se
    host = request.host.lower()
    is_com = 'returnadisc.com' in host
    is_se = 'returnadisc.se' in host or not is_com  # Default till .se beteende
    
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
        
        # Hämta paketinfo baserat på domän
        try:
            config = ValidationService.get_package_config(package, host)
            count = config['count']
            price = config['price']
        except ValidationError:
            flash('Ogiltigt paket.', 'error')
            return redirect(url_for('auth.buy_stickers'))
        
        # Hämta rätt Stripe Price ID baserat på domän
        price_ids = Config.get_stripe_price_ids(host)
        price_id = price_ids.get(package)
        currency = price_ids.get('currency', 'sek')
        
        if not price_id:
            # Fallback till price_data om inget Price ID är konfigurerat
            logger.warning(f"Inget Stripe Price ID konfigurerat för {package} på {host}")
            unit_amount = int(price * 100)  # Öre/cents
            
            line_item = {
                'price_data': {
                    'currency': currency,
                    'product_data': {
                        'name': f'ReturnaDisc Stickers - {package.capitalize()}',
                        'description': f'{count} QR stickers',
                    },
                    'unit_amount': unit_amount,
                },
                'quantity': 1,
            }
        else:
            # Använd befintligt Price ID
            line_item = {
                'price': price_id,
                'quantity': 1,
            }
        
        # Skapa Stripe Checkout Session
        try:
            checkout_session = stripe.checkout.Session.create(
                payment_method_types=['card'],
                line_items=[line_item],
                mode='payment',
                success_url=request.host_url + 'order-confirmation-stripe?session_id={CHECKOUT_SESSION_ID}',
                cancel_url=request.host_url + 'buy-stickers',
                customer_email=email,
                metadata={
                    'package': package,
                    'count': str(count),
                    'customer_email': email,
                    'domain': 'com' if is_com else 'se',
                    'currency': currency
                }
            )
            
            return redirect(checkout_session.url, code=303)
            
        except Exception as e:
            logger.error(f"Stripe checkout error: {e}")
            flash('Ett fel uppstod vid betalning. Försök igen.', 'error')
            return redirect(url_for('auth.buy_stickers'))
    
    # Steg 1: Visa formulär (GET)
    package = request.args.get('package', 'medium')
    
    try:
        config = ValidationService.get_package_config(package, host)
    except ValidationError:
        flash('Ogiltigt paket.', 'error')
        return redirect(url_for('auth.buy_stickers'))
    
    # UPPDATERADE PAKETNAMN baserat på domän
    if is_com:
        package_names = {
            'small': 'Small (6 stickers)',
            'medium': 'Medium (12 stickers)',
            'large': 'Large (24 stickers)'
        }
    else:
        # Svenska för .se
        package_names = {
            'small': 'Small (6 stickers)',
            'medium': 'Medium (12 stickers)',
            'large': 'Large (24 stickers)'
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
        
        # Konvertera Stripe metadata-objekt till vanlig dict
        metadata_obj = getattr(checkout_session, 'metadata', None)
        
        if metadata_obj is None:
            metadata = {}
        elif hasattr(metadata_obj, 'to_dict'):
            metadata = metadata_obj.to_dict()
        elif isinstance(metadata_obj, dict):
            metadata = metadata_obj
        else:
            try:
                metadata = dict(metadata_obj)
            except:
                metadata = {}
        
        package = metadata.get('package')
        count_str = metadata.get('count', '12')
        domain = metadata.get('domain', 'se')
        currency = metadata.get('currency', 'sek')
        
        try:
            count = int(count_str)
        except (ValueError, TypeError):
            count = 12
        
        # Fallback om metadata saknas
        if not package:
            try:
                line_items = stripe.checkout.Session.list_line_items(session_id, limit=1)
                if line_items and line_items.data:
                    desc = line_items.data[0].description or ''
                    if 'small' in desc.lower():
                        package = 'small'
                        count = 6
                    elif 'large' in desc.lower():
                        package = 'large'
                        count = 24
                    else:
                        package = 'medium'
                        count = 12
            except Exception as e:
                logger.warning(f"Kunde inte hämta line_items: {e}")
                package = 'medium'
                count = 12
        
        if package not in ['small', 'medium', 'large']:
            package = 'medium'
            count = 12
        
        # Hämta KUNDUPPGIFTER
        shipping_name = session.get('checkout_name', '')
        shipping_email = session.get('checkout_email', '')
        shipping_phone = session.get('checkout_phone', '')
        shipping_address = session.get('checkout_address', '')
        shipping_postal_code = session.get('checkout_postal_code', '')
        shipping_city = session.get('checkout_city', '')
        
        # Hämta customer_details på säkert sätt
        customer_details = getattr(checkout_session, 'customer_details', None)
        
        if customer_details:
            if not shipping_email:
                shipping_email = getattr(customer_details, 'email', '') or ''
            if not shipping_name:
                shipping_name = getattr(customer_details, 'name', '') or ''
            
            if not shipping_address:
                address = getattr(customer_details, 'address', None)
                if address:
                    shipping_address = getattr(address, 'line1', '') or ''
                    line2 = getattr(address, 'line2', '')
                    if line2:
                        shipping_address += f", {line2}"
                    shipping_postal_code = getattr(address, 'postal_code', '') or ''
                    shipping_city = getattr(address, 'city', '') or ''
        
        if not shipping_email:
            shipping_email = getattr(checkout_session, 'customer_email', '') or ''
        
        if not shipping_email:
            logger.error("Ingen email hittades för order! Session ID: %s", session_id)
            flash('Ett fel uppstod - kunde inte identifiera beställningen', 'error')
            return redirect(url_for('auth.index'))
        
        shipping_country = 'SE' if domain == 'se' else 'US'
        
        logger.info(f"Order från: {shipping_email}, paket: {package}, count: {count}, domain: {domain}")
        
        # SKAPA ANVÄNDARE ELLER HÄMTA BEFINTLIG
        user = db.get_user_by_email(shipping_email) if shipping_email else None
        user_id = None
        qr_id = None
        
        if user:
            user_id = user['id']
            user_qr = db.get_user_qr(user_id)
            if user_qr:
                qr_id = user_qr.get('qr_id')
        else:
            user_id = 0
        
        # SKAPA ORDER
        # Använd rätt pris baserat på domän
        if domain == 'com':
            package_prices = {'small': 5.99, 'medium': 7.99, 'large': 9.99}
        else:
            package_prices = {'small': 49, 'medium': 69, 'large': 99}
        
        total_amount = package_prices.get(package, 69 if domain == 'se' else 7.99)
        
        order_data = {
            'user_id': user_id,
            'qr_id': qr_id,
            'package_type': package,
            'quantity': count,
            'total_amount': total_amount,
            'currency': currency.upper(),
            'status': 'paid',
            'payment_method': 'stripe',
            'payment_id': checkout_session.payment_intent,
            'shipping_name': shipping_name or 'Okänd',
            'shipping_address': shipping_address or 'Ej angiven',
            'shipping_postal_code': shipping_postal_code or '00000',
            'shipping_city': shipping_city or 'Okänd',
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
        
        # RENSA SESSION
        for key in ['checkout_package', 'checkout_name', 'checkout_email', 
                    'checkout_phone', 'checkout_address', 'checkout_postal_code', 
                    'checkout_city']:
            session.pop(key, None)
        
        # SKICKA MAIL
        admin_email = 'info@returnadisc.com'
        
        # Anpassa mail baserat på domän
        if domain == 'com':
            address_html = f"{shipping_name or ''}<br>{shipping_address or ''}<br>{shipping_postal_code or ''} {shipping_city or ''}"
            currency_symbol = '$'
        else:
            address_html = f"{shipping_name or ''}<br>{shipping_address or ''}<br>{shipping_postal_code or ''} {shipping_city or ''}"
            currency_symbol = 'kr'
        
        admin_html = f"""<h2>Ny betalning mottagen!</h2>
<p><strong>Order:</strong> #{order_number}</p>
<p><strong>Kund:</strong> {shipping_email}</p>
<p><strong>Telefon:</strong> {shipping_phone or '-'}</p>
<p><strong>Paket:</strong> {package} ({count} stickers)</p>
<p><strong>Betalat:</strong> {currency_symbol}{total_amount}</p>
<p><strong>Domän:</strong> {domain}</p>
<hr>
<p><strong>Leveransadress:</strong><br>{address_html}</p>
<hr>
<p><strong>QR-kod:</strong> {qr_id or 'Tilldelas vid registrering'}</p>
<p><a href="{Config.PUBLIC_URL}/admin/orders">Se alla ordrar i admin</a></p>"""
        
        try:
            send_email_async(admin_email, f"Ny order #{order_number}", admin_html)
        except Exception as e:
            logger.error(f"Kunde inte skicka admin-mail: {e}")
        
        # Kundmail anpassat för domän
        if domain == 'com':
            customer_html = f"""<div style="font-family: Arial, sans-serif; max-width: 600px;">
<h2 style="color: #166534;">Hi {shipping_name or 'Customer'}!</h2>
<p style="font-size: 16px;">Thank you for your order at <strong>ReturnaDisc</strong>.</p>
<p style="font-size: 16px;"><strong>Your order number:</strong> #{order_number}</p>
<p style="font-size: 16px; background: #f0fdf4; padding: 15px; border-radius: 8px;">
Your QR stickers will be shipped within <strong>1-2 business days</strong> to:</p>
<p style="font-size: 14px;">{shipping_name or ''}<br>{shipping_address or ''}<br>{shipping_postal_code or ''} {shipping_city or ''}</p>
<p style="font-size: 14px; color: #666;">Questions? Contact us at <a href="mailto:info@returnadisc.com">info@returnadisc.com</a></p>
<br>
<p style="font-size: 14px;">Best regards,<br><strong>The ReturnaDisc Team</strong></p>
</div>"""
        else:
            # Svenskt mail för .se
            customer_html = f"""<div style="font-family: Arial, sans-serif; max-width: 600px;">
<h2 style="color: #166534;">Hej {shipping_name or 'Kund'}!</h2>
<p style="font-size: 16px;">Tack för din beställning hos <strong>ReturnaDisc</strong>.</p>
<p style="font-size: 16px;"><strong>Ditt ordernummer:</strong> #{order_number}</p>
<p style="font-size: 16px; background: #f0fdf4; padding: 15px; border-radius: 8px;">
Dina QR-klistermärken skickas inom <strong>1-2 arbetsdagar</strong> till:</p>
<p style="font-size: 14px;">{shipping_name or ''}<br>{shipping_address or ''}<br>{shipping_postal_code or ''} {shipping_city or ''}</p>
<p style="font-size: 14px; color: #666;">Har du frågor? Kontakta oss på <a href="mailto:info@returnadisc.com">info@returnadisc.com</a></p>
<br>
<p style="font-size: 14px;">Med vänliga hälsningar,<br><strong>ReturnaDisc-teamet</strong></p>
</div>"""
        
        try:
            send_email_async(shipping_email, f"Din beställning #{order_number} är bekräftad" if domain == 'se' else f"Your order #{order_number} is confirmed", customer_html)
        except Exception as e:
            logger.error(f"Kunde inte skicka kundmail: {e}")
        
        return render_template('auth/order_confirmation_stripe.html', 
                             package=package,
                             count=count,
                             order_id=order_number,
                             email=shipping_email,
                             domain=domain)
        
    except Exception as e:
        logger.error(f"Order confirmation error: {e}")
        logger.exception("Full stacktrace:")
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
            return redirect(request.url)
        
        if len(password) < 6:
            flash('Lösenordet måste vara minst 6 tecken.', 'error')
            return redirect(request.url)
        
        # Normalisera email
        normalized_email = email.lower().strip()
        
        # Validera email-format
        email_pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        if not re.match(email_pattern, normalized_email):
            flash('Ogiltigt email-format.', 'error')
            return redirect(request.url)
        
        # Kontrollera att email inte redan finns
        if db.get_user_by_email(normalized_email):
            flash('Det finns redan ett konto med denna emailadress. Logga in för att aktivera QR-koden.', 'error')
            # Spara QR-koden i session så de kan aktivera den efter inloggning
            session['pending_qr_activation'] = qr_id
            return redirect(url_for('auth.login'))
        
        # Kontrollera att QR-koden finns och är inaktiv (ej tilldelad)
        qr = db.get_qr(qr_id)
        logger.info(f"Signup with QR: Hittade QR {qr_id}: {qr}")
        
        if not qr:
            flash(f'QR-koden "{qr_id}" hittades inte. Kontrollera att du skrivit rätt.', 'error')
            return redirect(request.url)
        
        if qr.get('user_id') or qr.get('is_active'):
            flash(f'QR-koden "{qr_id}" är redan aktiverad. Kontakta support om du behöver hjälp.', 'error')
            return redirect(request.url)
        
        try:
            # Skapa användare och aktivera DENNA specifika QR-kod
            user_id = db.register_user_on_qr(qr_id, name, normalized_email, password)
            
            logger.info(f"Användare {user_id} skapad via QR-scan/köp, QR {qr_id} aktiverad")
            
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
            return redirect(request.url)
        except Exception as e:
            logger.error(f"Fel vid skapande av konto med QR: {e}")
            error_str = str(e).lower()
            if "unique" in error_str or "duplicate" in error_str or "integrity" in error_str:
                flash('Det finns redan ett konto med denna emailadress.', 'error')
                return redirect(url_for('auth.login'))
            flash('Ett fel uppstod. Försök igen eller kontakta support.', 'error')
            return redirect(request.url)
    
    # GET - visa formuläret (qr_id kan komma från query string vid scanning)
    return render_template('auth/signup_with_purchased_qr.html')
    
    
    
from flask import Blueprint, jsonify

# ... befintlig kod ...

@bp.route('/api/check-session')
def check_session():
    """API endpoint to check if session is still valid"""
    if 'user_id' in session:
        return '', 200  # Session valid
    return '', 401  # Session expired
    
    
    
@bp.route('/faq')
def faq():
    """Vanliga frågor om ReturnaDisc."""
    return render_template('faq.html')