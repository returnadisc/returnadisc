"""Autentisering och användarhantering."""
import logging
import secrets
import os
from dataclasses import dataclass
from typing import Optional, Dict, List, Callable
from functools import wraps

import stripe
from flask import (
    Blueprint, render_template, request, redirect, 
    url_for, flash, session, send_file, current_app
)
from werkzeug.security import generate_password_hash, check_password_hash

from database import db, Database
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
            count=session.get('order_count', 20),
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
        'start': {'count': 10, 'price': 59},
        'standard': {'count': 20, 'price': 99},
        'pro': {'count': 40, 'price': 179}
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
    
    def __init__(self, database: Database):
        self.db = database
    
    def register(self, name: str, email: str, password: str) -> int:
        """Registrera ny användare."""
        registration = UserRegistration(name, email, password)
        registration.validate()
        
        if self.db.get_user_by_email(email):
            raise ValidationError("Det finns redan ett konto med den emailen.")
        
        password_hash = generate_password_hash(password)
        return self.db.create_user(name, email, password_hash)
    
    def login(self, email: str, password: str) -> Optional[Dict]:
        """Logga in användare."""
        user = self.db.get_user_by_email(email)
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
        email = request.form.get('email', '').strip().lower()
        password = request.form.get('password', '').strip()
        
        try:
            user_id, qr_id, qr_filename = db.create_user_with_qr(
                name, email, generate_password_hash(password)
            )
        except Exception as e:
            logger.error(f"Failed to create user with QR: {e}")
            flash('Ett fel uppstod vid skapande av konto.', 'error')
            return redirect(url_for('auth.signup'))
        
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
        
        # Kolla om användaren finns (visa inte om den inte finns - säkerhet)
        user = db.get_user_by_email(email)
        
        if user:
            # Generera reset-token
            reset_token = secrets.token_urlsafe(32)
            
            # Spara token i databasen
            db.set_reset_token(email, reset_token)
            
            # Skicka email med reset-länk
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
        
        # Visa alltid samma meddelande oavsett om användaren finns (säkerhet)
        flash('Om det finns ett konto med den emailen har vi skickat en återställningslänk.', 'info')
        return redirect(url_for('auth.login'))
    
    return render_template('auth/forgot_password.html')


@bp.route('/reset-password/<token>', methods=['GET', 'POST'])
@handle_auth_errors
def reset_password(token):
    """Återställ lösenord med token."""
    # Verifiera token
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
        
        # Uppdatera lösenord och rensa token
        password_hash = generate_password_hash(password)
        db.update_password(user['id'], password_hash)
        
        flash('Ditt lösenord har uppdaterats! Logga in med ditt nya lösenord.', 'success')
        return redirect(url_for('auth.login'))
    
    return render_template('auth/reset_password.html', token=token)


# ============================================================================
# Routes - Stripe Betalning
# ============================================================================

@bp.route('/checkout', methods=['POST'])
def checkout():
    """Stripe checkout för stickers."""
    try:
        package = request.form.get('package')
        count = int(request.form.get('count', 10))
        
        prices = {
            'start': 5900,
            'standard': 9900,
            'pro': 17900
        }
        
        price = prices.get(package, 5900)
        
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
            success_url=request.host_url + 'order-confirmation-stripe?session_id={CHECKOUT_SESSION_ID}',
            cancel_url=request.host_url + 'buy-stickers',
            metadata={
                'package': package,
                'count': str(count),
            }
        )
        
        return redirect(checkout_session.url, code=303)
        
    except Exception as e:
        logger.error(f"Stripe checkout error: {e}")
        flash('Ett fel uppstod vid betalning. Försök igen.', 'error')
        return redirect(url_for('auth.buy_stickers'))


@bp.route('/order-confirmation-stripe')
def order_confirmation_stripe():
    """Visa bekräftelse efter Stripe-betalning."""
    session_id = request.args.get('session_id')
    
    if not session_id:
        flash('Ingen order hittades', 'error')
        return redirect(url_for('auth.index'))
    
    try:
        checkout_session = stripe.checkout.Session.retrieve(session_id)
        
        if checkout_session.payment_status == 'paid':
            package = checkout_session.metadata.get('package')
            count = int(checkout_session.metadata.get('count', 10))
            customer_email = checkout_session.customer_details.email if checkout_session.customer_details else 'okänd'
            
            # Generera QR-koder
            qr_service = QRGenerationService(db)
            qr_codes = qr_service.generate_batch(count)
            
            order_id = f"STRIPE-{session_id[:8].upper()}"
            
            # Mail till admin (dig)
            admin_email = os.environ.get('ADMIN_EMAIL', 'din-email@example.com')
            admin_subject = f"NY BETALNING - ReturnaDisc Order #{order_id}"
            admin_html = f"""
            <h2>Ny betalning mottagen!</h2>
            <p><strong>Order:</strong> #{order_id}</p>
            <p><strong>Kund:</strong> {customer_email}</p>
            <p><strong>Paket:</strong> {package} ({count} stickers)</p>
            <p><strong>Betalat:</strong> {checkout_session.amount_total / 100} kr</p>
            <p><strong>QR-koder:</strong></p>
            <ul>
                {''.join([f'<li>{qr["qr_id"]} - https://returnadisc.se/static/qr/{qr["qr_filename"]}</li>' for qr in qr_codes])}
            </ul>
            <p>Skriv ut QR-koderna och skicka till kunden!</p>
            """
            send_email_async(admin_email, admin_subject, admin_html)
            
            # Mail till kund
            customer_subject = "Din ReturnaDisc beställning är bekräftad!"
            customer_html = f"""
            <h2>Tack för din beställning!</h2>
            <p>Du har beställt {count} QR-klistermärken.</p>
            <p>Dina QR-koder:</p>
            <ul>
                {''.join([f'<li>{qr["qr_id"]}</li>' for qr in qr_codes])}
            </ul>
            <p>Vi skickar dina klistermärken inom 2-3 arbetsdagar.</p>
            """
            send_email_async(customer_email, customer_subject, customer_html)
            
            return render_template('auth/order_confirmation_stripe.html', 
                                 package=package,
                                 count=count,
                                 order_id=order_id,
                                 qr_codes=qr_codes,
                                 email=customer_email)
        else:
            flash('Betalningen är inte slutförd', 'warning')
            return redirect(url_for('auth.buy_stickers'))
            
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