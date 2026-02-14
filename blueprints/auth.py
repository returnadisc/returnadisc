"""Autentisering och användarhantering."""
import logging
import secrets
import os
from dataclasses import dataclass
from typing import Optional, Dict, List, Callable
from functools import wraps

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
    
    @classmethod
    def validate_checkout_form(cls, form: Dict) -> Dict:
        """Validera checkout-formulär."""
        required = ['name', 'email', 'address', 'postal_code', 'city', 'package']
        missing = [f for f in required if not form.get(f)]
        
        if missing:
            raise ValidationError(f"Fyll i alla obligatoriska fält: {', '.join(missing)}")
        
        config = cls.validate_package(form.get('package'))
        
        try:
            count = int(form.get('count', 0))
        except ValueError:
            raise ValidationError("Ogiltigt antal.")
        
        if count != config['count']:
            raise ValidationError("Ogiltigt paket eller antal.")
        
        return {
            'name': form.get('name').strip(),
            'email': form.get('email').strip().lower(),
            'phone': form.get('phone', '').strip(),
            'address': form.get('address').strip(),
            'postal_code': form.get('postal_code').strip(),
            'city': form.get('city').strip(),
            'package': form.get('package'),
            'count': count,
            'price': config['price']
        }


class QRGenerationService:
    """Generering av QR-koder för ordrar."""
    
    MAX_ATTEMPTS = 10
    
    def __init__(self, database: Database):
        self.db = database
    
    def generate_batch(self, count: int) -> List[Dict]:
        """
        Generera batch med QR-koder.
        
        Returns:
            Lista med dicts innehållande 'qr_id' och 'qr_filename'
        """
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
            
            # Kolla om redan finns (race condition-skydd)
            if self.db.get_qr(qr_id):
                continue
            
            # Skapa i databasen
            if not self.db.create_qr(qr_id):
                continue
            
            # Generera bild
            try:
                qr_filename = create_qr_code(qr_id, None)
                return {'qr_id': qr_id, 'qr_filename': qr_filename}
            except Exception as e:
                logger.error(f"Kunde inte skapa QR-bild för {qr_id}: {e}")
                continue
        
        return None


class OrderService:
    """Hantering av beställningsflödet."""
    
    def __init__(
        self, 
        database: Database,
        qr_service: QRGenerationService,
        session_service: SessionService
    ):
        self.db = database
        self.qr_service = qr_service
        self.session = session_service
    
    def process_checkout(self, form_data: Dict) -> OrderData:
        """
        Bearbeta en komplett checkout.
        
        Flow:
        1. Validera input
        2. Generera QR-koder
        3. Generera PDF
        4. Skicka email
        5. Spara i session
        
        Returns:
            OrderData för bekräftelse
        """
        # 1. Validera
        validated = ValidationService.validate_checkout_form(form_data)
        
        # 2. Generera QR-koder
        qr_codes = self.qr_service.generate_batch(validated['count'])
        qr_ids = [q['qr_id'] for q in qr_codes]
        
        # 3. Skapa order
        order = OrderData(
            order_id=secrets.token_hex(8).upper(),
            package=validated['package'],
            count=validated['count'],
            price=validated['price'],
            qr_codes=qr_ids,
            email=validated['email']
        )
        
        # 4. Generera PDF
        try:
            pdf_path = generate_qr_pdf_for_order(qr_codes, Config.PUBLIC_URL)
            order.pdf_path = pdf_path
        except Exception as e:
            logger.error(f"PDF generation failed: {e}")
        
        # 5. Skicka email
        self._send_confirmation_email(order, qr_codes)
        
        # 6. Spara i session
        self.session.save_order(order)
        
        return order
    
    def _send_confirmation_email(self, order: OrderData, qr_codes: List[Dict]) -> None:
        """Skicka bekräftelsemail."""
        qr_list_html = ''.join([f'<li>{q["qr_id"]}</li>' for q in qr_codes])
        
        html_content = f'''
        <h2>Tack för din beställning!</h2>
        <p>Ordernummer: <strong>#{order.order_id}</strong></p>
        <p>Dina QR-koder:</p>
        <ul>{qr_list_html}</ul>
        <p><strong>Viktigt:</strong> Dina QR-koder är ännu inte aktiverade. 
        Besök <a href="{Config.BASE_URL}/signup-with-qr/{order.order_id}">denna länk</a> 
        för att skapa konto och aktivera dem.</p>
        <p>Eller gå till returnadisc.se och klicka på "Jag har köpt stickers" 
        när du vill aktivera.</p>
        '''
        
        send_email_async(
            order.email,
            'Dina ReturnaDisc QR-koder är redo! - ReturnaDisc',
            html_content
        )
    
    def get_or_regenerate_pdf(self, order: OrderData) -> Optional[str]:
        """Hämta befintlig PDF eller generera ny."""
        if order.pdf_path and os.path.exists(order.pdf_path):
            return order.pdf_path
        
        # Generera ny
        qr_codes = [{'qr_id': qid} for qid in order.qr_codes]
        try:
            return generate_qr_pdf_for_order(qr_codes, Config.PUBLIC_URL)
        except Exception as e:
            logger.error(f"PDF regeneration failed: {e}")
            return None


class AuthService:
    """Hantering av autentisering."""
    
    def __init__(self, database: Database):
        self.db = database
    
    def register(self, name: str, email: str, password: str) -> int:
        """
        Registrera ny användare.
        
        Returns:
            user_id
            
        Raises:
            ValidationError om email redan finns
        """
        registration = UserRegistration(name, email, password)
        registration.validate()
        
        if self.db.get_user_by_email(email):
            raise ValidationError("Det finns redan ett konto med den emailen.")
        
        password_hash = generate_password_hash(password)
        return self.db.create_user(name, email, password_hash)
    
    def register_with_qr(
        self, 
        name: str, 
        email: str, 
        password: str,
        qr_id: str,
        valid_qr_codes: List[str]
    ) -> int:
        """
        Registrera användare och aktivera QR-kod.
        
        Returns:
            user_id
        """
        # Validera att QR-koden tillhör ordern
        if qr_id not in valid_qr_codes:
            raise AuthError("Ogiltig QR-kod för denna order.")
        
        # Kolla att QR-koden finns och inte är aktiverad
        qr = self.db.get_qr(qr_id)
        if not qr:
            raise AuthError("QR-koden hittades inte.")
        if qr.get('is_active'):
            raise AuthError("Denna QR-kod är redan aktiverad.")
        if qr.get('user_id') is not None:
            raise AuthError("Denna QR-kod tillhör någon annan.")
        
        # Skapa användare
        user_id = self.register(name, email, password)
        
        # Aktivera QR-koden
        self.db.activate_qr(qr_id, user_id)
        
        return user_id
    
    def login(self, email: str, password: str) -> Optional[Dict]:
        """
        Logga in användare.
        
        Returns:
            User dict om lyckad, None annars
        """
        user = self.db.get_user_by_email(email)
        if not user:
            return None
        
        if not check_password_hash(user['password'], password):
            return None
        
        # Uppdatera senaste inloggning
        self.db.update_last_login(user['id'])
        
        return user
    
    def activate_qr_for_existing_user(self, user_id: int, qr_id: str) -> None:
        """
        Aktivera QR-kod på befintligt konto.
        """
        qr = self.db.get_qr(qr_id)
        
        if not qr:
            raise ValidationError("QR-koden hittades inte.")
        
        if qr.get('is_active'):
            raise ValidationError("Denna QR-kod är redan aktiverad.")
        
        if qr.get('user_id') is not None:
            raise ValidationError("Denna QR-kod tillhör någon annan.")
        
        self.db.activate_qr(qr_id, user_id)
    
    def initiate_password_reset(self, email: str) -> bool:
        """
        Starta lösenordsåterställning.
        
        Returns:
            True om användare finns (oavsett om mailet skickas)
        """
        user = self.db.get_user_by_email(email)
        if not user:
            return False
        
        token = secrets.token_urlsafe(32)
        self.db.set_reset_token(email, token)
        
        reset_link = f"{Config.BASE_URL}/reset-password/{token}"
        send_email_async(
            email,
            'Återställ ditt lösenord - ReturnaDisc',
            f'<p>Klicka <a href="{reset_link}">här</a> för att återställa.</p>'
        )
        
        return True
    
    def reset_password(self, token: str, new_password: str) -> bool:
        """
        Återställ lösenord med token.
        
        Returns:
            True om lyckad
        """
        if len(new_password) < 6:
            raise ValidationError("Minst 6 tecken.")
        
        user = self.db.get_user_by_token(token)
        if not user:
            return False
        
        password_hash = generate_password_hash(new_password)
        self.db.update_password(user['id'], password_hash)
        
        return True


# ============================================================================
# Decorators
# ============================================================================

def require_order(f: Callable) -> Callable:
    """Decorator som kräver giltig order i session."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        order_id = kwargs.get('order_id')
        if not order_id:
            flash('Order ID saknas.', 'error')
            return redirect(url_for('auth.index'))
        
        if not SessionService.validate_order_access(order_id):
            flash('Order hittades inte.', 'error')
            return redirect(url_for('auth.index'))
        
        return f(*args, **kwargs)
    return decorated_function


def handle_auth_errors(f: Callable) -> Callable:
    """Decorator som fångar auth-fel och visar flash-meddelanden."""
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
        except OrderError as e:
            logger.error(f"Order error: {e}")
            flash(str(e), 'error')
            return redirect(url_for('auth.buy_stickers'))
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
        
        # Skapa användare med QR (endast ett anrop nu!)
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


# ============================================================================
# Routes - Lösenord
# ============================================================================

@bp.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    """Glömt lösenord."""
    if request.method == 'POST':
        email = request.form.get('email', '').strip().lower()
        
        auth_service = AuthService(db)
        auth_service.initiate_password_reset(email)
        
        # Samma meddelande oavsett om användare finns (säkerhet)
        flash('Om kontot finns har vi skickat en reset-länk.', 'info')
        return redirect(url_for('auth.login'))
    
    return render_template('auth/forgot_password.html')


@bp.route('/reset-password/<token>', methods=['GET', 'POST'])
@handle_auth_errors
def reset_password(token):
    """Återställ lösenord."""
    if request.method == 'POST':
        password = request.form.get('password', '').strip()
        
        auth_service = AuthService(db)
        
        if auth_service.reset_password(token, password):
            flash('Lösenord uppdaterat!', 'success')
            return redirect(url_for('auth.login'))
        
        flash('Ogiltig länk.', 'error')
        return redirect(url_for('auth.login'))
    
    return render_template('auth/reset_password.html', token=token)


# ============================================================================
# Routes - Beställning (Checkout)
# ============================================================================

@bp.route('/buy-stickers-checkout', methods=['POST'])
def buy_stickers_checkout():
    """Hantera val av paket från buy_stickers sidan."""
    package = request.form.get('package')
    
    try:
        config = ValidationService.validate_package(package)
        session['order_package'] = package
        session['order_count'] = config['count']
        session['order_price'] = config['price']
    except ValidationError:
        flash('Ogiltigt paket.', 'error')
        return redirect(url_for('auth.buy_stickers'))
    
    return redirect(url_for('auth.checkout'))


@bp.route('/checkout', methods=['GET', 'POST'])
@handle_auth_errors
def checkout():
    """Checkout-sida för beställning."""
    order_service = OrderService(
        db, 
        QRGenerationService(db),
        SessionService
    )
    
    if request.method == 'POST':
        form_data = {
            'name': request.form.get('name'),
            'email': request.form.get('email'),
            'phone': request.form.get('phone'),
            'address': request.form.get('address'),
            'postal_code': request.form.get('postal_code'),
            'city': request.form.get('city'),
            'package': request.form.get('package'),
            'count': request.form.get('count')
        }
        
        order = order_service.process_checkout(form_data)
        return redirect(url_for('auth.order_confirmation', order_id=order.order_id))
    
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
@require_order
def order_confirmation(order_id):
    """Orderbekräftelse efter köp."""
    order = SessionService.get_order()
    
    qr_codes = []
    for qr_id in order.qr_codes:
        qr = db.get_qr(qr_id)
        if qr:
            qr_codes.append(qr)
    
    return render_template('auth/order_confirmation.html',
                         order_id=order_id,
                         qr_codes=qr_codes,
                         total_price=order.price)


@bp.route('/download-order-pdf/<order_id>')
@require_order
def download_order_pdf(order_id):
    """Ladda ner PDF för order."""
    order = SessionService.get_order()
    order_service = OrderService(db, QRGenerationService(db), SessionService)
    
    pdf_path = order_service.get_or_regenerate_pdf(order)
    
    if not pdf_path:
        flash('Kunde inte generera PDF.', 'error')
        return redirect(url_for('auth.order_confirmation', order_id=order_id))
    
    # Säkerhet: Validera att path är inom PDF_FOLDER
    pdf_folder = current_app.config.get('PDF_FOLDER', 'static/pdfs')
    full_path = os.path.abspath(pdf_path)
    allowed_folder = os.path.abspath(pdf_folder)
    
    if not full_path.startswith(allowed_folder):
        logger.warning(f"Försök till path traversal: {pdf_path}")
        flash('Ogiltig fil.', 'error')
        return redirect(url_for('auth.index'))
    
    return send_file(
        full_path, 
        as_attachment=True,
        download_name=f'returnadisc-order-{order_id}.pdf'
    )


# ============================================================================
# Routes - QR-aktivering
# ============================================================================

@bp.route('/signup-with-qr/<order_id>', methods=['GET', 'POST'])
@require_order
@handle_auth_errors
def signup_with_qr(order_id):
    """Skapa konto och aktivera QR-kod från order."""
    order = SessionService.get_order()
    
    if request.method == 'POST':
        name = request.form.get('name', '').strip()
        email = request.form.get('email', '').strip().lower()
        password = request.form.get('password', '').strip()
        submitted_qr_id = request.form.get('qr_id', '').strip().upper()
        
        # Använd submitted eller första från ordern
        target_qr_id = submitted_qr_id or order.qr_codes[0]
        
        auth_service = AuthService(db)
        user_id = auth_service.register_with_qr(
            name, email, password, target_qr_id, order.qr_codes
        )
        
        # Logga in
        session['user_id'] = user_id
        session.permanent = True
        
        # Rensa order-session (frivilligt - kan behållas för fler QR-koder)
        # SessionService.clear_order()
        
        flash('Välkommen! Din QR-kod är nu aktiverad.', 'success')
        return redirect(url_for('disc.dashboard'))
    
    # Hämta första QR-koden för visning
    first_qr = db.get_qr(order.qr_codes[0]) if order.qr_codes else None
    
    return render_template('auth/signup_with_qr.html',
                         order_id=order_id,
                         qr_code=first_qr)


@bp.route('/activate-later/<order_id>')
def activate_later(order_id):
    """Sida som förklarar hur man aktiverar senare."""
    return render_template('auth/activate_later.html', order_id=order_id)


@bp.route('/activate-existing', methods=['GET', 'POST'])
@handle_auth_errors
def activate_existing():
    """Aktivera QR-kod på befintligt konto."""
    if 'user_id' not in session:
        flash('Logga in först.', 'error')
        return redirect(url_for('auth.login'))
    
    if request.method == 'POST':
        qr_id = request.form.get('qr_id', '').strip().upper()
        
        auth_service = AuthService(db)
        auth_service.activate_qr_for_existing_user(session['user_id'], qr_id)
        
        flash('Din QR-kod är nu aktiverad!', 'success')
        return redirect(url_for('disc.dashboard'))
    
    qr_id = request.args.get('qr_id', '')
    return render_template('auth/activate_qr_page.html', prefilled_qr=qr_id)
    
    
    
import stripe
import os

# Stripe konfiguration
stripe.api_key = os.environ.get('STRIPE_SECRET_KEY')

@bp.route('/checkout', methods=['POST'])
def checkout():
    """Stripe checkout session."""
    try:
        package = request.form.get('package')
        count = int(request.form.get('count', 10))
        
        # Priser i ören (SEK)
        prices = {
            'start': 5900,      # 59 kr
            'standard': 9900,   # 99 kr
            'pro': 17900        # 179 kr
        }
        
        price = prices.get(package, 5900)
        
        # Skapa Stripe checkout session
        session = stripe.checkout.Session.create(
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
            success_url=request.host_url + 'order-confirmation?session_id={CHECKOUT_SESSION_ID}',
            cancel_url=request.host_url + 'buy-stickers',
            metadata={
                'package': package,
                'count': str(count),
            }
        )
        
        return redirect(session.url, code=303)
        
    except Exception as e:
        logger.error(f"Stripe checkout error: {e}")
        flash('Ett fel uppstod vid betalning. Försök igen.', 'error')
        return redirect(url_for('auth.buy_stickers'))


@bp.route('/order-confirmation')
def order_confirmation():
    """Visa orderbekräftelse och skicka mail till admin."""
    session_id = request.args.get('session_id')
    
    if not session_id:
        flash('Ingen order hittades', 'error')
        return redirect(url_for('auth.index'))
    
    try:
        # Hämta session från Stripe
        session = stripe.checkout.Session.retrieve(session_id)
        
        if session.payment_status == 'paid':
            package = session.metadata.get('package')
            count = session.metadata.get('count')
            
            # Här ska vi skicka mail till dig med orderinfo
            # TODO: Lägg till mail-funktion
            
            return render_template('auth/order_confirmation.html', 
                                 package=package, 
                                 count=count,
                                 email=session.customer_details.email if session.customer_details else None)
        else:
            flash('Betalningen är inte slutförd', 'warning')
            return redirect(url_for('auth.buy_stickers'))
            
    except Exception as e:
        logger.error(f"Order confirmation error: {e}")
        flash('Ett fel uppstod', 'error')
        return redirect(url_for('auth.index'))
        
        
import stripe
import os
from flask import url_for, redirect, request, render_template, flash
from utils import send_email_async, create_qr_code, generate_random_qr_id

# Stripe konfiguration
stripe.api_key = os.environ.get('STRIPE_SECRET_KEY')

@bp.route('/checkout', methods=['POST'])
def checkout():
    """Stripe checkout för stickers."""
    try:
        package = request.form.get('package')
        count = int(request.form.get('count', 10))
        
        # Priser i ören (SEK)
        prices = {
            'start': 5900,      # 59 kr
            'standard': 9900,   # 99 kr
            'pro': 17900        # 179 kr
        }
        
        price = prices.get(package, 5900)
        
        # Skapa Stripe checkout session
        session = stripe.checkout.Session.create(
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
        
        return redirect(session.url, code=303)
        
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
        # Hämta session från Stripe
        session = stripe.checkout.Session.retrieve(session_id)
        
        if session.payment_status == 'paid':
            package = session.metadata.get('package')
            count = int(session.metadata.get('count', 10))
            customer_email = session.customer_details.email if session.customer_details else 'okänd'
            
            # Generera QR-koder för ordern
            qr_codes = []
            for i in range(count):
                qr_id = generate_random_qr_id()
                create_qr_code(qr_id)
                qr_codes.append({'qr_id': qr_id})
            
            # Skapa order i databasen (simplified)
            order_id = f"STRIPE-{session_id[:8].upper()}"
            
            # SKICKA MAIL TILL DIG (ADMIN)
            admin_email = os.environ.get('ADMIN_EMAIL', 'din-email@example.com')
            admin_subject = f"NY BETALNING - ReturnaDisc Order #{order_id}"
            admin_html = f"""
            <h2>Ny betalning mottagen!</h2>
            <p><strong>Order:</strong> #{order_id}</p>
            <p><strong>Kund:</strong> {customer_email}</p>
            <p><strong>Paket:</strong> {package} ({count} stickers)</p>
            <p><strong>Betalat:</strong> {session.amount_total / 100} kr</p>
            <p><strong>QR-koder:</strong></p>
            <ul>
                {''.join([f'<li>{qr["qr_id"]} - https://returnadisc.se/static/qr/qr_{qr["qr_id"]}.png</li>' for qr in qr_codes])}
            </ul>
            <p>Skriv ut QR-koderna och skicka till kunden!</p>
            """
            send_email_async(admin_email, admin_subject, admin_html)
            
            # Skicka mail till kund
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
    import os
    from flask import send_file
    
    qr_folder = os.environ.get('QR_FOLDER', 'static/qr')
    filepath = os.path.join(qr_folder, f"qr_{qr_id}.png")
    
    if os.path.exists(filepath):
        return send_file(filepath, as_attachment=True, download_name=f'returnadisc_{qr_id}.png')
    else:
        flash(f'QR-kod {qr_id} hittades inte', 'error')
        return redirect(url_for('auth.index'))