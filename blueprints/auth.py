"""Autentisering."""
import logging
from flask import Blueprint, render_template, request, redirect, url_for, flash, session
from werkzeug.security import generate_password_hash, check_password_hash

from database import db
from utils import send_email_async
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