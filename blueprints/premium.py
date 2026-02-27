"""Premium-funktionalitet och betalning."""
import logging
import os
import stripe
from datetime import datetime, timedelta
from flask import (
    Blueprint, render_template, request, redirect, 
    url_for, flash, session, jsonify
)
from functools import wraps

from database import db
from config import Config

logger = logging.getLogger(__name__)

# Stripe konfiguration
stripe.api_key = os.environ.get('STRIPE_SECRET_KEY')

bp = Blueprint('premium', __name__, url_prefix='/premium')


def login_required(f):
    """Decorator som kräver inloggning."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Du måste vara inloggad för att se denna sida.', 'error')
            return redirect(url_for('auth.login'))
        return f(*args, **kwargs)
    return decorated_function


@bp.route('/')
@login_required
def index():
    """Premium-sida med information och köp/aktivering."""
    user_id = session.get('user_id')
    
    # Hämta full premium-status från nya databasstrukturen
    premium_status = db.get_user_premium_status(user_id)
    
    if not premium_status or premium_status.get('error'):
        flash('Kunde inte hämta användarinfo.', 'error')
        return redirect(url_for('auth.index'))
    
    # Kolla om vi är i lanseringsperioden
    is_launch = db.is_launch_period()
    
    # Kan användaren få gratis premium?
    can_get_free = db.can_get_free_premium(user_id)
    
    return render_template('premium/premium_index.html',
                         premium_status=premium_status,
                         is_launch=is_launch,
                         can_get_free=can_get_free,
                         regular_price=39,
                         launch_end_date="1 juli 2026")


@bp.route('/activate-free', methods=['POST'])
@login_required
def activate_free():
    """Aktivera gratis premium under lanseringsperioden."""
    user_id = session.get('user_id')
    
    # Validera att användaren kan få gratis premium
    if not db.can_get_free_premium(user_id):
        if not db.is_launch_period():
            flash('Lanseringsperioden är över. Premium kostar nu 39 kr/år.', 'info')
        else:
            flash('Du kan inte aktivera gratis premium. Kanske har du redan det?', 'error')
        return redirect(url_for('premium.index'))
    
    try:
        # Aktivera gratis premium via nya databasmetoden
        subscription = db.activate_free_launch_premium(user_id)
        
        if subscription:
            logger.info(f"Användare {user_id} aktiverade gratis premium (launch)")
            flash('🎉 Grattis! Du har nu aktiverat gratis Premium till 1 mars 2027!', 'success')
            return redirect(url_for('premium.success'))
        else:
            flash('Kunde inte aktivera premium. Försök igen.', 'error')
            
    except Exception as e:
        logger.error(f"Fel vid aktivering av gratis premium: {e}")
        flash('Ett fel uppstod. Försök igen.', 'error')
    
    return redirect(url_for('premium.index'))


@bp.route('/checkout', methods=['POST'])
@login_required
def checkout():
    """Stripe checkout för premium-betalning."""
    user_id = session.get('user_id')
    
    # Om vi fortfarande är i launch-period och användaren kan få gratis
    if db.is_launch_period() and db.can_get_free_premium(user_id):
        flash('Premium är fortfarande gratis! Aktivera utan kostnad.', 'info')
        return redirect(url_for('premium.index'))
    
    try:
        # Hämta användarens email för Stripe
        user = db.get_user_by_id(user_id)
        customer_email = user.get('email') if user else None
        
        # Skapa Stripe Checkout Session för engångsbetalning (1 år)
        checkout_session = stripe.checkout.Session.create(
            payment_method_types=['card'],
            line_items=[{
                'price_data': {
                    'currency': 'sek',
                    'product_data': {
                        'name': 'ReturnaDisc Premium - 1 år',
                        'description': 'Premium-medlemskap i 1 år. Se alla discar på communitykartan.',
                    },
                    'unit_amount': 3900,  # 39 kr i öre
                },
                'quantity': 1,
            }],
            mode='payment',  # Engångsbetalning (inte subscription)
            success_url=request.host_url + 'premium/success-paid?session_id={CHECKOUT_SESSION_ID}',
            cancel_url=request.host_url + 'premium/',
            metadata={
                'user_id': str(user_id),
                'type': 'premium',
                'duration': '1_year'
            },
            customer_email=customer_email
        )
        
        # Spara session_id i session för verifiering senare
        session['premium_checkout_session'] = checkout_session.id
        
        return redirect(checkout_session.url, code=303)
        
    except Exception as e:
        logger.error(f"Stripe checkout error för premium: {e}")
        flash('Ett fel uppstod vid betalning. Försök igen.', 'error')
        return redirect(url_for('premium.index'))


@bp.route('/success-paid')
@login_required
def success_paid():
    """Hantera lyckad betalning och aktivera premium."""
    user_id = session.get('user_id')
    checkout_session_id = request.args.get('session_id')
    
    if not checkout_session_id:
        flash('Ingen betalningsinformation hittades.', 'error')
        return redirect(url_for('premium.index'))
    
    try:
        # Verifiera betalningen med Stripe
        checkout_session = stripe.checkout.Session.retrieve(checkout_session_id)
        
        if checkout_session.payment_status == 'paid':
            # Kontrollera att detta är rätt användare
            metadata_user_id = checkout_session.metadata.get('user_id')
            if metadata_user_id != str(user_id):
                logger.error(f"User mismatch: {metadata_user_id} vs {user_id}")
                flash('Felaktig betalningsinformation.', 'error')
                return redirect(url_for('premium.index'))
            
            # Aktivera premium för 1 år
            expires_at = datetime.now() + timedelta(days=365)
            
            # Använd din befintliga activate_premium-metod
            subscription = db.activate_premium(
                user_id=user_id,
                payment_method='stripe',
                payment_id=checkout_session.payment_intent,
                amount=39.0
            )
            
            # Uppdatera expires_at i prenumerationen
            if subscription and subscription.get('id'):
                query = """
                    UPDATE premium_subscriptions 
                    SET expires_at = ? 
                    WHERE id = ?
                """
                db._db.execute(query, (expires_at.isoformat(), subscription.get('id')))
            
            logger.info(f"Premium aktiverat för användare {user_id} via Stripe")
            flash('🎉 Tack för ditt köp! Premium är nu aktiverat i 1 år.', 'success')
            
            # Rensa checkout session
            session.pop('premium_checkout_session', None)
            
            return redirect(url_for('premium.success'))
        else:
            flash('Betalningen är inte slutförd.', 'warning')
            return redirect(url_for('premium.index'))
            
    except Exception as e:
        logger.error(f"Fel vid hantering av premium-betalning: {e}")
        flash('Ett fel uppstod vid aktivering av premium.', 'error')
        return redirect(url_for('premium.index'))


@bp.route('/success')
@login_required
def success():
    """Sida som visas efter lyckad aktivering (gratis eller betald)."""
    user_id = session.get('user_id')
    premium_status = db.get_user_premium_status(user_id)
    
    if not premium_status.get('has_premium'):
        flash('Ingen premium hittades.', 'error')
        return redirect(url_for('premium.index'))
    
    return render_template('premium/success.html',
                         premium_status=premium_status,
                         is_launch=db.is_launch_period())


@bp.route('/manage')
@login_required
def manage():
    """Hantera befintligt premium."""
    user_id = session.get('user_id')
    premium_status = db.get_user_premium_status(user_id)
    
    if not premium_status.get('has_premium'):
        flash('Du har inte premium ännu.', 'info')
        return redirect(url_for('premium.index'))
    
    return render_template('premium/manage.html',
                         premium_status=premium_status,
                         is_launch=db.is_launch_period())


@bp.route('/cancel', methods=['POST'])
@login_required
def cancel():
    """Avbryt premium-prenumeration - behåll till periodens slut."""
    user_id = session.get('user_id')
    
    try:
        # Hämta aktiv prenumeration
        query = """
            SELECT * FROM premium_subscriptions 
            WHERE user_id = ? AND status = 'active'
            ORDER BY created_at DESC 
            LIMIT 1
        """
        active_sub = db._db.fetch_one(query, (user_id,))
        
        if not active_sub:
            flash('Du har ingen aktiv prenumeration.', 'info')
            return redirect(url_for('premium.manage'))
        
        # Markera som cancelled men behåll expires_at oförändrad
        update_query = """
            UPDATE premium_subscriptions 
            SET status = 'cancelled'
            WHERE id = ? AND user_id = ?
        """
        db._db.execute(update_query, (active_sub['id'], user_id))
        
        logger.info(f"Premium markerat som avbrutet för användare {user_id}, giltigt till {active_sub.get('expires_at')}")
        flash('Din prenumeration är avbruten. Du behåller premium-funktionerna till periodens slut.', 'success')
        
        return redirect(url_for('premium.manage'))
        
    except Exception as e:
        logger.error(f"Fel vid avbrytande av premium: {e}")
        flash('Ett fel uppstod. Kontakta support.', 'error')
        return redirect(url_for('premium.manage'))


@bp.route('/reactivate', methods=['POST'])
@login_required
def reactivate():
    """Återaktivera avbruten premium-prenumeration."""
    user_id = session.get('user_id')
    
    try:
        # Hämta avbruten prenumeration som fortfarande är giltig
        query = """
            SELECT * FROM premium_subscriptions 
            WHERE user_id = ? AND status = 'cancelled'
            AND (expires_at IS NULL OR expires_at > CURRENT_TIMESTAMP)
            ORDER BY created_at DESC 
            LIMIT 1
        """
        cancelled_sub = db._db.fetch_one(query, (user_id,))
        
        if not cancelled_sub:
            flash('Ingen avbruten prenumeration hittades.', 'info')
            return redirect(url_for('premium.manage'))
        
        # Återaktivera prenumerationen
        update_query = """
            UPDATE premium_subscriptions 
            SET status = 'active'
            WHERE id = ? AND user_id = ?
        """
        db._db.execute(update_query, (cancelled_sub['id'], user_id))
        
        logger.info(f"Premium återaktiverat för användare {user_id}")
        flash('Din prenumeration är återaktiverad!', 'success')
        
        return redirect(url_for('premium.manage'))
        
    except Exception as e:
        logger.error(f"Fel vid återaktivering av premium: {e}")
        flash('Ett fel uppstod. Kontakta support.', 'error')
        return redirect(url_for('premium.manage'))


@bp.route('/status')
@login_required
def status():
    """API-endpoint för att kolla premium-status (JSON)."""
    user_id = session.get('user_id')
    premium_status = db.get_user_premium_status(user_id)
    return jsonify(premium_status)


@bp.route('/webhook', methods=['POST'])
def webhook():
    """Webhook för Stripe betalningshändelser."""
    payload = request.get_data()
    sig_header = request.headers.get('Stripe-Signature', '')
    webhook_secret = os.environ.get('STRIPE_WEBHOOK_SECRET', '')
    
    try:
        event = stripe.Webhook.construct_event(
            payload, sig_header, webhook_secret
        )
        
        # Hantera olika event-typer
        if event['type'] == 'checkout.session.completed':
            session_data = event['data']['object']
            metadata = session_data.get('metadata', {})
            
            if metadata.get('type') == 'premium':
                user_id = int(metadata.get('user_id'))
                # Dubbelkolla att premium inte redan aktiverats
                premium_status = db.get_user_premium_status(user_id)
                if not premium_status.get('has_premium'):
                    expires_at = datetime.now() + timedelta(days=365)
                    db.activate_premium(
                        user_id=user_id,
                        payment_method='stripe',
                        payment_id=session_data.get('payment_intent'),
                        amount=39.0
                    )
                    logger.info(f"Premium aktiverat via webhook för användare {user_id}")
        
        return jsonify({'status': 'success'}), 200
        
    except ValueError as e:
        # Ogiltig payload
        logger.error(f"Invalid webhook payload: {e}")
        return jsonify({'error': 'Invalid payload'}), 400
    except stripe.error.SignatureVerificationError as e:
        # Ogiltig signatur
        logger.error(f"Invalid webhook signature: {e}")
        return jsonify({'error': 'Invalid signature'}), 400
    except Exception as e:
        logger.error(f"Webhook error: {e}")
        return jsonify({'error': 'Server error'}), 500
        