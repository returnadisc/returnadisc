"""Premium-funktionalitet med Stripe Subscription."""
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
stripe.api_key = os.environ.get('STRIPE_SECRET_KEY')

bp = Blueprint('premium', __name__, url_prefix='/premium')


def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Du måste vara inloggad.', 'error')
            return redirect(url_for('auth.login'))
        return f(*args, **kwargs)
    return decorated_function


@bp.route('/')
@login_required
def index():
    """Premium-sida."""
    user_id = session.get('user_id')
    premium_status = db.get_user_premium_status(user_id)
    is_launch = datetime.now() < datetime(2026, 7, 1)
    can_get_free = is_launch and not premium_status.get('has_premium')
    
    return render_template('premium/premium_index.html',
                         premium_status=premium_status,
                         is_launch=is_launch,
                         can_get_free=can_get_free,
                         launch_end_date="1 juli 2026")


@bp.route('/checkout', methods=['POST'])
@login_required
def checkout():
    """Stripe Checkout för prenumeration."""
    user_id = session.get('user_id')
    user = db.get_user_by_id(user_id)
    
    if not user:
        flash('Användare hittades inte.', 'error')
        return redirect(url_for('premium.index'))
    
    price_id = Config.STRIPE_PREMIUM_PRICE_ID
    if not price_id:
        flash('Premium är inte konfigurerat.', 'error')
        return redirect(url_for('premium.index'))
    
    try:
        # Räkna ut trial-dagar till 1 mars 2027 om kampanj
        is_launch = datetime.now() < datetime(2026, 7, 1)
        trial_days = None
        
        if is_launch:
            target_date = datetime(2027, 3, 1)
            trial_days = (target_date - datetime.now()).days
        
        checkout_params = {
            'payment_method_types': ['card'],
            'line_items': [{'price': price_id, 'quantity': 1}],
            'mode': 'subscription',
            'success_url': request.host_url + 'premium/success?session_id={CHECKOUT_SESSION_ID}',
            'cancel_url': request.host_url + 'premium/',
            'metadata': {'user_id': str(user_id)},
            'customer_email': user.get('email')
        }
        
        if trial_days and trial_days > 0:
            checkout_params['subscription_data'] = {'trial_period_days': trial_days}
        
        checkout_session = stripe.checkout.Session.create(**checkout_params)
        return redirect(checkout_session.url, code=303)
        
    except Exception as e:
        logger.error(f"Stripe checkout error: {e}")
        flash('Ett fel uppstod.', 'error')
        return redirect(url_for('premium.index'))


@bp.route('/success')
@login_required
def success():
    """Efter lyckad betalning."""
    session_id = request.args.get('session_id')
    user_id = session.get('user_id')
    
    if not session_id:
        flash('Ingen betalningsinfo hittades.', 'error')
        return redirect(url_for('premium.index'))
    
    try:
        checkout_session = stripe.checkout.Session.retrieve(session_id)
        
        if not checkout_session.subscription:
            flash('Ingen prenumeration hittades.', 'error')
            return redirect(url_for('premium.index'))
        
        subscription = stripe.Subscription.retrieve(checkout_session.subscription)
        
        # Hämta current_period_end från subscription
        period_end = subscription.get('current_period_end')
        if period_end:
            expires_at = datetime.fromtimestamp(period_end)
        else:
            # Fallback: 1 år från nu
            expires_at = datetime.now() + timedelta(days=365)
        
        db.activate_premium_subscription(
            user_id=user_id,
            stripe_subscription_id=subscription.id,
            stripe_customer_id=checkout_session.customer,
            expires_at=expires_at,
            is_launch_offer=bool(subscription.get('trial_end'))
        )
        
        flash('🎉 Premium aktiverat!', 'success')
        return render_template('premium/success.html')
        
    except Exception as e:
        logger.error(f"Fel i success: {e}")
        flash('Ett fel uppstod.', 'error')
        return redirect(url_for('premium.index'))


@bp.route('/manage')
@login_required
def manage():
    """Hantera prenumeration."""
    user_id = session.get('user_id')
    premium_status = db.get_user_premium_status(user_id)
    
    if not premium_status.get('has_premium'):
        flash('Du har inte premium.', 'info')
        return redirect(url_for('premium.index'))
    
    return render_template('premium/manage.html', premium_status=premium_status)


@bp.route('/cancel', methods=['POST'])
@login_required
def cancel():
    """Avbryt prenumeration - behåll till periodens slut."""
    user_id = session.get('user_id')
    
    try:
        sub = db.get_stripe_subscription(user_id)
        if sub and sub.get('stripe_subscription_id'):
            # Avbryt i Stripe (men behåll till periodens slut)
            stripe.Subscription.modify(
                sub['stripe_subscription_id'],
                cancel_at_period_end=True
            )
            # Markera i databasen att den avbryts vid periodens slut
            db.update_cancel_at_period_end(user_id, True)
            logger.info(f"Prenumeration markerad för avbrytning för användare {user_id}")
            flash('Din prenumeration avbryts vid periodens slut. Du behåller premium till dess.', 'success')
        else:
            flash('Ingen aktiv prenumeration hittades.', 'error')
    except Exception as e:
        logger.error(f"Fel vid avbrytning: {e}")
        flash('Ett fel uppstod.', 'error')
    
    return redirect(url_for('premium.manage'))


@bp.route('/webhook', methods=['POST'])
def webhook():
    """Stripe webhook."""
    payload = request.get_data()
    sig_header = request.headers.get('Stripe-Signature', '')
    webhook_secret = os.environ.get('STRIPE_WEBHOOK_SECRET', '')
    
    try:
        if webhook_secret:
            event = stripe.Webhook.construct_event(
                payload, sig_header, webhook_secret
            )
        else:
            import json
            event = json.loads(payload)
        
        event_type = event.get('type')
        data = event.get('data', {}).get('object', {})
        
        # Hantera första betalningen (checkout)
        if event_type == 'checkout.session.completed':
            metadata = data.get('metadata', {})
            if metadata.get('type') == 'premium':
                user_id = int(metadata.get('user_id'))
                subscription_id = data.get('subscription')
                
                if subscription_id:
                    subscription = stripe.Subscription.retrieve(subscription_id)
                    db.activate_premium_subscription(
                        user_id=user_id,
                        stripe_subscription_id=subscription.id,
                        stripe_customer_id=data.get('customer'),
                        expires_at=datetime.fromtimestamp(subscription.current_period_end),
                        is_launch_offer=bool(subscription.get('trial_end'))
                    )
                    logger.info(f"Premium aktiverat via checkout för {user_id}")
        
        # Hantera automatisk förnyelse (varje år)
        elif event_type == 'invoice.payment_succeeded':
            subscription_id = data.get('subscription')
            if subscription_id:
                subscription = stripe.Subscription.retrieve(subscription_id)
                
                # Hitta användare baserat på subscription_id
                user = db.get_user_by_stripe_subscription(subscription_id)
                if user:
                    # Förläng premium med 1 år
                    new_expires = datetime.fromtimestamp(subscription.current_period_end)
                    db.extend_premium(user['id'], new_expires)
                    logger.info(f"Premium förnyat för {user['id']} till {new_expires}")
        
        # Hantera misslyckad betalning
        elif event_type == 'invoice.payment_failed':
            subscription_id = data.get('subscription')
            if subscription_id:
                user = db.get_user_by_stripe_subscription(subscription_id)
                if user:
                    db.cancel_subscription(user['id'])
                    logger.info(f"Premium avbrutet för {user['id']} pga misslyckad betalning")
        
        return jsonify({'status': 'success'}), 200
        
    except Exception as e:
        logger.error(f"Webhook error: {e}")
        return jsonify({'status': 'received'}), 200