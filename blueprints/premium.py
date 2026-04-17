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
from utils import send_email_async

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
    
    # Kolla om det är .com eller .se för att visa rätt pris
    host = request.host.lower()
    is_com = 'returnadisc.com' in host
    
    if is_com:
        price_display = '$4.99/year'
        currency = 'usd'
    else:
        price_display = '39 kr/år'
        currency = 'sek'
    
    return render_template('premium/premium_index.html',
                         premium_status=premium_status,
                         is_launch=is_launch,
                         can_get_free=can_get_free,
                         launch_end_date="1 juli 2026",
                         price_display=price_display,
                         currency=currency)


@bp.route('/checkout', methods=['POST'])
@login_required
def checkout():
    """Stripe Checkout för prenumeration."""
    user_id = session.get('user_id')
    user = db.get_user_by_id(user_id)
    
    if not user:
        flash('Användare hittades inte.', 'error')
        return redirect(url_for('premium.index'))
    
    # Kolla om det är .com eller .se
    host = request.host.lower()
    is_com = 'returnadisc.com' in host
    
    # Välj rätt pris baserat på domän
    price_ids = Config.get_stripe_price_ids(host)
    price_id = price_ids.get('premium')
    currency = price_ids.get('currency', 'sek')
    
    if not price_id:
        flash('Premium är inte konfigurerat för denna domän.', 'error')
        return redirect(url_for('premium.index'))
    
    try:
        is_launch = datetime.now() < datetime(2026, 7, 1)
        
        checkout_params = {
            'payment_method_types': ['card'],
            'line_items': [{'price': price_id, 'quantity': 1}],
            'mode': 'subscription',
            'success_url': request.host_url + 'premium/success?session_id={CHECKOUT_SESSION_ID}',
            'cancel_url': request.host_url + 'premium/',
            'metadata': {
                'user_id': str(user_id), 
                'type': 'premium',
                'domain': 'com' if is_com else 'se',
                'currency': currency
            },
            'customer_email': user.get('email')
        }
        
        # Om lanseringsperiod: 365 dagar gratis trial (1 år)
        if is_launch:
            checkout_params['subscription_data'] = {
                'trial_period_days': 365,
                'metadata': {'is_launch_offer': 'true'}
            }
        
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
        
        # SÄKER HÄMTNING AV ATTRIBUT
        subscription_attr = getattr(checkout_session, 'subscription', None)
        
        if subscription_attr is None:
            flash('Ingen prenumeration hittades.', 'error')
            return redirect(url_for('premium.index'))
        
        # Om det är en sträng, hämta prenumerationen
        if isinstance(subscription_attr, str):
            subscription_id = subscription_attr
        else:
            subscription_id = getattr(subscription_attr, 'id', None)
        
        if not subscription_id:
            flash('Ingen prenumeration hittades.', 'error')
            return redirect(url_for('premium.index'))
        
        # Hämta prenumerationsdetaljer
        subscription = stripe.Subscription.retrieve(subscription_id)
        
        # Hämta metadata säkert
        sub_metadata_obj = getattr(subscription, 'metadata', None)
        if sub_metadata_obj is None:
            sub_metadata = {}
        elif hasattr(sub_metadata_obj, 'to_dict'):
            sub_metadata = sub_metadata_obj.to_dict()
        elif isinstance(sub_metadata_obj, dict):
            sub_metadata = sub_metadata_obj
        else:
            try:
                sub_metadata = dict(sub_metadata_obj)
            except:
                sub_metadata = {}
        
        is_launch_offer = bool(sub_metadata.get('is_launch_offer'))
        
        # Kolla trial_end för att bekräfta launch offer
        trial_end = getattr(subscription, 'trial_end', None)
        if trial_end and not is_launch_offer:
            is_launch_offer = True
        
        # Hämta period_end
        period_end = getattr(subscription, 'current_period_end', None)
        if period_end is None:
            try:
                period_end = subscription['current_period_end']
            except (KeyError, TypeError):
                period_end = None
        
        if period_end:
            expires_at = datetime.fromtimestamp(period_end)
        else:
            expires_at = datetime.now() + timedelta(days=365)
        
        # Hämta customer ID
        customer_attr = getattr(checkout_session, 'customer', None)
        if isinstance(customer_attr, str):
            customer_id = customer_attr
        else:
            customer_id = getattr(customer_attr, 'id', None) if customer_attr else None
        
        # Hämta domän från metadata
        checkout_metadata_obj = getattr(checkout_session, 'metadata', None)
        if checkout_metadata_obj:
            if hasattr(checkout_metadata_obj, 'to_dict'):
                checkout_metadata = checkout_metadata_obj.to_dict()
            elif isinstance(checkout_metadata_obj, dict):
                checkout_metadata = checkout_metadata_obj
            else:
                checkout_metadata = {}
        else:
            checkout_metadata = {}
        
        domain = checkout_metadata.get('domain', 'se')
        
        # SPARA I DATABASEN
        db.activate_premium_subscription(
            user_id=user_id,
            stripe_subscription_id=subscription_id,
            stripe_customer_id=customer_id,
            expires_at=expires_at,
            is_launch_offer=is_launch_offer
        )
        
        # Anpassa meddelande baserat på domän
        if is_launch_offer:
            if domain == 'com':
                flash('🎉 You have activated 1 year of free Premium! After 365 days, $4.99/year will be charged automatically.', 'success')
            else:
                flash('🎉 Du har aktiverat 1 år gratis Premium! Efter 365 dagar dras 39 kr/år automatiskt.', 'success')
        else:
            if domain == 'com':
                flash('🎉 Premium activated!', 'success')
            else:
                flash('🎉 Premium aktiverat!', 'success')
            
        return render_template('premium/success.html', domain=domain)
        
    except Exception as e:
        logger.error(f"Fel i success: {e}")
        logger.exception("Full stacktrace:")
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
    
    # Kolla domän för att visa rätt pris
    host = request.host.lower()
    is_com = 'returnadisc.com' in host
    
    return render_template('premium/manage.html', 
                         premium_status=premium_status,
                         is_com=is_com)


@bp.route('/cancel', methods=['POST'])
@login_required
def cancel():
    """Avbryt prenumeration - behåll till periodens slut."""
    user_id = session.get('user_id')
    
    # Kolla domän för rätt meddelande
    host = request.host.lower()
    is_com = 'returnadisc.com' in host
    
    try:
        sub = db.get_stripe_subscription(user_id)
        if sub and sub.get('stripe_subscription_id'):
            stripe.Subscription.modify(
                sub['stripe_subscription_id'],
                cancel_at_period_end=True
            )
            db.update_cancel_at_period_end(user_id, True)
            logger.info(f"Prenumeration markerad för avbrytning för användare {user_id}")
            
            if is_com:
                flash('Your subscription will be cancelled at the end of the period. You keep premium until then.', 'success')
            else:
                flash('Din prenumeration avbryts vid periodens slut. Du behåller premium till dess.', 'success')
        else:
            if is_com:
                flash('No active subscription found.', 'error')
            else:
                flash('Ingen aktiv prenumeration hittades.', 'error')
    except Exception as e:
        logger.error(f"Fel vid avbrytning: {e}")
        if is_com:
            flash('An error occurred.', 'error')
        else:
            flash('Ett fel uppstod.', 'error')
    
    return redirect(url_for('premium.manage'))


@bp.route('/reactivate', methods=['POST'])
@login_required
def reactivate():
    """Återaktivera prenumeration som ska avbrytas."""
    user_id = session.get('user_id')
    
    # Kolla domän för rätt meddelande
    host = request.host.lower()
    is_com = 'returnadisc.com' in host
    
    try:
        sub = db.get_stripe_subscription(user_id)
        if sub and sub.get('stripe_subscription_id'):
            stripe.Subscription.modify(
                sub['stripe_subscription_id'],
                cancel_at_period_end=False
            )
            db.update_cancel_at_period_end(user_id, False)
            logger.info(f"Prenumeration återaktiverad för {user_id}")
            
            if is_com:
                flash('Your subscription is reactivated!', 'success')
            else:
                flash('Din prenumeration är återaktiverad!', 'success')
        else:
            if is_com:
                flash('No subscription found.', 'error')
            else:
                flash('Ingen prenumeration hittades.', 'error')
    except Exception as e:
        logger.error(f"Fel vid återaktivering: {e}")
        if is_com:
            flash('An error occurred.', 'error')
        else:
            flash('Ett fel uppstod.', 'error')
    
    return redirect(url_for('premium.manage'))


@bp.route('/webhook', methods=['POST'])
def webhook():
    """Stripe webhook - skickar mail här för att vara säker på att det kommer fram."""
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
                domain = metadata.get('domain', 'se')
                
                if subscription_id:
                    subscription = stripe.Subscription.retrieve(subscription_id)
                    is_launch_offer = bool(subscription.get('trial_end'))
                    period_end = subscription.get('current_period_end')
                    
                    if period_end:
                        expires_at = datetime.fromtimestamp(period_end)
                    else:
                        expires_at = datetime.now() + timedelta(days=365)
                    
                    # Aktivera i databasen
                    db.activate_premium_subscription(
                        user_id=user_id,
                        stripe_subscription_id=subscription.id,
                        stripe_customer_id=data.get('customer'),
                        expires_at=expires_at,
                        is_launch_offer=is_launch_offer
                    )
                    
                    # HÄR SKICKAR VI MAILET
                    try:
                        user = db.get_user_by_id(user_id)
                        if user:
                            if is_launch_offer:
                                if domain == 'com':
                                    # Engelskt mail för .com
                                    subject = "🎉 Welcome to ReturnaDisc Premium!"
                                    html_content = f"""
                                    <div style="font-family: Arial, sans-serif; max-width: 600px; color: #333;">
                                        <h2 style="color: #166534;">Hi {user.get('name', '')}!</h2>
                                        
                                        <p style="font-size: 16px;">Thank you for activating <strong>ReturnaDisc Premium</strong>!</p>
                                        
                                        <div style="background: #f0fdf4; padding: 20px; border-radius: 12px; margin: 20px 0; border-left: 4px solid #166534;">
                                            <h3 style="margin-top: 0; color: #166534;">🎉 You got 1 year completely free!</h3>
                                            <p style="margin-bottom: 0;">As a thank you for joining early, you get <strong>365 days of free Premium</strong>.</p>
                                        </div>
                                        
                                        <p style="font-size: 16px;"><strong>Your Premium is active until:</strong><br>
                                        <span style="font-size: 18px; color: #166534; font-weight: bold;">{expires_at.strftime('%Y-%m-%d')}</span></p>
                                        
                                        <p style="font-size: 14px; color: #666; margin-top: 20px;">
                                            <strong>What happens next?</strong><br>
                                            After your free period, the subscription automatically continues at $4.99/year.
                                            You can cancel anytime at <a href="{Config.PUBLIC_URL}/premium/manage" style="color: #166534;">My Premium</a>.
                                        </p>
                                        
                                        <p style="font-size: 14px; margin-top: 30px;">
                                            <strong>With Premium you get:</strong>
                                            <ul style="color: #666;">
                                                <li>Full access to the Community map</li>
                                                <li>Priority support</li>
                                                <li>Early access to new features</li>
                                            </ul>
                                        </p>
                                        
                                        <hr style="border: none; border-top: 1px solid #e5e7eb; margin: 30px 0;">
                                        
                                        <p style="font-size: 14px; color: #666;">
                                            Questions? Contact us at <a href="mailto:info@returnadisc.com" style="color: #166534;">info@returnadisc.com</a>
                                        </p>
                                        
                                        <p style="font-size: 14px;">
                                            Best regards,<br>
                                            <strong>The ReturnaDisc Team</strong>
                                        </p>
                                    </div>
                                    """
                                else:
                                    # Svenskt mail för .se
                                    subject = "🎉 Välkommen till ReturnaDisc Premium!"
                                    html_content = f"""
                                    <div style="font-family: Arial, sans-serif; max-width: 600px; color: #333;">
                                        <h2 style="color: #166534;">Hej {user.get('name', '')}!</h2>
                                        
                                        <p style="font-size: 16px;">Tack för att du aktiverat <strong>ReturnaDisc Premium</strong>!</p>
                                        
                                        <div style="background: #f0fdf4; padding: 20px; border-radius: 12px; margin: 20px 0; border-left: 4px solid #166534;">
                                            <h3 style="margin-top: 0; color: #166534;">🎉 Du har fått 1 år helt gratis!</h3>
                                            <p style="margin-bottom: 0;">Som tack för att du anslöt dig tidigt får du <strong>365 dagars gratis Premium</strong>.</p>
                                        </div>
                                        
                                        <p style="font-size: 16px;"><strong>Ditt Premium är aktivt till:</strong><br>
                                        <span style="font-size: 18px; color: #166534; font-weight: bold;">{expires_at.strftime('%Y-%m-%d')}</span></p>
                                        
                                        <p style="font-size: 14px; color: #666; margin-top: 20px;">
                                            <strong>Vad händer sedan?</strong><br>
                                            Efter din gratisperiod övergår prenumerationen automatiskt till 39 kr/år. 
                                            Du kan avbryta när som helst under <a href="{Config.PUBLIC_URL}/premium/manage" style="color: #166534;">Mitt Premium</a>.
                                        </p>
                                        
                                        <p style="font-size: 14px; margin-top: 30px;">
                                            <strong>Med Premium får du:</strong>
                                            <ul style="color: #666;">
                                                <li>Full tillgång till Community kartan</li>
                                                <li>Prioriterad support</li>
                                                <li>Early access till nya funktioner</li>
                                            </ul>
                                        </p>
                                        
                                        <hr style="border: none; border-top: 1px solid #e5e7eb; margin: 30px 0;">
                                        
                                        <p style="font-size: 14px; color: #666;">
                                            Har du frågor? Kontakta oss på <a href="mailto:info@returnadisc.com" style="color: #166534;">info@returnadisc.com</a>
                                        </p>
                                        
                                        <p style="font-size: 14px;">
                                            Med vänliga hälsningar,<br>
                                            <strong>ReturnaDisc-teamet</strong>
                                        </p>
                                    </div>
                                    """
                            else:
                                # Direkt betalning - anpassa för domän
                                if domain == 'com':
                                    subject = "🎉 Thank you for purchasing ReturnaDisc Premium!"
                                    html_content = f"""
                                    <div style="font-family: Arial, sans-serif; max-width: 600px; color: #333;">
                                        <h2 style="color: #166534;">Hi {user.get('name', '')}!</h2>
                                        
                                        <p style="font-size: 16px;">Thank you for purchasing <strong>ReturnaDisc Premium</strong>!</p>
                                        
                                        <div style="background: #f0fdf4; padding: 20px; border-radius: 12px; margin: 20px 0; border-left: 4px solid #166534;">
                                            <h3 style="margin-top: 0; color: #166534;">Receipt</h3>
                                            <p style="margin: 5px 0;"><strong>Product:</strong> ReturnaDisc Premium (1 year)</p>
                                            <p style="margin: 5px 0;"><strong>Price:</strong> $4.99</p>
                                            <p style="margin: 5px 0;"><strong>Payment method:</strong> Card (Stripe)</p>
                                            <p style="margin: 5px 0;"><strong>Valid until:</strong> {expires_at.strftime('%Y-%m-%d')}</p>
                                        </div>
                                        
                                        <p style="font-size: 14px; color: #666;">
                                            Your subscription renews automatically after 1 year ($4.99/year). 
                                            You can manage or cancel your subscription anytime at 
                                            <a href="{Config.PUBLIC_URL}/premium/manage" style="color: #166534;">My Premium</a>.
                                        </p>
                                        
                                        <p style="font-size: 14px; margin-top: 20px;">
                                            <strong>With Premium you get:</strong>
                                            <ul style="color: #666;">
                                                <li>Full access to the Community map</li>
                                                <li>Priority support</li>
                                                <li>Early access to new features</li>
                                            </ul>
                                        </p>
                                        
                                        <hr style="border: none; border-top: 1px solid #e5e7eb; margin: 30px 0;">
                                        
                                        <p style="font-size: 14px; color: #666;">
                                            Questions? Contact us at <a href="mailto:info@returnadisc.com" style="color: #166534;">info@returnadisc.com</a>
                                        </p>
                                        
                                        <p style="font-size: 14px;">
                                            Best regards,<br>
                                            <strong>The ReturnaDisc Team</strong>
                                        </p>
                                    </div>
                                    """
                                else:
                                    # Svenskt mail
                                    subject = "🎉 Tack för ditt köp av ReturnaDisc Premium!"
                                    html_content = f"""
                                    <div style="font-family: Arial, sans-serif; max-width: 600px; color: #333;">
                                        <h2 style="color: #166534;">Hej {user.get('name', '')}!</h2>
                                        
                                        <p style="font-size: 16px;">Tack för ditt köp av <strong>ReturnaDisc Premium</strong>!</p>
                                        
                                        <div style="background: #f0fdf4; padding: 20px; border-radius: 12px; margin: 20px 0; border-left: 4px solid #166534;">
                                            <h3 style="margin-top: 0; color: #166534;">Kvitto</h3>
                                            <p style="margin: 5px 0;"><strong>Produkt:</strong> ReturnaDisc Premium (1 år)</p>
                                            <p style="margin: 5px 0;"><strong>Pris:</strong> 39 kr</p>
                                            <p style="margin: 5px 0;"><strong>Betalningsmetod:</strong> Kort (Stripe)</p>
                                            <p style="margin: 5px 0;"><strong>Giltigt till:</strong> {expires_at.strftime('%Y-%m-%d')}</p>
                                        </div>
                                        
                                        <p style="font-size: 14px; color: #666;">
                                            Din prenumeration förnyas automatiskt efter 1 år (39 kr/år). 
                                            Du kan hantera eller avbryta din prenumeration när som helst under 
                                            <a href="{Config.PUBLIC_URL}/premium/manage" style="color: #166534;">Mitt Premium</a>.
                                        </p>
                                        
                                        <p style="font-size: 14px; margin-top: 20px;">
                                            <strong>Med Premium får du:</strong>
                                            <ul style="color: #666;">
                                                <li>Full tillgång till Community kartan</li>
                                                <li>Prioriterad support</li>
                                                <li>Early access till nya funktioner</li>
                                            </ul>
                                        </p>
                                        
                                        <hr style="border: none; border-top: 1px solid #e5e7eb; margin: 30px 0;">
                                        
                                        <p style="font-size: 14px; color: #666;">
                                            Har du frågor? Kontakta oss på <a href="mailto:info@returnadisc.com" style="color: #166534;">info@returnadisc.com</a>
                                        </p>
                                        
                                        <p style="font-size: 14px;">
                                            Med vänliga hälsningar,<br>
                                            <strong>ReturnaDisc-teamet</strong>
                                        </p>
                                    </div>
                                    """
                            
                            send_email_async(user.get('email'), subject, html_content)
                            logger.info(f"Premium bekräftelsemail skickat till {user.get('email')} via webhook")
                    except Exception as e:
                        logger.error(f"Kunde inte skicka premium bekräftelsemail via webhook: {e}")
                    
                    logger.info(f"Premium aktiverat via webhook för {user_id}, launch_offer={is_launch_offer}")
        
        # Hantera automatisk förnyelse (varje år)
        elif event_type == 'invoice.payment_succeeded':
            subscription_id = data.get('subscription')
            if subscription_id:
                subscription = stripe.Subscription.retrieve(subscription_id)
                
                user = db.get_user_by_stripe_subscription(subscription_id)
                if user:
                    new_expires = datetime.fromtimestamp(subscription.current_period_end)
                    db.extend_premium(user['id'], new_expires)
                    
                    # Kolla domän från metadata eller user
                    sub_metadata = getattr(subscription, 'metadata', {}) or {}
                    domain = sub_metadata.get('domain', 'se')
                    
                    # Skicka förnyelsemail
                    try:
                        if domain == 'com':
                            subject = "🔄 Your ReturnaDisc Premium has been renewed"
                            html_content = f"""
                            <div style="font-family: Arial, sans-serif; max-width: 600px; color: #333;">
                                <h2 style="color: #166534;">Hi {user.get('name', '')}!</h2>
                                
                                <p style="font-size: 16px;">Your <strong>ReturnaDisc Premium</strong> subscription has been automatically renewed.</p>
                                
                                <div style="background: #f0fdf4; padding: 20px; border-radius: 12px; margin: 20px 0; border-left: 4px solid #166534;">
                                    <p style="margin: 5px 0;"><strong>New validity date:</strong> {new_expires.strftime('%Y-%m-%d')}</p>
                                    <p style="margin: 5px 0;"><strong>Charged amount:</strong> $4.99</p>
                                </div>
                                
                                <p style="font-size: 14px; color: #666;">
                                    You can manage your subscription at <a href="{Config.PUBLIC_URL}/premium/manage" style="color: #166534;">My Premium</a>.
                                </p>
                                
                                <p style="font-size: 14px;">
                                    Best regards,<br>
                                    <strong>The ReturnaDisc Team</strong>
                                </p>
                            </div>
                            """
                        else:
                            subject = "🔄 Din ReturnaDisc Premium har förnyats"
                            html_content = f"""
                            <div style="font-family: Arial, sans-serif; max-width: 600px; color: #333;">
                                <h2 style="color: #166534;">Hej {user.get('name', '')}!</h2>
                                
                                <p style="font-size: 16px;">Din <strong>ReturnaDisc Premium</strong> prenumeration har automatiskt förnyats.</p>
                                
                                <div style="background: #f0fdf4; padding: 20px; border-radius: 12px; margin: 20px 0; border-left: 4px solid #166534;">
                                    <p style="margin: 5px 0;"><strong>Nytt giltighetsdatum:</strong> {new_expires.strftime('%Y-%m-%d')}</p>
                                    <p style="margin: 5px 0;"><strong>Debiterat belopp:</strong> 39 kr</p>
                                </div>
                                
                                <p style="font-size: 14px; color: #666;">
                                    Du kan hantera din prenumeration under <a href="{Config.PUBLIC_URL}/premium/manage" style="color: #166534;">Mitt Premium</a>.
                                </p>
                                
                                <p style="font-size: 14px;">
                                    Med vänliga hälsningar,<br>
                                    <strong>ReturnaDisc-teamet</strong>
                                </p>
                            </div>
                            """
                        send_email_async(user.get('email'), subject, html_content)
                        logger.info(f"Förnyelsemail skickat till {user.get('email')}")
                    except Exception as e:
                        logger.error(f"Kunde inte skicka förnyelsemail: {e}")
                    
                    logger.info(f"Premium förnyat för {user['id']} till {new_expires}")
        
        # Hantera misslyckad betalning
        elif event_type == 'invoice.payment_failed':
            subscription_id = data.get('subscription')
            if subscription_id:
                user = db.get_user_by_stripe_subscription(subscription_id)
                if user:
                    db.update_subscription_status(user['id'], 'cancelled')
                    
                    # Kolla domän från subscription metadata
                    subscription = stripe.Subscription.retrieve(subscription_id)
                    sub_metadata = getattr(subscription, 'metadata', {}) or {}
                    domain = sub_metadata.get('domain', 'se')
                    
                    # Skicka mail om misslyckad betalning
                    try:
                        if domain == 'com':
                            subject = "⚠️ Your ReturnaDisc Premium could not be renewed"
                            html_content = f"""
                            <div style="font-family: Arial, sans-serif; max-width: 600px; color: #333;">
                                <h2 style="color: #dc2626;">Hi {user.get('name', '')}!</h2>
                                
                                <p style="font-size: 16px;">Unfortunately, we could not renew your <strong>ReturnaDisc Premium</strong> subscription.</p>
                                
                                <div style="background: #fef2f2; padding: 20px; border-radius: 12px; margin: 20px 0; border-left: 4px solid #dc2626;">
                                    <p style="margin: 0;">This is likely because your payment card has expired or there are insufficient funds.</p>
                                </div>
                                
                                <p style="font-size: 14px; color: #666;">
                                    You can update your payment details at <a href="{Config.PUBLIC_URL}/premium/manage" style="color: #166534;">My Premium</a> to reactivate your Premium.
                                </p>
                                
                                <p style="font-size: 14px;">
                                    Best regards,<br>
                                    <strong>The ReturnaDisc Team</strong>
                                </p>
                            </div>
                            """
                        else:
                            subject = "⚠️ Din ReturnaDisc Premium kunde inte förnyas"
                            html_content = f"""
                            <div style="font-family: Arial, sans-serif; max-width: 600px; color: #333;">
                                <h2 style="color: #dc2626;">Hej {user.get('name', '')}!</h2>
                                
                                <p style="font-size: 16px;">Vi kunde tyvärr inte förnya din <strong>ReturnaDisc Premium</strong> prenumeration.</p>
                                
                                <div style="background: #fef2f2; padding: 20px; border-radius: 12px; margin: 20px 0; border-left: 4px solid #dc2626;">
                                    <p style="margin: 0;">Detta beror troligen på att ditt betalkort har gått ut eller att det inte finns tillräckligt med medel.</p>
                                </div>
                                
                                <p style="font-size: 14px; color: #666;">
                                    Du kan uppdatera dina betalningsuppgifter under <a href="{Config.PUBLIC_URL}/premium/manage" style="color: #166534;">Mitt Premium</a> för att återaktivera ditt Premium.
                                </p>
                                
                                <p style="font-size: 14px;">
                                    Med vänliga hälsningar,<br>
                                    <strong>ReturnaDisc-teamet</strong>
                                </p>
                            </div>
                            """
                        send_email_async(user.get('email'), subject, html_content)
                        logger.info(f"Misslyckad betalning mail skickat till {user.get('email')}")
                    except Exception as e:
                        logger.error(f"Kunde inte skicka misslyckad betalning mail: {e}")
                    
                    logger.info(f"Premium avbrutet för {user['id']} pga misslyckad betalning")
        
        return jsonify({'status': 'success'}), 200
        
    except Exception as e:
        logger.error(f"Webhook error: {e}")
        return jsonify({'status': 'received'}), 200