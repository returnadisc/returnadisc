"""Admin-funktioner med säkerhet och audit-logging."""
import logging
import os
from dataclasses import dataclass, asdict
from datetime import datetime, timedelta
from typing import Optional, Dict, List, Callable, TYPE_CHECKING
from functools import wraps
from database import db, encryption

from flask import (
    Blueprint, render_template, request, redirect, 
    url_for, flash, session, send_file, current_app, g,
    jsonify
)
from werkzeug.security import check_password_hash, generate_password_hash

from database import db

if TYPE_CHECKING:
    from database import Database

from config import Config

logger = logging.getLogger(__name__)

bp = Blueprint('admin', __name__, url_prefix='/admin')


# ============================================================================
# Dataclasses
# ============================================================================

@dataclass
class AdminSession:
    """Håller admin-session data."""
    email: str
    ip_address: str
    login_time: datetime
    
    def to_dict(self) -> Dict:
        return asdict(self)


@dataclass
class AuditLogEntry:
    """Audit log entry för admin-åtgärder."""
    timestamp: datetime
    admin_email: str
    action: str
    details: str
    ip_address: str
    success: bool


# ============================================================================
# Exceptions
# ============================================================================

class AdminAuthError(Exception):
    """Fel vid admin-autentisering."""
    pass


class AdminSecurityError(Exception):
    """Säkerhetsrelaterat fel."""
    pass


class TemplateError(Exception):
    """Fel vid template-rendering."""
    pass


# ============================================================================
# Services
# ============================================================================

class AuditLogService:
    """Service för audit-logging av admin-åtgärder."""
    
    def __init__(self, log_file: str = 'admin_audit.log'):
        self.log_file = log_file
        self._setup_logger()
    
    def _setup_logger(self) -> None:
        """Setup separat logger för audit."""
        self.audit_logger = logging.getLogger('admin_audit')
        self.audit_logger.setLevel(logging.INFO)
        
        if not self.audit_logger.handlers:
            handler = logging.FileHandler(self.log_file)
            formatter = logging.Formatter(
                '%(asctime)s - %(message)s',
                datefmt='%Y-%m-%d %H:%M:%S'
            )
            handler.setFormatter(formatter)
            self.audit_logger.addHandler(handler)
    
    def log(
        self,
        admin_email: str,
        action: str,
        details: str = "",
        ip_address: str = "",
        success: bool = True
    ) -> None:
        """Logga admin-åtgärd."""
        status = "SUCCESS" if success else "FAILED"
        message = f"[{status}] {admin_email} | {action} | {details} | IP: {ip_address}"
        self.audit_logger.info(message)
        
        if not success:
            logger.warning(f"Admin action failed: {action} by {admin_email} from {ip_address}")
    
    def get_recent_logs(self, limit: int = 100) -> List[Dict]:
        """Hämta senaste loggarna."""
        try:
            if not os.path.exists(self.log_file):
                return []
            
            with open(self.log_file, 'r') as f:
                lines = f.readlines()
            
            logs = []
            for line in lines[-limit:]:
                line = line.strip()
                if not line:
                    continue
                
                try:
                    parts = line.split(' - ', 1)
                    if len(parts) != 2:
                        continue
                    
                    timestamp_str, rest = parts
                    logs.append({
                        'timestamp': timestamp_str,
                        'raw': rest
                    })
                except Exception:
                    continue
            
            return list(reversed(logs))
            
        except Exception as e:
            logger.error(f"Kunde inte läsa audit log: {e}")
            return []


class AdminAuthService:
    """Service för admin-autentisering."""
    
    MAX_LOGIN_ATTEMPTS = 5
    LOCKOUT_DURATION_MINUTES = 30
    
    def __init__(self, config: Config, audit_service: AuditLogService):
        self.config = config
        self.audit = audit_service
        self._failed_attempts: Dict[str, List[datetime]] = {}
    
    def _is_locked_out(self, ip_address: str) -> bool:
        """Kontrollera om IP är låst."""
        attempts = self._failed_attempts.get(ip_address, [])
        cutoff = datetime.now() - timedelta(minutes=self.LOCKOUT_DURATION_MINUTES)
        
        recent_attempts = [a for a in attempts if a > cutoff]
        self._failed_attempts[ip_address] = recent_attempts
        
        return len(recent_attempts) >= self.MAX_LOGIN_ATTEMPTS
    
    def _record_failed_attempt(self, ip_address: str) -> None:
        """Registrera misslyckat inloggningsförsök."""
        if ip_address not in self._failed_attempts:
            self._failed_attempts[ip_address] = []
        self._failed_attempts[ip_address].append(datetime.now())
    
    def authenticate(self, email: str, password: str, ip_address: str) -> bool:
        """Autentisera admin."""
        if self._is_locked_out(ip_address):
            self.audit.log(
                email, "LOGIN_ATTEMPT", "IP locked out",
                ip_address, success=False
            )
            raise AdminSecurityError(
                f"För många misslyckade försök. Försök igen om {self.LOCKOUT_DURATION_MINUTES} minuter."
            )
        
        if email != self.config.ADMIN_EMAIL:
            self._record_failed_attempt(ip_address)
            self.audit.log(email, "LOGIN", "Wrong email", ip_address, success=False)
            raise AdminAuthError("Fel inloggningsuppgifter.")
        
        if not self.config.ADMIN_PASSWORD_HASH:
            logger.error("ADMIN_PASSWORD_HASH not set!")
            self.audit.log(email, "LOGIN", "Password hash not configured", ip_address, success=False)
            raise AdminAuthError("Systemfel. Kontakta support.")
        
        if not check_password_hash(self.config.ADMIN_PASSWORD_HASH, password):
            self._record_failed_attempt(ip_address)
            self.audit.log(email, "LOGIN", "Wrong password", ip_address, success=False)
            raise AdminAuthError("Fel inloggningsuppgifter.")
        
        self.audit.log(email, "LOGIN", "Successful login", ip_address, success=True)
        return True
    
    def verify_session(self, session_data: Dict) -> bool:
        """Verifiera att admin-session fortfarande är giltig."""
        if not session_data.get('is_admin'):
            return False
        
        if session_data.get('admin_email') != self.config.ADMIN_EMAIL:
            return False
        
        login_time = session_data.get('admin_login_time')
        if login_time:
            try:
                login_dt = datetime.fromisoformat(login_time)
                if datetime.now() - login_dt > timedelta(hours=12):
                    return False
            except (ValueError, TypeError):
                return False
        
        return True
    
    def create_session(self, email: str, ip_address: str) -> Dict:
        """Skapa ny admin-session."""
        return {
            'is_admin': True,
            'admin_email': email,
            'admin_ip': ip_address,
            'admin_login_time': datetime.now().isoformat()
        }
    
    def destroy_session(self, session_data: Dict, ip_address: str) -> None:
        """Förstör admin-session och logga."""
        email = session_data.get('admin_email', 'unknown')
        self.audit.log(email, "LOGOUT", "Admin logged out", ip_address, success=True)


class AdminSecurityService:
    """Service för säkerhetskontroller."""
    
    DESTRUCTIVE_ACTIONS = {'RESET_DATABASE', 'DELETE_USER', 'DELETE_QR_BATCH'}
    
    @staticmethod
    def validate_reset_confirmation(confirmation: str) -> bool:
        """Validera att användaren skrivit rätt bekräftelse."""
        return confirmation == 'DELETE EVERYTHING'
    
    @staticmethod
    def verify_password_for_destructive_action(
        password: str, 
        expected_hash: str
    ) -> bool:
        """Verifiera lösenord för destruktiv operation."""
        if not expected_hash:
            return False
        return check_password_hash(expected_hash, password)
    
    @classmethod
    def is_destructive_action(cls, action: str) -> bool:
        """Kontrollera om åtgärd är destruktiv."""
        return action in cls.DESTRUCTIVE_ACTIONS


class QRGenerationService:
    """Service för batch-generering av QR-koder."""
    
    def __init__(self, database: 'Database'):
        self.db = database
    
    def generate_batch(self, count: int, base_url: str) -> List[str]:
        """Generera batch med QR-koder."""
        from utils import create_qr_code
        
        qr_codes = []
        max_attempts_per_code = 5
        
        for i in range(count):
            qr_id = self._generate_single_qr(max_attempts_per_code)
            if qr_id:
                qr_codes.append(qr_id)
            else:
                logger.error(f"Kunde inte generera QR-kod {i+1}/{count}")
        
        if not qr_codes:
            raise RuntimeError("Inga QR-koder kunde skapas")
        
        return qr_codes
    
    def _generate_single_qr(self, max_attempts: int) -> Optional[str]:
        """Generera en QR-kod med retry."""
        from utils import generate_random_qr_id, create_qr_code
        
        for attempt in range(max_attempts):
            qr_id = generate_random_qr_id()
            
            if self.db.get_qr(qr_id):
                continue
            
            if self.db.create_qr(qr_id):
                try:
                    create_qr_code(qr_id, None)
                    return qr_id
                except Exception as e:
                    logger.error(f"Kunde inte skapa QR-bild för {qr_id}: {e}")
                    continue
        
        return None


class AdminStatsService:
    """Service för admin-statistik."""
    
    def __init__(self, database: 'Database'):
        self.db = database
    
    def get_dashboard_stats(self) -> Dict:
        """Hämta omfattande statistik för dashboard."""
        return self.db.get_admin_stats()
    
    def get_system_health(self) -> Dict:
        """Kontrollera systemhälsa."""
        stats = {
            'database_ok': self._check_database(),
            'disk_space_ok': self._check_disk_space(),
            'email_configured': bool(os.environ.get('SENDGRID_API_KEY')),
            'admin_configured': bool(Config.ADMIN_PASSWORD_HASH),
            'encryption_configured': bool(os.environ.get('PII_ENCRYPTION_KEY') or os.environ.get('SECRET_KEY'))
        }
        stats['all_systems_go'] = all(stats.values())
        return stats
    
    def _check_database(self) -> bool:
        """Kontrollera databasanslutning."""
        try:
            self.db.get_stats()
            return True
        except Exception:
            return False
    
    def _check_disk_space(self) -> bool:
        """Kontrollera ledigt diskutrymme."""
        try:
            import shutil
            stat = shutil.disk_usage('/')
            return stat.free > 1_000_000_000
        except Exception:
            return True


class TemplateService:
    """Service för säker template-rendering med felhantering."""
    
    @staticmethod
    def render(template_name: str, **kwargs) -> str:
        """
        Rendera template med felhantering.
        
        Raises:
            TemplateError om template saknas eller är ogiltig
        """
        try:
            return render_template(template_name, **kwargs)
        except Exception as e:
            logger.error(f"Template-fel ({template_name}): {e}")
            raise TemplateError(f"Kunde inte rendera sida: {template_name}")
    
    @staticmethod
    def render_error(error_code: int, message: str = None) -> tuple:
        """Rendera felsida."""
        try:
            return render_template(f'errors/{error_code}.html', message=message), error_code
        except Exception:
            # Fallback om även felsidan saknas
            return f"Fel {error_code}: {message or 'Ett fel uppstod'}", error_code


# ============================================================================
# Decorators
# ============================================================================

def admin_required(f: Callable) -> Callable:
    """Decorator som kräver giltig admin-inloggning."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        auth_service = AdminAuthService(Config, AuditLogService())
        
        if not auth_service.verify_session(session):
            if session.get('is_admin'):
                session.clear()
                flash('Session expired. Logga in igen.', 'error')
            else:
                flash('Logga in som admin först.', 'error')
            return redirect(url_for('admin.login'))
        
        g.admin_email = session.get('admin_email')
        g.admin_ip = request.remote_addr
        
        return f(*args, **kwargs)
    
    return decorated_function


def audit_log(action: str, details: str = ""):
    """Decorator som loggar admin-åtgärder."""
    def decorator(f: Callable) -> Callable:
        @wraps(f)
        def decorated_function(*args, **kwargs):
            audit = AuditLogService()
            email = session.get('admin_email', 'unknown')
            ip = request.remote_addr
            
            try:
                result = f(*args, **kwargs)
                audit.log(email, action, details, ip, success=True)
                return result
            except Exception as e:
                audit.log(email, action, f"{details} - Error: {str(e)}", ip, success=False)
                raise
        
        return decorated_function
    return decorator


def handle_template_errors(f: Callable) -> Callable:
    """Decorator som fångar template-fel och visar användarvänligt meddelande."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        try:
            return f(*args, **kwargs)
        except TemplateError as e:
            logger.error(f"Template-fel i route: {e}")
            return TemplateService.render_error(500, "Sidan kunde inte laddas")
        except Exception as e:
            logger.error(f"Oväntat fel: {e}")
            return TemplateService.render_error(500, "Ett oväntat fel uppstod")
    
    return decorated_function


# ============================================================================
# Routes
# ============================================================================

@bp.route('/login', methods=['GET', 'POST'])
@handle_template_errors
def login():
    """Admin login med säker verifiering."""
    auth_service = AdminAuthService(Config, AuditLogService())
    
    if auth_service.verify_session(session):
        return redirect(url_for('admin.dashboard'))
    
    if request.method == 'POST':
        email = request.form.get('email', '').strip().lower()
        password = request.form.get('password', '').strip()
        ip = request.remote_addr
        
        try:
            auth_service.authenticate(email, password, ip)
            session.update(auth_service.create_session(email, ip))
            session.permanent = True
            
            flash('Inloggad som admin.', 'success')
            return redirect(url_for('admin.dashboard'))
            
        except AdminSecurityError as e:
            flash(str(e), 'error')
        except AdminAuthError as e:
            flash(str(e), 'error')
        
        return TemplateService.render('admin/admin_login.html')
    
    return TemplateService.render('admin/admin_login.html')


@bp.route('/logout')
def logout():
    """Admin logout."""
    if session.get('is_admin'):
        audit = AuditLogService()
        audit.destroy_session(session, request.remote_addr)
    
    session.pop('is_admin', None)
    session.pop('admin_email', None)
    session.pop('admin_ip', None)
    session.pop('admin_login_time', None)
    
    flash('Utloggad.', 'info')
    return redirect(url_for('auth.index'))


@bp.route('/')
@admin_required
@handle_template_errors
def dashboard():
    """Admin dashboard."""
    stats_service = AdminStatsService(db)
    
    stats = stats_service.get_dashboard_stats()
    health = stats_service.get_system_health()
    recent_logs = AuditLogService().get_recent_logs(20)
    
    # Kontrollera om vi är i lanseringsperioden
    is_launch = db.is_launch_period()
    
    return TemplateService.render(
        'admin/admin_dashboard.html',
        stats=stats,
        health=health,
        recent_logs=recent_logs,
        is_launch=is_launch
    )


@bp.route('/create', methods=['GET'])
@admin_required
@handle_template_errors
def create_qr():
    """Skapa QR-koder (admin)."""
    return TemplateService.render('admin/create_qr.html')


@bp.route('/qr-pdf', methods=['POST'])
@admin_required
@audit_log("GENERATE_QR_PDF", "Generated QR code PDF")
def qr_pdf():
    """Generera QR-PDF."""
    try:
        count = int(request.form.get('count', 10))
        
        if count < 1 or count > Config.MAX_QR_PER_REQUEST:
            flash(f'Antal måste vara mellan 1 och {Config.MAX_QR_PER_REQUEST}.', 'error')
            return redirect(url_for('admin.create_qr'))
        
        # Generera QR-koder
        qr_service = QRGenerationService(db)
        qr_codes = qr_service.generate_batch(count, Config.PUBLIC_URL)
        
        # Skapa PDF med befintlig funktion från utils
        from utils import generate_qr_pdf_for_order
        
        qr_codes_data = [{'qr_id': qid, 'qr_filename': f'qr_{qid}.png'} for qid in qr_codes]
        pdf_path = generate_qr_pdf_for_order(qr_codes_data, Config.PUBLIC_URL)
        
        logger.info(f"Admin {g.admin_email} generated {count} QR codes from {g.admin_ip}")
        flash(f'{len(qr_codes)} QR-koder genererade!', 'success')
        
        return send_file(
            pdf_path, 
            as_attachment=True, 
            download_name=f'returnadisc-qr-batch-{count}st.pdf'
        )
        
    except Exception as e:
        logger.error(f"PDF generation failed: {e}")
        flash(f'Fel vid generering: {str(e)}', 'error')
        return redirect(url_for('admin.create_qr'))


@bp.route('/job-status/<job_id>')
@admin_required
def job_status(job_id: str):
    """Kolla status på bakgrundsjobb."""
    from utils import job_manager
    
    job = job_manager.get_job_status(job_id)
    
    if not job:
        flash('Jobb hittades inte.', 'error')
        return redirect(url_for('admin.dashboard'))
    
    if job.status == 'completed':
        flash('PDF är klar!', 'success')
        return send_file(
            job.result,
            as_attachment=True,
            download_name=f'returnadisc-qr-batch.pdf'
        )
    elif job.status == 'failed':
        flash(f'PDF-generering misslyckades: {job.error}', 'error')
        return redirect(url_for('admin.create_qr'))
    
    # Fortfarande pågående
    return TemplateService.render(
        'admin/job_status.html',
        job_id=job_id,
        status=job.status,
        created_at=job.created_at
    )


@bp.route('/api/job-status/<job_id>')
@admin_required
def api_job_status(job_id: str):
    """API-endpoint för AJAX-polling av jobbstatus."""
    from utils import job_manager
    
    job = job_manager.get_job_status(job_id)
    
    if not job:
        return jsonify({'error': 'Jobb hittades inte'}), 404
    
    return jsonify({
        'job_id': job.job_id,
        'status': job.status,
        'result': job.result,
        'error': job.error,
        'created_at': job.created_at.isoformat() if job.created_at else None,
        'completed_at': job.completed_at.isoformat() if job.completed_at else None
    })


@bp.route('/qr-codes')
@admin_required
@handle_template_errors
def list_qr_codes():
    """Lista alla QR-koder och ägare."""
    try:
        qr_codes = db.get_all_qr_codes_with_users()
        
        # Debug: Kontrollera om resultatet är None
        if qr_codes is None:
            logger.error("db.get_all_qr_codes_with_users() returnerade None")
            qr_codes = []
        
        # Debug: Logga antal och typ
        logger.info(f"Hämtade {len(qr_codes)} QR-koder, typ: {type(qr_codes)}")
        
        # Konvertera alla objekt till dict för säkerhet och fixa datatyper
        formatted_codes = []
        for qr in qr_codes:
            try:
                if isinstance(qr, dict):
                    qr_dict = qr
                elif hasattr(qr, '_asdict'):
                    qr_dict = qr._asdict()
                elif hasattr(qr, '__dict__'):
                    qr_dict = vars(qr)
                else:
                    qr_dict = {
                        'qr_id': getattr(qr, 'qr_id', 'N/A'),
                        'name': getattr(qr, 'name', None),
                        'email': getattr(qr, 'email', None),
                        'is_active': getattr(qr, 'is_active', False),
                        'total_scans': getattr(qr, 'total_scans', 0),
                        'is_premium': getattr(qr, 'is_premium', False),
                    }
                
                # VIKTIGT: Konvertera is_premium till boolean (hantera 0/1)
                is_premium = qr_dict.get('is_premium', False)
                if isinstance(is_premium, int):
                    is_premium = bool(is_premium)
                elif isinstance(is_premium, str):
                    is_premium = is_premium.lower() in ('true', '1', 'yes', 'ja')
                
                # VIKTIGT: Konvertera is_active till boolean
                is_active = qr_dict.get('is_active', False)
                if isinstance(is_active, int):
                    is_active = bool(is_active)
                
                # VIKTIGT: Fixa name och email - hämta separat om user_id finns men name är tomt
                name = qr_dict.get('name')
                email = qr_dict.get('email')
                user_id = qr_dict.get('user_id')
                
                if user_id and (not name or name == 'None'):
                    logger.warning(f"QR {qr_dict.get('qr_id')} har user_id {user_id} men ingen name! Hämtar separat...")
                    user_row = db._db.fetch_one(
                        "SELECT name, email, is_premium FROM users WHERE id = ?", 
                        (user_id,)
                    )
                    if user_row:
                        name = user_row.get('name', 'Okänd')
                        email = user_row.get('email', '')
                        # Uppdatera is_premium från användaren om den är satt
                        user_premium = user_row.get('is_premium', 0)
                        if user_premium:
                            is_premium = bool(int(user_premium)) if isinstance(user_premium, (int, str)) else bool(user_premium)
                        
                        # Dekryptera email om nödvändigt
                        if email and email.startswith('gAAAA'):
                            email = encryption.decrypt(email)
                    else:
                        name = 'Okänd (saknas)'
                
                # Sätt standardvärden om tomma
                if not name or name == 'None':
                    name = None  # Kommer visa "Ej tilldelad"
                if not email or email == 'None':
                    email = None
                
                formatted_codes.append({
                    'qr_id': qr_dict.get('qr_id') or 'N/A',
                    'name': name,
                    'email': email,
                    'is_active': is_active,
                    'total_scans': qr_dict.get('total_scans', 0) or 0,
                    'is_premium': is_premium,
                    'created_at': qr_dict.get('created_at'),
                    'user_id': user_id
                })
                
            except Exception as e:
                logger.error(f"Fel vid konvertering av QR-kod: {e}")
                continue
        
        return TemplateService.render('admin/qr_codes.html', qr_codes=formatted_codes)
        
    except Exception as e:
        logger.error(f"Fel i list_qr_codes: {str(e)}", exc_info=True)
        flash(f"Ett fel uppstod vid hämtning av QR-koder: {str(e)}", "error")
        return redirect(url_for('admin.dashboard'))


@bp.route('/users')
@admin_required
@handle_template_errors
def list_users():
    """Lista alla användare med detaljerad statistik."""
    try:
        users = db.get_all_users_with_stats()
        
        # Debug-loggning
        if users is None:
            logger.error("db.get_all_users_with_stats() returnerade None")
            users = []
        
        logger.info(f"Hämtade {len(users)} användare")
        
        # Kontrollera om vi är i lanseringsperioden
        is_launch = db.is_launch_period()
        
        # Konvertera till dicts för säkerhet
        formatted_users = []
        for user in users:
            try:
                if isinstance(user, dict):
                    formatted_users.append(user)
                elif hasattr(user, '_asdict'):
                    formatted_users.append(user._asdict())
                elif hasattr(user, '__dict__'):
                    formatted_users.append(vars(user))
                else:
                    formatted_users.append({
                        'id': getattr(user, 'id', 0),
                        'name': getattr(user, 'name', 'Okänd'),
                        'email': getattr(user, 'email', '-'),
                        'created_at': getattr(user, 'created_at', None),
                        'missing_count': getattr(user, 'missing_count', 0),
                        'found_count': getattr(user, 'found_count', 0),
                        'handovers_count': getattr(user, 'handovers_count', 0),
                        'is_premium': getattr(user, 'is_premium', False),
                        'premium_until': getattr(user, 'premium_until', None)
                    })
            except Exception as e:
                logger.error(f"Fel vid konvertering av användare: {e}")
                continue
        
        return TemplateService.render('admin/users.html', 
                                    users=formatted_users,
                                    is_launch=is_launch)
        
    except Exception as e:
        logger.error(f"Fel i list_users: {str(e)}", exc_info=True)
        flash(f"Ett fel uppstod: {str(e)}", "error")
        return redirect(url_for('admin.dashboard'))


@bp.route('/reset', methods=['POST'])
@admin_required
@audit_log("RESET_DATABASE_ATTEMPT", "Attempted database reset")
def reset_db():
    """Nollställ databasen."""
    from werkzeug.security import check_password_hash
    
    confirmation = request.form.get('confirm', '').strip()
    password = request.form.get('admin_password', '').strip()
    
    # Debug-loggning
    logger.info(f"Reset attempt: confirm='{confirmation}', password_entered={'yes' if password else 'no'}")
    
    # Kolla bekräftelse-text
    if confirmation != 'DELETE EVERYTHING':
        flash('Skriv exakt "DELETE EVERYTHING" (versaler) för att bekräfta.', 'error')
        return redirect(url_for('admin.dashboard'))
    
    # Kolla lösenord - använd samma som admin-inloggning
    if not Config.ADMIN_PASSWORD_HASH:
        logger.error("ADMIN_PASSWORD_HASH är inte satt i config!")
        flash('Systemfel: Admin-lösenord inte konfigurerat.', 'error')
        return redirect(url_for('admin.dashboard'))
    
    if not check_password_hash(Config.ADMIN_PASSWORD_HASH, password):
        audit = AuditLogService()
        audit.log(
            g.admin_email, "RESET_DATABASE", 
            "Failed - wrong password", g.admin_ip, success=False
        )
        flash('Fel lösenord. Ange ditt admin-lösenord.', 'error')
        return redirect(url_for('admin.dashboard'))
    
    try:
        success = db.reset_database(confirm=True)
        
        if success:
            audit = AuditLogService()
            audit.log(
                g.admin_email, "RESET_DATABASE",
                "Database was reset successfully", g.admin_ip, success=True
            )
            logger.critical(f"Database was reset by admin {g.admin_email} from {g.admin_ip}!")
            
            # Logga ut och redirecta till login
            session.clear()
            flash('Databasen är nollställd. En backup har skapats. Du måste logga in igen.', 'warning')
            return redirect(url_for('admin.login'))
        else:
            flash('Nollställning avbröts av systemet.', 'error')
            return redirect(url_for('admin.dashboard'))
            
    except Exception as e:
        logger.error(f"Database reset failed: {e}")
        flash(f'Fel vid nollställning: {str(e)}', 'error')
        return redirect(url_for('admin.dashboard'))


@bp.route('/audit-log')
@admin_required
@handle_template_errors
def view_audit_log():
    """Visa audit log."""
    audit = AuditLogService()
    logs = audit.get_recent_logs(500)
    return TemplateService.render('admin/audit_log.html', logs=logs)


@bp.route('/system-health')
@admin_required
def system_health():
    """API-endpoint för systemhälsa (för dashboard AJAX)."""
    stats_service = AdminStatsService(db)
    health = stats_service.get_system_health()
    return jsonify(health)


# ============================================================================
# ORDER-HANTERING (ENDAST EN VERSION)
# ============================================================================

@bp.route('/orders')
@admin_required
@handle_template_errors
def list_orders():
    """Lista alla ordrar med fullständig information."""
    try:
        status_filter = request.args.get('status', 'all')
        
        # Hämta ordrar med användarinfo
        orders = db.get_all_orders_with_user_info(
            status=None if status_filter == 'all' else status_filter
        )
        
        # Beräkna statistik
        stats = db.get_order_stats()
        
        # Formatera ordrar för display - VIKTIGT: Inkludera alla adress-fält!
        formatted_orders = []
        for order in orders:
            try:
                formatted_orders.append({
                    'id': order.get('id'),
                    'order_number': order.get('order_number', 'N/A'),
                    'user_name': order.get('user_name', 'Okänd'),
                    'user_email': order.get('user_email', ''),
                    'qr_id': order.get('assigned_qr') or order.get('qr_id', '-'),
                    'package_type': order.get('package_type', ''),
                    'quantity': order.get('quantity', 0),
                    'total_amount': order.get('total_amount', 0),
                    'currency': order.get('currency', 'SEK'),
                    'status': order.get('status', 'pending'),
                    'payment_method': order.get('payment_method', '-'),
                    # VIKTIGT: Dessa fält måste vara med!
                    'shipping_name': order.get('shipping_name', ''),
                    'shipping_address': order.get('shipping_address', ''),
                    'shipping_postal_code': order.get('shipping_postal_code', ''),
                    'shipping_city': order.get('shipping_city', ''),
                    'created_at': order.get('created_at'),
                    'paid_at': order.get('paid_at')
                })
            except Exception as e:
                logger.error(f"Fel vid formatering av order: {e}")
                continue
        
        return TemplateService.render('admin/orders.html',
                                    orders=formatted_orders,
                                    stats=stats,
                                    current_filter=status_filter)
        
    except Exception as e:
        logger.error(f"Fel i list_orders: {e}", exc_info=True)
        flash('Ett fel uppstod vid hämtning av ordrar', 'error')
        return redirect(url_for('admin.dashboard'))


@bp.route('/orders/<int:order_id>')
@admin_required
@handle_template_errors
def view_order(order_id: int):
    """Visa detaljer för specifik order."""
    try:
        order = db.get_order_by_id(order_id)
        if not order:
            flash('Ordern hittades inte', 'error')
            return redirect(url_for('admin.list_orders'))
        
        # Hämta användarinfo
        user = db.get_user_by_id(order['user_id'])
        
        return TemplateService.render('admin/order_detail.html',
                                    order=order,
                                    user=user)
        
    except Exception as e:
        logger.error(f"Fel i view_order: {e}")
        flash('Ett fel uppstod', 'error')
        return redirect(url_for('admin.list_orders'))


@bp.route('/orders/<int:order_id>/status', methods=['POST'])
@admin_required
@audit_log("UPDATE_ORDER_STATUS", "Update order status")
def update_order_status(order_id: int):
    """Uppdatera orderstatus."""
    try:
        new_status = request.form.get('status')
        valid_statuses = ['pending', 'paid', 'shipped', 'delivered', 'cancelled']
        
        if new_status not in valid_statuses:
            flash('Ogiltig status', 'error')
            return redirect(url_for('admin.list_orders'))
        
        db.update_order_status(order_id, new_status)
        
        flash(f'Orderstatus uppdaterad', 'success')
        
    except Exception as e:
        logger.error(f"Fel vid uppdatering av orderstatus: {e}")
        flash('Ett fel uppstod', 'error')
    
    return redirect(url_for('admin.list_orders'))


@bp.route('/download-qr/<qr_id>')
@admin_required
def download_qr(qr_id: str):
    """Ladda ner QR-kod som PNG."""
    import os
    from flask import send_file
    
    qr_folder = os.environ.get('QR_FOLDER', 'static/qr')
    filepath = os.path.join(qr_folder, f"qr_{qr_id}.png")
    
    if os.path.exists(filepath):
        return send_file(filepath, as_attachment=True, download_name=f'returnadisc_{qr_id}.png')
    else:
        flash(f'QR-kod {qr_id} hittades inte', 'error')
        return redirect(url_for('admin.list_orders'))


# ============================================================================
# QR-kod Admin-hantering (Redigering, Premium, Registrering)
# ============================================================================

@bp.route('/qr/<qr_id>/delete', methods=['POST'])
@admin_required
@audit_log("DELETE_QR", "Delete QR code")
def delete_qr(qr_id: str):
    """Radera QR-kod (endast om ej tilldelad)."""
    try:
        qr = db.get_qr(qr_id)
        
        if not qr:
            flash('QR-koden hittades inte', 'error')
            return redirect(url_for('admin.list_qr_codes'))
        
        if qr.get('user_id'):
            flash('Kan inte radera QR-kod som är tilldelad en användare', 'error')
            return redirect(url_for('admin.edit_qr', qr_id=qr_id))
        
        # Radera från databasen
        query = "DELETE FROM qr_codes WHERE qr_id = ?"
        db._db.execute(query, (qr_id,))
        
        # Radera bildfil
        import os
        qr_folder = os.environ.get('QR_FOLDER', 'static/qr')
        filepath = os.path.join(qr_folder, f"qr_{qr_id}.png")
        if os.path.exists(filepath):
            os.remove(filepath)
        
        flash(f'QR-kod {qr_id} raderad', 'success')
        
    except Exception as e:
        logger.error(f"Fel vid radering av QR: {e}")
        flash('Ett fel uppstod vid radering', 'error')
    
    return redirect(url_for('admin.list_qr_codes'))


@bp.route('/user/<int:user_id>/delete', methods=['POST'])
@admin_required
@audit_log("DELETE_USER", "Delete user")
def delete_user(user_id: int):
    """Radera (soft delete) en användare."""
    try:
        user = db.get_user_by_id(user_id)
        if not user:
            flash('Användaren hittades inte', 'error')
            return redirect(url_for('admin.list_qr_codes'))
        
        # Soft delete via UserRepository
        db.soft_delete_user(user_id)
        
        # Inaktivera QR-koden också
        qr = db.get_user_qr(user_id)
        if qr:
            query = "UPDATE qr_codes SET user_id = NULL, is_active = 0 WHERE qr_id = ?"
            db._db.execute(query, (qr['qr_id'],))
        
        flash(f'Användare {user.get("name", user_id)} har raderats', 'success')
        
    except Exception as e:
        logger.error(f"Fel vid radering av användare: {e}")
        flash('Ett fel uppstod vid radering', 'error')
    
    return redirect(url_for('admin.list_qr_codes'))


@bp.route('/qr/<qr_id>/edit', methods=['GET', 'POST'])
@admin_required
@audit_log("EDIT_QR", "Edit QR code")
def edit_qr(qr_id: str):
    """Redigera QR-kod - byt ID, redigera användare, eller registrera ny användare."""
    try:
        # Hämta QR-kod med all info
        qr_data = db.get_qr_with_payment_info(qr_id)
        
        if not qr_data:
            flash(f'QR-kod {qr_id} hittades inte', 'error')
            return redirect(url_for('admin.list_qr_codes'))
        
        if request.method == 'POST':
            action = request.form.get('action')
            
            if action == 'change_id':
                # Byt QR-ID
                new_qr_id = request.form.get('new_qr_id', '').strip().upper()
                
                try:
                    db.update_qr_id(qr_id, new_qr_id)
                    flash(f'QR-ID ändrat från {qr_id} till {new_qr_id}', 'success')
                    return redirect(url_for('admin.edit_qr', qr_id=new_qr_id))
                except ValueError as e:
                    flash(str(e), 'error')
            
            elif action == 'toggle_premium':
                # Växla premium-status
                user_id = qr_data.get('user_id')
                if not user_id:
                    flash('QR-koden har ingen ägare att sätta premium på', 'error')
                else:
                    current_premium = qr_data.get('is_premium', False)
                    new_premium = not current_premium
                    db.toggle_user_premium(user_id, new_premium)
                    status = "aktiverad" if new_premium else "avaktiverad"
                    flash(f'Premium {status} för användare', 'success')
                    return redirect(url_for('admin.edit_qr', qr_id=qr_id))
            
            elif action == 'update_user':
                # Uppdatera användarens namn och email
                user_id = qr_data.get('user_id')
                if not user_id:
                    flash('QR-koden har ingen ägare att uppdatera', 'error')
                else:
                    name = request.form.get('user_name', '').strip()
                    email = request.form.get('user_email', '').strip().lower()
                    
                    if not name or not email:
                        flash('Namn och email måste fyllas i', 'error')
                    else:
                        try:
                            # Använd direkt SQL för att uppdatera
                            query = "UPDATE users SET name = ? WHERE id = ?"
                            db._db.execute(query, (name, user_id))
                            
                            # Uppdatera email om den ändrats
                            current_email = qr_data.get('email')
                            if email != current_email:
                                from database import encryption
                                encrypted_email = encryption.encrypt(email)
                                email_hash = encryption.hash_email(email)
                                query = "UPDATE users SET email = ?, email_hash = ? WHERE id = ?"
                                db._db.execute(query, (encrypted_email, email_hash, user_id))
                            
                            flash('Användaruppgifter uppdaterade', 'success')
                            return redirect(url_for('admin.edit_qr', qr_id=qr_id))
                        except Exception as e:
                            logger.error(f"Fel vid uppdatering: {e}")
                            flash('Ett fel uppstod vid uppdatering', 'error')
            
            elif action == 'register_user':
                # Registrera ny användare på denna QR-kod
                if qr_data.get('user_id'):
                    flash('QR-koden är redan tilldelad en användare', 'error')
                else:
                    name = request.form.get('name', '').strip()
                    email = request.form.get('email', '').strip().lower()
                    password = request.form.get('password', '').strip()
                    
                    if not all([name, email, password]):
                        flash('Alla fält måste fyllas i', 'error')
                    elif len(password) < 6:
                        flash('Lösenordet måste vara minst 6 tecken', 'error')
                    else:
                        try:
                            user_id = db.register_user_on_qr(qr_id, name, email, password)
                            flash(f'Användare skapad och kopplad till QR-koden! ID: {user_id}', 'success')
                            return redirect(url_for('admin.edit_qr', qr_id=qr_id))
                        except ValueError as e:
                            flash(str(e), 'error')
                        except Exception as e:
                            logger.error(f"Fel vid registrering: {e}")
                            flash('Ett fel uppstod vid registrering', 'error')
        
        return TemplateService.render('admin/edit_qr.html', qr=qr_data)
        
    except Exception as e:
        logger.error(f"Fel i edit_qr: {e}")
        flash('Ett fel uppstod', 'error')
        return redirect(url_for('admin.list_qr_codes'))


# ============================================================================
# Premium Admin-hantering
# ============================================================================

@bp.route('/premium')
@admin_required
@handle_template_errors
def premium_overview():
    """Översikt över premium-användare och prenumerationer."""
    try:
        # Hämta alla användare med premium-info
        query = """
            SELECT 
                u.id, u.name, u.email, u.created_at, u.is_premium,
                u.premium_started_at, u.premium_until,
                COUNT(DISTINCT ps.id) as subscription_count
            FROM users u
            LEFT JOIN premium_subscriptions ps ON u.id = ps.user_id
            WHERE u.is_active = 1
            GROUP BY u.id
            ORDER BY u.is_premium DESC, u.premium_started_at DESC
        """
        users = db._db.fetch_all(query)
        
        # Beräkna statistik
        total_premium = sum(1 for u in users if u.get('is_premium'))
        total_users = len(users)
        launch_users = sum(1 for u in users if u.get('is_premium') and not u.get('premium_until'))
        
        # Hämta prenumerationsdetaljer
        sub_query = """
            SELECT ps.*, u.name, u.email
            FROM premium_subscriptions ps
            JOIN users u ON ps.user_id = u.id
            ORDER BY ps.created_at DESC
            LIMIT 100
        """
        subscriptions = db._db.fetch_all(sub_query)
        
        is_launch = db.is_launch_period()
        
        return TemplateService.render('admin/premium_overview.html',
                                    users=users,
                                    subscriptions=subscriptions,
                                    total_premium=total_premium,
                                    total_users=total_users,
                                    launch_users=launch_users,
                                    is_launch=is_launch)
        
    except Exception as e:
        logger.error(f"Fel i premium_overview: {e}")
        flash('Ett fel uppstod vid hämtning av premium-data', 'error')
        return redirect(url_for('admin.dashboard'))


@bp.route('/premium/grant', methods=['POST'])
@admin_required
@audit_log("GRANT_PREMIUM", "Grant premium to user")
def grant_premium():
    """Manuellt ge premium till en användare."""
    try:
        user_id = int(request.form.get('user_id', 0))
        duration_days = int(request.form.get('duration_days', 365))
        note = request.form.get('note', '')
        
        if not user_id:
            flash('Användar-ID saknas', 'error')
            return redirect(url_for('admin.premium_overview'))
        
        user = db.get_user_by_id(user_id)
        if not user:
            flash('Användaren hittades inte', 'error')
            return redirect(url_for('admin.premium_overview'))
        
        # Beräkna utgångsdatum
        from datetime import timedelta
        expires_at = datetime.now() + timedelta(days=duration_days)
        
        # Aktivera premium
        db.activate_premium(user_id, payment_method='manual', 
                          payment_id=f'ADMIN-{g.admin_email}-{datetime.now().isoformat()}',
                          amount=0)
        
        flash(f'Premium aktiverat för {user.get("name", user_id)} till {expires_at.date()}', 'success')
        logger.info(f"Admin {g.admin_email} gav premium till användare {user_id}")
        
    except Exception as e:
        logger.error(f"Fel vid beviljande av premium: {e}")
        flash('Ett fel uppstod', 'error')
    
    return redirect(url_for('admin.premium_overview'))


@bp.route('/premium/revoke', methods=['POST'])
@admin_required
@audit_log("REVOKE_PREMIUM", "Revoke premium from user")
def revoke_premium():
    """Återkalla premium från en användare."""
    try:
        user_id = int(request.form.get('user_id', 0))
        
        if not user_id:
            flash('Användar-ID saknas', 'error')
            return redirect(url_for('admin.premium_overview'))
        
        user = db.get_user_by_id(user_id)
        if not user:
            flash('Användaren hittades inte', 'error')
            return redirect(url_for('admin.premium_overview'))
        
        # Avaktivera premium
        db._users.deactivate_premium(user_id)
        
        # Uppdatera alla aktiva prenumerationer till cancelled
        query = """
            UPDATE premium_subscriptions 
            SET status = 'cancelled', expires_at = CURRENT_TIMESTAMP
            WHERE user_id = ? AND status = 'active'
        """
        db._db.execute(query, (user_id,))
        
        flash(f'Premium återkallat från {user.get("name", user_id)}', 'success')
        logger.info(f"Admin {g.admin_email} återkallade premium från användare {user_id}")
        
    except Exception as e:
        logger.error(f"Fel vid återkallande av premium: {e}")
        flash('Ett fel uppstod', 'error')
    
    return redirect(url_for('admin.premium_overview'))


@bp.route('/premium/check-expired')
@admin_required
def check_expired_premium():
    """Kontrollera och uppdatera utgångna prenumerationer."""
    try:
        count = db.check_expired_subscriptions()
        flash(f'{count} utgångna prenumerationer uppdaterade', 'success')
    except Exception as e:
        logger.error(f"Fel vid kontroll av utgångna prenumerationer: {e}")
        flash('Ett fel uppstod', 'error')
    
    return redirect(url_for('admin.premium_overview'))