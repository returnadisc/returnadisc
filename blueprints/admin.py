"""Admin-funktioner med säkerhet och audit-logging."""
import logging
import os
from dataclasses import dataclass, asdict
from datetime import datetime, timedelta
from typing import Optional, Dict, List, Callable, TYPE_CHECKING
from functools import wraps

from flask import (
    Blueprint, render_template, request, redirect, 
    url_for, flash, session, send_file, current_app, g,
    jsonify  # Ny för AJAX
)
from werkzeug.security import check_password_hash, generate_password_hash

from database import db

# TYPE_CHECKING används för att undvika circular imports vid runtime
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
    
    def __init__(self, database: 'Database'):  # TYPE_CHECKING används här
        self.db = database
    
    def generate_batch(self, count: int, base_url: str) -> List[str]:
        """Generera batch med QR-koder."""
        from utils import generate_qr_pdf, create_qr_code
        
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
    
    def __init__(self, database: 'Database'):  # TYPE_CHECKING används här
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
    
    return TemplateService.render(
        'admin/admin_dashboard.html',
        stats=stats,
        health=health,
        recent_logs=recent_logs
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
    """Generera QR-PDF - nu med bakgrundsjobb för stora batcher."""
    try:
        count = int(request.form.get('count', 10))
        
        if count < 1 or count > Config.MAX_QR_PER_REQUEST:
            flash(f'Antal måste vara mellan 1 och {Config.MAX_QR_PER_REQUEST}.', 'error')
            return redirect(url_for('admin.create_qr'))
        
        # För små batcher (< 20), gör synkront för snabbhet
        if count <= 20:
            qr_service = QRGenerationService(db)
            qr_codes = qr_service.generate_batch(count, Config.PUBLIC_URL)
            
            from utils import generate_qr_pdf
            pdf_path = generate_qr_pdf(count, Config.PUBLIC_URL)
            
            logger.info(f"Admin {g.admin_email} generated {count} QR codes from {g.admin_ip}")
            flash(f'{len(qr_codes)} QR-koder genererade!', 'success')
            
            return send_file(
                pdf_path, 
                as_attachment=True, 
                download_name=f'returnadisc-qr-batch-{count}st.pdf'
            )
        
        # För stora batcher, använd bakgrundsjobb
        from utils import job_manager
        
        job_id = job_manager.submit_pdf_job(count, Config.PUBLIC_URL)
        flash(f'Stor batch på {count} QR-koder köas för generering. Jobb-ID: {job_id}', 'info')
        
        return redirect(url_for('admin.job_status', job_id=job_id))
        
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
    qr_codes = db.get_all_qr_codes_with_users()
    return TemplateService.render('admin/qr_codes.html', qr_codes=qr_codes)


@bp.route('/users')
@admin_required
@handle_template_errors
def list_users():
    """Lista alla användare med detaljerad statistik."""
    users = db.get_all_users_with_stats()
    return TemplateService.render('admin/users.html', users=users)


@bp.route('/reset', methods=['POST'])
@admin_required
@audit_log("RESET_DATABASE_ATTEMPT", "Attempted database reset")
def reset_db():
    """Nollställ databasen."""
    security = AdminSecurityService()
    
    confirmation = request.form.get('confirm', '')
    if not security.validate_reset_confirmation(confirmation):
        flash('Skriv "DELETE EVERYTHING" för att bekräfta.', 'error')
        return redirect(url_for('admin.dashboard'))
    
    password = request.form.get('admin_password', '').strip()
    if not security.verify_password_for_destructive_action(
        password, Config.ADMIN_PASSWORD_HASH
    ):
        audit = AuditLogService()
        audit.log(
            g.admin_email, "RESET_DATABASE", 
            "Failed - wrong password", g.admin_ip, success=False
        )
        flash('Fel lösenord. Databasen är INTE nollställd.', 'error')
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
            flash('Databasen är nollställd. En backup har skapats.', 'warning')
        else:
            flash('Nollställning avbröts.', 'error')
            
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