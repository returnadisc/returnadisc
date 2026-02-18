"""Disc/QR-hantering för inloggade användare."""
import logging
import os
import re
from dataclasses import dataclass
from typing import Optional, Dict, Callable
from functools import wraps
from pathlib import Path
from database import db, DB_PATH, encryption

from flask import (
    Blueprint, render_template, request, flash, 
    session, redirect, url_for, send_file, current_app, g
)

from database import db
from utils import create_small_qr_for_pdf, serve_qr_image
from config import Config

logger = logging.getLogger(__name__)

bp = Blueprint('disc', __name__, url_prefix='')


# ============================================================================
# Dataclasses
# ============================================================================

@dataclass
class QRValidationResult:
    """Resultat av QR-validering."""
    is_valid: bool
    error_message: Optional[str] = None
    sanitized_id: Optional[str] = None


# ============================================================================
# Services
# ============================================================================

class QRValidationService:
    """Service för validering av QR-koder."""
    
    MAX_LENGTH = 20
    ALLOWED_PATTERN = re.compile(r'^[A-Z0-9\-]+$')
    
    @classmethod
    def validate(cls, qr_id: str) -> QRValidationResult:
        """
        Validera QR-ID för att förhindra path traversal.
        
        Returns:
            QRValidationResult med status och ev. felmeddelande
        """
        if not qr_id:
            return QRValidationResult(False, "QR-ID saknas.")
        
        if len(qr_id) > cls.MAX_LENGTH:
            return QRValidationResult(False, "QR-ID för långt.")
        
        if not cls.ALLOWED_PATTERN.match(qr_id):
            return QRValidationResult(False, "Ogiltigt QR-ID format.")
        
        return QRValidationResult(True, sanitized_id=qr_id)
    
    @classmethod
    def sanitize_filename(cls, qr_id: str) -> str:
        """Säkerställ att filnamn är säkert."""
        # Ta bort eventuella path-separatorer
        return re.sub(r'[\\/]', '', qr_id)


class FileSecurityService:
    """Service för filsäkerhet."""
    
    @staticmethod
    def validate_path_within_folder(file_path: str, allowed_folder: str) -> bool:
        """
        Validera att en filsökväg är inom tillåten mapp.
        
        Returns:
            True om sökvägen är säker
        """
        try:
            full_path = os.path.abspath(file_path)
            allowed = os.path.abspath(allowed_folder)
            return full_path.startswith(allowed)
        except Exception as e:
            logger.error(f"Path validation error: {e}")
            return False
    
    @staticmethod
    def safe_join(base: str, *paths: str) -> Optional[str]:
        """Säker path-join som förhindrar traversal."""
        try:
            base_path = Path(base).resolve()
            full_path = base_path.joinpath(*paths).resolve()
            
            # Kontrollera att resultatet är inom base
            if not str(full_path).startswith(str(base_path)):
                return None
            
            return str(full_path)
        except Exception as e:
            logger.error(f"Safe join error: {e}")
            return None


class QRDownloadService:
    """Service för nedladdning av QR-koder."""
    
    def __init__(self, app_config: Dict):
        self.config = app_config
    
    def get_qr_image_path(self, qr_id: str) -> Optional[str]:
        """Hämta sökväg till QR-bild."""
        validation = QRValidationService.validate(qr_id)
        if not validation.is_valid:
            return None
        
        qr_folder = self.config.get('QR_FOLDER', 'static/qr')
        filename = f"qr_{QRValidationService.sanitize_filename(qr_id)}.png"
        
        return FileSecurityService.safe_join(qr_folder, filename)
    
    def get_qr_pdf_path(self, qr_id: str) -> Optional[str]:
        """Generera och returnera sökväg till QR-PDF."""
        validation = QRValidationService.validate(qr_id)
        if not validation.is_valid:
            return None
        
        try:
            from reportlab.pdfgen import canvas
            from reportlab.lib.pagesizes import letter
            from reportlab.lib.units import cm
            
            pdf_folder = self.config.get('PDF_FOLDER', 'static/pdfs')
            filename = f"qr_{qr_id}.pdf"
            pdf_path = FileSecurityService.safe_join(pdf_folder, filename)
            
            if not pdf_path:
                return None
            
            Path(pdf_folder).mkdir(parents=True, exist_ok=True)
            
            # Skapa PDF
            c = canvas.Canvas(pdf_path, pagesize=letter)
            width, height = letter
            
            # Hämta QR-bild från databasen istället för att generera ny
            from utils import get_qr_image_from_db
            img_data = get_qr_image_from_db(qr_id)
            
            if not img_data:
                logger.error(f"QR-bild för {qr_id} hittades inte i databasen")
                return None
            
            # Temp-fil för bild
            temp_path = os.path.join(pdf_folder, f"temp_{qr_id}_{os.getpid()}.png")
            
            try:
                # Spara bilddata till temporär fil
                with open(temp_path, 'wb') as f:
                    f.write(img_data)
                
                # Centrera på sidan
                qr_size = 2.5 * cm
                x = (width - qr_size) / 2
                y = (height - qr_size) / 2
                
                c.drawImage(temp_path, x, y, width=qr_size, height=qr_size)
                c.save()
                
                return pdf_path
                
            finally:
                # Garanterad uppstädning
                if os.path.exists(temp_path):
                    try:
                        os.remove(temp_path)
                    except Exception as e:
                        logger.error(f"Kunde inte ta bort temp-fil: {e}")
                        
        except Exception as e:
            logger.error(f"PDF generation failed: {e}")
            return None


class UserDashboardService:
    """Service för dashboard-data."""
    
    def __init__(self, database):
        self.db = database
    
    def get_dashboard_data(self, user_id: int) -> Dict:
        """
        Hämta all data för användardashboard.
        
        Returns:
            Dict med user, qr, stats, missing_stats
        """
        user = self.db.get_user_by_id(user_id)
        
        if not user:
            raise ValueError("Användare hittades inte.")
        
        return {
            'user': user,
            'qr': self.db.get_user_qr(user_id),
            'stats': self.db.get_user_stats(user_id),
            'missing_stats': self.db.get_user_missing_stats(user_id)
        }


# ============================================================================
# Decorators
# ============================================================================

def login_required(f: Callable) -> Callable:
    """Decorator som kräver inloggning."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        user_id = session.get('user_id')
        
        if not user_id:
            flash('Logga in först.', 'error')
            return redirect(url_for('auth.login'))
        
        # Verifiera att användare fortfarande finns
        user = db.get_user_by_id(user_id)
        if not user:
            session.clear()
            flash('Användare hittades inte.', 'error')
            return redirect(url_for('auth.login'))
        
        g.user_id = user_id
        g.current_user = user
        
        return f(*args, **kwargs)
    
    return decorated_function


def require_ownership(f: Callable) -> Callable:
    """
    Decorator som kräver att användaren äger QR-koden.
    
    Förväntar sig att qr_id finns i kwargs.
    """
    @wraps(f)
    def decorated_function(qr_id, *args, **kwargs):
        validation = QRValidationService.validate(qr_id)
        
        if not validation.is_valid:
            flash(validation.error_message or 'Ogiltigt QR-ID.', 'error')
            return redirect(url_for('disc.dashboard'))
        
        # Hämta och verifiera ägarskap
        qr = db.get_qr(qr_id)
        
        if not qr or qr.get('user_id') != g.user_id:
            flash('Åtkomst nekad.', 'error')
            return redirect(url_for('disc.dashboard'))
        
        g.qr_code = qr
        return f(qr_id, *args, **kwargs)
    
    return decorated_function


# ============================================================================
# Routes
# ============================================================================

@bp.route('/dashboard')
@login_required
def dashboard():
    """Huvudsida för inloggade användare."""
    user_id = session.get('user_id')
    
    try:
        user = db.get_user_by_id(user_id)
        if not user:
            session.clear()
            flash('Användare hittades inte.', 'error')
            return redirect(url_for('auth.login'))
        
        # Hämta ALLA QR-koder för användaren (nu en lista)
        all_qrs = db.get_user_qr_codes(user_id)
        
        # Hämta första aktiva QR-koden för bakåtkompatibilitet
        active_qrs = [qr for qr in all_qrs if qr.get('is_enabled')]
        qr = active_qrs[0] if active_qrs else (all_qrs[0] if all_qrs else None)
        
        stats = db.get_user_stats(user_id)
        missing_stats = db.get_user_missing_stats(user_id)
        
        # Kolla och uppdatera premium-status
        premium_status = db.get_user_premium_status(user_id)
        has_premium = premium_status.get('has_premium', False) if premium_status else False
        is_launch = db.is_launch_period()
        
        # UPPDATERA SESSIONEN med aktuell premium-status
        session['has_premium'] = has_premium
        
        data = {
            'user': user,
            'qr': qr,
            'all_qrs': all_qrs,
            'active_qrs': active_qrs,
            'stats': stats,
            'missing_stats': missing_stats,
            'has_premium': has_premium,
            'is_launch': is_launch,
            'premium_status': premium_status
        }
        
        premium_status = db.get_user_premium_status(user_id)
        print(f"DEBUG: {premium_status}")  # Lägg till detta
        
        return render_template('disc/dashboard.html', **data)
        
    except Exception as e:
        logger.error(f"Dashboard error: {e}")
        flash('Ett fel uppstod. Försök igen.', 'error')
        return redirect(url_for('auth.login'))


@bp.route('/download-qr/<qr_id>')
@login_required
@require_ownership
def download_qr(qr_id):
    """Ladda ner QR-kod som bild från databasen."""
    validation = QRValidationService.validate(qr_id)
    if not validation.is_valid:
        flash('Ogiltigt QR-ID.', 'error')
        return redirect(url_for('disc.dashboard'))
    
    # VIKTIGT: Hämta alltid från databasen först!
    img_buffer = serve_qr_image(qr_id)
    
    if not img_buffer:
        # Om inte i databasen, försök generera ny
        try:
            from utils import create_qr_code
            create_qr_code(qr_id, g.user_id)
            # Försök igen
            img_buffer = serve_qr_image(qr_id)
        except Exception as e:
            logger.error(f"Kunde inte generera QR: {e}")
    
    if not img_buffer:
        flash('QR-kod hittades inte.', 'error')
        return redirect(url_for('disc.dashboard'))
    
    return send_file(
        img_buffer,
        mimetype='image/png',
        as_attachment=True,
        download_name=f"returnadisc-{qr_id}.png"
    )


@bp.route('/download-qr-pdf/<qr_id>')
@login_required
@require_ownership
def download_qr_pdf(qr_id):
    """Ladda ner QR-kod som PDF."""
    download_service = QRDownloadService(current_app.config)
    pdf_path = download_service.get_qr_pdf_path(qr_id)
    
    if not pdf_path:
        flash('Kunde inte generera PDF.', 'error')
        return redirect(url_for('disc.dashboard'))
    
    # Säkerhetskontroll
    pdf_folder = current_app.config.get('PDF_FOLDER', 'static/pdfs')
    if not FileSecurityService.validate_path_within_folder(pdf_path, pdf_folder):
        logger.warning(f"Path traversal attempt in PDF: {qr_id}")
        flash('Ogiltig fil.', 'error')
        return redirect(url_for('disc.dashboard'))
    
    return send_file(
        pdf_path,
        as_attachment=True,
        download_name=f"returnadisc-{qr_id}.pdf"
    )