"""Utility-funktioner för ReturnaDisc."""
import logging
import secrets
import os
import re
import threading
import base64
import io
from datetime import datetime
from typing import Optional, List, Dict, Tuple

import qrcode
from PIL import Image, ImageDraw, ImageFont
from reportlab.lib.pagesizes import A4
from reportlab.pdfgen import canvas
from reportlab.lib.utils import ImageReader

from config import Config

logger = logging.getLogger(__name__)


# ============================================================================
# Email Service
# ============================================================================

class EmailService:
    """Service för att skicka email."""
    
    def __init__(self):
        # Hantera saknade config-värden
        self.enabled = getattr(Config, 'EMAIL_ENABLED', False)
        self.smtp_server = getattr(Config, 'SMTP_SERVER', None)
        self.smtp_port = getattr(Config, 'SMTP_PORT', 587)
        self.email_from = getattr(Config, 'EMAIL_FROM', None)
        self.email_user = getattr(Config, 'EMAIL_USER', None)
        self.email_password = getattr(Config, 'EMAIL_PASSWORD', None)
    
    def send_async(self, to_email: str, subject: str, html_content: str) -> None:
        """Skicka email asynkront."""
        if not self.enabled:
            logger.info(f"Email disabled. Would send to {to_email}: {subject}")
            return
        
        if not all([self.smtp_server, self.email_from, self.email_user, self.email_password]):
            logger.warning("Email config incomplete, cannot send email")
            return
        
        def send():
            try:
                import smtplib
                from email.mime.text import MIMEText
                from email.mime.multipart import MIMEMultipart
                
                msg = MIMEMultipart('alternative')
                msg['Subject'] = subject
                msg['From'] = self.email_from
                msg['To'] = to_email
                
                msg.attach(MIMEText(html_content, 'html'))
                
                with smtplib.SMTP(self.smtp_server, self.smtp_port) as server:
                    server.starttls()
                    server.login(self.email_user, self.email_password)
                    server.sendmail(self.email_from, [to_email], msg.as_string())
                
                logger.info(f"Email sent to {to_email}")
            except Exception as e:
                logger.error(f"Failed to send email: {e}")
        
        thread = threading.Thread(target=send)
        thread.daemon = True
        thread.start()


# Global email service instance
email_service = EmailService()


def send_email_async(to_email: str, subject: str, html_content: str) -> None:
    """Helper funktion för att skicka email."""
    email_service.send_async(to_email, subject, html_content)


# ============================================================================
# QR Code Generation
# ============================================================================

def generate_random_qr_id(length: int = 5) -> str:
    """Generera ett slumpmässigt QR-ID."""
    import random
    import string
    
    # Använd versaler och siffror, undvik I, O, Q, 1, 0 för att undvika förväxling
    chars = ''.join(c for c in (string.ascii_uppercase + string.digits) 
                   if c not in 'IOQ10')
    return ''.join(random.choices(chars, k=length))


def create_qr_code(qr_id: str, user_id: Optional[int] = None) -> str:
    """
    Skapa QR-kod bild och spara den.
    """
    qr_folder = os.environ.get('QR_FOLDER', getattr(Config, 'QR_FOLDER', 'static/qr'))
    public_url = getattr(Config, 'PUBLIC_URL', 'http://localhost:5000')
    
    os.makedirs(qr_folder, exist_ok=True)
    
    # Hitta font - först i projektmappen, sedan systemet
    font_path = 'static/fonts/arial.ttf'
    if not os.path.exists(font_path):
        font_path = 'C:/Windows/Fonts/arial.ttf'
    
    # Skapa QR-kod
    qr = qrcode.QRCode(
        version=1,
        error_correction=qrcode.constants.ERROR_CORRECT_H,
        box_size=20,
        border=2,
    )
    
    qr_url = f"{public_url}/found/{qr_id}"
    qr.add_data(qr_url)
    qr.make(fit=True)
    
    qr_img = qr.make_image(fill_color="black", back_color="white")
    
    if qr_img.mode != 'RGB':
        qr_img = qr_img.convert('RGB')
    
    try:
        # Ladda samma font lokalt och online
        font_large = ImageFont.truetype(font_path, 112)
        font_small = ImageFont.truetype(font_path, 72)
        
        draw = ImageDraw.Draw(qr_img)
        
        text_se = "returnadisc.se"
        text_id = qr_id
        
        bbox_se = draw.textbbox((0, 0), text_se, font=font_small)
        width_se = bbox_se[2] - bbox_se[0]
        height_se = bbox_se[3] - bbox_se[1]
        bbox_id = draw.textbbox((0, 0), text_id, font=font_large)
        width_id = bbox_id[2] - bbox_id[0]
        height_id = bbox_id[3] - bbox_id[1]
        
        width, height = qr_img.size
        
        margin_top = 16
        line_spacing = 10
        margin_bottom = 30
        
        total_text_height = margin_top + height_se + line_spacing + height_id + margin_bottom
        
        new_height = height + int(total_text_height)
        new_img = Image.new('RGB', (width, new_height), 'white')
        new_img.paste(qr_img, (0, 0))
        
        draw = ImageDraw.Draw(new_img)
        
        x_se = (width - int(width_se)) // 2
        y_se = height + margin_top
        draw.text((x_se, y_se), text_se, fill='#888888', font=font_small)
        
        x_id = (width - int(width_id)) // 2
        y_id = y_se + height_se + line_spacing
        draw.text((x_id, y_id), text_id, fill='#0066CC', font=font_large)
        
        # Skala till 400px
        final_width = 400
        current_width, current_height = new_img.size
        scale = final_width / current_width
        final_height = int(current_height * scale)
        
        qr_img = new_img.resize((final_width, final_height), Image.Resampling.LANCZOS)
        
    except Exception as e:
        logger.error(f"Font fel: {e}")
        raise  # Kasta felet så du ser vad som gick snett
    
    filename = f"qr_{qr_id}.png"
    filepath = os.path.join(qr_folder, filename)
    qr_img.save(filepath, quality=95)
    
    logger.info(f"Created QR code: {filename}")
    return filename


def create_small_qr_for_pdf(qr_id: str, size: int = 100) -> io.BytesIO:
    """
    Skapa en liten QR-kod för PDF-användning.
    
    Args:
        qr_id: QR-kodens ID
        size: Storlek i pixlar (default 100)
    
    Returns:
        BytesIO objekt med PNG-bilden
    """
    public_url = getattr(Config, 'PUBLIC_URL', 'http://localhost:5000')
    
    # Skapa QR-kod
    qr = qrcode.QRCode(
        version=1,
        error_correction=qrcode.constants.ERROR_CORRECT_M,
        box_size=5,
        border=2,
    )
    
    qr_url = f"{public_url}/found/{qr_id}"
    qr.add_data(qr_url)
    qr.make(fit=True)
    
    # Skapa bild
    qr_img = qr.make_image(fill_color="black", back_color="white")
    
    # Konvertera till RGB om nödvändigt
    if qr_img.mode != 'RGB':
        qr_img = qr_img.convert('RGB')
    
    # Resize till önskad storlek
    qr_img = qr_img.resize((size, size), Image.Resampling.LANCZOS)
    
    # Spara till BytesIO
    img_buffer = io.BytesIO()
    qr_img.save(img_buffer, format='PNG')
    img_buffer.seek(0)
    
    return img_buffer


def generate_qr_pdf_for_order(qr_codes: List[Dict], base_url: str) -> str:
    """
    Generera PDF med QR-koder för en order.
    
    Args:
        qr_codes: Lista med dicts innehållande 'qr_id' och 'qr_filename'
        base_url: Bas-URL för applikationen
    
    Returns:
        Sökväg till genererad PDF
    """
    # Hämta folders från config eller använd default
    qr_folder = os.environ.get('QR_FOLDER', getattr(Config, 'QR_FOLDER', 'static/qr'))
    pdf_folder = getattr(Config, 'PDF_FOLDER', 'static/pdfs')
    
    # Skapa PDF
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    pdf_filename = f"returnadisc_order_{timestamp}.pdf"
    
    # Skapa mappen om den inte finns
    os.makedirs(pdf_folder, exist_ok=True)
    
    pdf_path = os.path.join(pdf_folder, pdf_filename)
    
    c = canvas.Canvas(pdf_path, pagesize=A4)
    width, height = A4
    
    # Marginaler och layout
    margin = 50
    qr_size = 200
    cols = 2
    rows = 3
    x_spacing = (width - 2 * margin - cols * qr_size) / (cols - 1) if cols > 1 else 0
    y_spacing = 50
    
    x_positions = [margin + i * (qr_size + x_spacing) for i in range(cols)]
    y_start = height - margin - qr_size
    
    for i, qr_data in enumerate(qr_codes):
        col = i % cols
        row = i // cols
        
        # Ny sida om nödvändigt
        if i > 0 and i % (cols * rows) == 0:
            c.showPage()
        
        x = x_positions[col]
        y = y_start - (row % rows) * (qr_size + y_spacing + 40)
        
        qr_id = qr_data['qr_id']
        qr_filename = qr_data.get('qr_filename', f"qr_{qr_id}.png")
        qr_path = os.path.join(qr_folder, qr_filename)
        
        # Rita QR-kod
        if os.path.exists(qr_path):
            c.drawImage(qr_path, x, y, width=qr_size, height=qr_size)
        
        # Rita ID under QR-koden
        c.setFont("Helvetica-Bold", 14)
        c.drawCentredString(x + qr_size/2, y - 20, f"ID: {qr_id}")
        
        # Rita URL
        c.setFont("Helvetica", 10)
        url_text = f"{base_url}/found/{qr_id}"
        c.drawCentredString(x + qr_size/2, y - 35, url_text)
    
    c.save()
    logger.info(f"Created PDF: {pdf_path}")
    
    return pdf_path


# ============================================================================
# Validation Utilities
# ============================================================================

def is_valid_email(email: str) -> bool:
    """Validera email-format."""
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return re.match(pattern, email) is not None


def sanitize_input(text: str, max_length: int = 500) -> str:
    """Sanera användarinput."""
    if not text:
        return ""
    
    # Ta bort farliga tecken
    text = text.strip()
    text = text.replace('<', '&lt;').replace('>', '&gt;')
    
    # Begränsa längd
    return text[:max_length]


# ============================================================================
# File Utilities
# ============================================================================

def allowed_file(filename: str, allowed_extensions: set = None) -> bool:
    """Kontrollera om filändelse är tillåten."""
    if allowed_extensions is None:
        allowed_extensions = {'png', 'jpg', 'jpeg', 'gif', 'webp'}
    
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in allowed_extensions


def save_uploaded_file(file, folder: str, filename: str = None) -> str:
    """Spara uppladdad fil."""
    if filename is None:
        from werkzeug.utils import secure_filename
        filename = secure_filename(file.filename)
    
    # Lägg till timestamp för att undvika kollisioner
    name, ext = os.path.splitext(filename)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"{name}_{timestamp}{ext}"
    
    filepath = os.path.join(folder, filename)
    file.save(filepath)
    
    return filename


def save_uploaded_photo(file, folder: str = None) -> Optional[str]:
    """
    Spara uppladdad foto-fil.
    
    Args:
        file: Flask file object
        folder: Mapp att spara i (default: UPLOAD_FOLDER från config)
    
    Returns:
        Filnamnet på den sparade filen, eller None om fel
    """
    if folder is None:
        folder = getattr(Config, 'UPLOAD_FOLDER', 'static/uploads')
    
    # Kontrollera att filen är tillåten
    if not allowed_file(file.filename):
        logger.warning(f"Invalid file type: {file.filename}")
        return None
    
    try:
        # Skapa mappen om den inte finns
        os.makedirs(folder, exist_ok=True)
        
        # Spara filen
        filename = save_uploaded_file(file, folder)
        logger.info(f"Saved photo: {filename}")
        return filename
        
    except Exception as e:
        logger.error(f"Failed to save photo: {e}")
        return None


# ============================================================================
# Date/Time Utilities
# ============================================================================

def format_datetime(dt: datetime, format_str: str = "%Y-%m-%d %H:%M") -> str:
    """Formatera datetime till läsbar sträng."""
    if dt is None:
        return "N/A"
    return dt.strftime(format_str)


def time_ago(dt: datetime) -> str:
    """Returnera 'för X tid sedan' sträng."""
    if dt is None:
        return "N/A"
    
    now = datetime.now()
    diff = now - dt
    
    seconds = diff.total_seconds()
    minutes = seconds / 60
    hours = minutes / 60
    days = hours / 24
    
    if seconds < 60:
        return "nyss"
    elif minutes < 60:
        return f"för {int(minutes)} minuter sedan"
    elif hours < 24:
        return f"för {int(hours)} timmar sedan"
    elif days < 30:
        return f"för {int(days)} dagar sedan"
    else:
        return format_datetime(dt)
        
        
def notify_admin_new_order(user_data: dict, qr_id: str):
    """Skicka email till admin vid ny beställning."""
    admin_email = "info@returnadisc.se"  # Byt till din riktiga email
    
    subject = f"Ny ReturnaDisc beställning - {user_data['name']}"
    
    html = f"""
    <h2>Ny beställning</h2>
    <p><strong>Namn:</strong> {user_data['name']}</p>
    <p><strong>Email:</strong> {user_data['email']}</p>
    <p><strong>Adress:</strong> {user_data.get('address', 'Saknas')}</p>
    <p><strong>QR-kod:</strong> {qr_id}</p>
    <p>Ladda ner QR-koden: https://returnadisc.se/static/qr/qr_{qr_id}.png</p>
    """
    
    send_email_async(admin_email, subject, html)