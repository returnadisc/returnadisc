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
# Email Service - SendGrid API (NY VERSION)
# ============================================================================

class EmailService:
    """Service för att skicka email via SendGrid API."""
    
    def __init__(self):
        self.api_key = os.environ.get('SENDGRID_API_KEY')
        self.enabled = bool(self.api_key)
        self.from_email = "noreply@returnadisc.se"
        self.from_name = "ReturnaDisc"
        
        if not self.enabled:
            logger.warning("SENDGRID_API_KEY saknas - email-funktionen är inaktiverad")
        else:
            logger.info("SendGrid email-service initialiserad")
    
    def send_async(self, to_email: str, subject: str, html_content: str, reply_to: str = None) -> None:
        """Skicka email asynkront via SendGrid API."""
        if not self.enabled:
            logger.warning(f"Email skickades inte till {to_email} - SendGrid API key saknas")
            return
        
        def send():
            try:
                from sendgrid import SendGridAPIClient
                from sendgrid.helpers.mail import Mail, Email, ReplyTo
                
                # Skapa meddelande
                message = Mail(
                    from_email=Email(self.from_email, self.from_name),
                    to_emails=to_email,
                    subject=subject,
                    html_content=html_content
                )
                
                # Sätt reply-to om angivet
                if reply_to:
                    message.reply_to = ReplyTo(reply_to)
                
                # Skicka via SendGrid
                sg = SendGridAPIClient(self.api_key)
                response = sg.send(message)
                
                if response.status_code in [200, 201, 202]:
                    logger.info(f"✅ Email skickat till {to_email} (status: {response.status_code})")
                else:
                    logger.warning(f"⚠️ SendGrid svarade med status: {response.status_code}")
                    
            except Exception as e:
                logger.error(f"❌ Kunde inte skicka email via SendGrid: {e}")
        
        thread = threading.Thread(target=send)
        thread.daemon = True
        thread.start()


# Global email service instance
email_service = EmailService()


def send_email_async(to_email: str, subject: str, html_content: str, plain_text: str = None) -> None:
    """Helper funktion för att skicka email."""
    email_service.send_async(to_email, subject, html_content, plain_text)


# ============================================================================
# QR Code Generation (oförändrad)
# ============================================================================

def generate_random_qr_id(length: int = 5) -> str:
    """Generera ett slumpmässigt QR-ID."""
    import random
    import string
    
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
    
    font_path = 'static/fonts/arial.ttf'
    if not os.path.exists(font_path):
        font_path = 'C:/Windows/Fonts/arial.ttf'
    
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
        
        final_width = 400
        current_width, current_height = new_img.size
        scale = final_width / current_width
        final_height = int(current_height * scale)
        
        qr_img = new_img.resize((final_width, final_height), Image.Resampling.LANCZOS)
        
    except Exception as e:
        logger.error(f"Font fel: {e}")
        raise
    
    filename = f"qr_{qr_id}.png"
    filepath = os.path.join(qr_folder, filename)
    qr_img.save(filepath, quality=95)
    
    logger.info(f"Created QR code: {filename}")
    return filename


def create_small_qr_for_pdf(qr_id: str, size: int = 100) -> io.BytesIO:
    """
    Skapa en liten QR-kod för PDF-användning.
    """
    public_url = getattr(Config, 'PUBLIC_URL', 'http://localhost:5000')
    
    qr = qrcode.QRCode(
        version=1,
        error_correction=qrcode.constants.ERROR_CORRECT_M,
        box_size=5,
        border=2,
    )
    
    qr_url = f"{public_url}/found/{qr_id}"
    qr.add_data(qr_url)
    qr.make(fit=True)
    
    qr_img = qr.make_image(fill_color="black", back_color="white")
    
    if qr_img.mode != 'RGB':
        qr_img = qr_img.convert('RGB')
    
    qr_img = qr_img.resize((size, size), Image.Resampling.LANCZOS)
    
    img_buffer = io.BytesIO()
    qr_img.save(img_buffer, format='PNG')
    img_buffer.seek(0)
    
    return img_buffer


def generate_qr_pdf_for_order(qr_codes: List[Dict], base_url: str) -> str:
    """
    Generera PDF med QR-koder för en order.
    """
    qr_folder = os.environ.get('QR_FOLDER', getattr(Config, 'QR_FOLDER', 'static/qr'))
    pdf_folder = getattr(Config, 'PDF_FOLDER', 'static/pdfs')
    
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    pdf_filename = f"returnadisc_order_{timestamp}.pdf"
    
    os.makedirs(pdf_folder, exist_ok=True)
    
    pdf_path = os.path.join(pdf_folder, pdf_filename)
    
    c = canvas.Canvas(pdf_path, pagesize=A4)
    width, height = A4
    
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
        
        if i > 0 and i % (cols * rows) == 0:
            c.showPage()
        
        x = x_positions[col]
        y = y_start - (row % rows) * (qr_size + y_spacing + 40)
        
        qr_id = qr_data['qr_id']
        qr_filename = qr_data.get('qr_filename', f"qr_{qr_id}.png")
        qr_path = os.path.join(qr_folder, qr_filename)
        
        if os.path.exists(qr_path):
            c.drawImage(qr_path, x, y, width=qr_size, height=qr_size)
        
        c.setFont("Helvetica-Bold", 14)
        c.drawCentredString(x + qr_size/2, y - 20, f"ID: {qr_id}")
        
        c.setFont("Helvetica", 10)
        url_text = f"{base_url}/found/{qr_id}"
        c.drawCentredString(x + qr_size/2, y - 35, url_text)
    
    c.save()
    logger.info(f"Created PDF: {pdf_path}")
    
    return pdf_path


# ============================================================================
# Validation Utilities (oförändrad)
# ============================================================================

def is_valid_email(email: str) -> bool:
    """Validera email-format."""
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return re.match(pattern, email) is not None


def sanitize_input(text: str, max_length: int = 500) -> str:
    """Sanera användarinput."""
    if not text:
        return ""
    
    text = text.strip()
    text = text.replace('<', '&lt;').replace('>', '&gt;')
    
    return text[:max_length]


# ============================================================================
# File Utilities (oförändrad)
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
    
    # Skapa unikt filnamn med timestamp
    name, ext = os.path.splitext(filename)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"{name}_{timestamp}{ext}"
    
    filepath = os.path.join(folder, filename)
    file.save(filepath)
    
    return filename  # Returnera bara filnamnet


def save_uploaded_photo(file, folder: str = None) -> Optional[str]:
    """
    Spara uppladdad foto-fil direkt under uploads/.
    """
    if folder is None:
        folder = getattr(Config, 'UPLOAD_FOLDER', 'static/uploads')
    
    if not allowed_file(file.filename):
        logger.warning(f"Invalid file type: {file.filename}")
        return None
    
    try:
        os.makedirs(folder, exist_ok=True)
        filename = save_uploaded_file(file, folder)
        
        # Returnera relativ sökväg: uploads/filnamn
        return f"uploads/{filename}"
        
    except Exception as e:
        logger.error(f"Failed to save photo: {e}")
        return None


# ============================================================================
# Date/Time Utilities (oförändrad)
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
    admin_email = getattr(Config, 'ADMIN_EMAIL', 'info@returnadisc.se')
    
    subject = f"Ny ReturnaDisc beställning - {user_data['name']}"
    
    html = f"""
    <h2>Ny beställning</h2>
    <p><strong>Namn:</strong> {user_data['name']}</p>
    <p><strong>Email:</strong> {user_data['email']}</p>
    <p><strong>Adress:</strong> {user_data.get('address', 'Saknas')}</p>
    <p><strong>QR-kod:</strong> {qr_id}</p>
    <p>Ladda ner QR-koden: {Config.PUBLIC_URL}/static/qr/qr_{qr_id}.png</p>
    """
    
    send_email_async(admin_email, subject, html)
    
    
def send_email_with_attachment(to_email: str, subject: str, html_content: str, 
                               attachment_path: str = None, attachment_cid: str = None) -> None:
    """Skicka email med bifogad bild via SendGrid API."""
    if not email_service.enabled:
        logger.warning(f"Email skickades inte till {to_email} - SendGrid API key saknas")
        return
    
    def send():
        try:
            from sendgrid import SendGridAPIClient
            from sendgrid.helpers.mail import Mail, Email, Attachment, FileContent, FileName, FileType, Disposition, ContentId
            
            # Skapa meddelande med HTML som huvudinnehåll
            message = Mail(
                from_email=Email(email_service.from_email, email_service.from_name),
                to_emails=to_email,
                subject=subject,
                html_content=html_content  # HTML är huvudinnehållet, inte attachment
            )
            
            # Bifoga bild som inline om angiven
            if attachment_path and os.path.exists(attachment_path):
                with open(attachment_path, 'rb') as f:
                    data = f.read()
                
                encoded = base64.b64encode(data).decode()
                
                attachment = Attachment()
                attachment.file_content = FileContent(encoded)
                attachment.file_name = FileName(os.path.basename(attachment_path))
                attachment.file_type = FileType('image/jpeg')
                attachment.disposition = Disposition('inline')
                attachment.content_id = ContentId(attachment_cid)
                
                message.add_attachment(attachment)
                logger.info(f"Bifogade bild: {attachment_path}")
            
            sg = SendGridAPIClient(email_service.api_key)
            response = sg.send(message)
            
            if response.status_code in [200, 201, 202]:
                logger.info(f"✅ Email skickat till {to_email} (status: {response.status_code})")
            else:
                logger.warning(f"⚠️ SendGrid svarade med status: {response.status_code}")
                
        except Exception as e:
            logger.error(f"❌ Kunde inte skicka email via SendGrid: {e}")
    
    thread = threading.Thread(target=send)
    thread.daemon = True
    thread.start()
