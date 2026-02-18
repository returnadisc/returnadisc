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


def create_qr_with_design(qr_id: str, public_url: str, target_size: int = None) -> Image.Image:
    """
    Skapa QR-kod med ReturnaDisc-design.
    """
    # 1. Skapa QR-koden
    qr = qrcode.QRCode(
        version=4,
        error_correction=qrcode.constants.ERROR_CORRECT_H,
        box_size=12,
        border=2,
    )
    
    qr_url = f"{public_url}/found/{qr_id}"
    qr.add_data(qr_url)
    qr.make(fit=True)
    
    # 2. Generera QR-bilden
    qr_img = qr.make_image(fill_color="black", back_color="white")
    qr_img = qr_img.convert('RGB')
    
    qr_width, qr_height = qr_img.size
    
    # 3. Fasta, säkra storlekar
    try:
        font_domain = ImageFont.truetype("static/fonts/arial.ttf", 28)
        font_id = ImageFont.truetype("static/fonts/arial.ttf", 36)
    except:
        font_domain = ImageFont.load_default()
        font_id = ImageFont.load_default()
    
    # 4. Mät texten först
    temp_draw = ImageDraw.Draw(Image.new('RGB', (1, 1)))
    
    bbox_d = temp_draw.textbbox((0, 0), "returnadisc.se", font=font_domain)
    domain_h = bbox_d[3] - bbox_d[1]
    
    bbox_i = temp_draw.textbbox((0, 0), qr_id, font=font_id)
    id_h = bbox_i[3] - bbox_i[1]
    
    # 5. Beräkna total höjd (QR + luft + domän + mellanrum + ID + botten)
    total_height = qr_height + 5 + domain_h + 8 + id_h + 10
    
    # 6. Skapa bild
    final_img = Image.new('RGB', (qr_width, total_height), 'white')
    final_img.paste(qr_img, (0, 0))
    draw = ImageDraw.Draw(final_img)
    
    # 7. Rita domän (centra)
    domain_w = bbox_d[2] - bbox_d[0]
    x_d = (qr_width - domain_w) // 2
    y_d = qr_height + 5
    draw.text((x_d, y_d), "returnadisc.se", fill="#666666", font=font_domain)
    
    # 8. Rita ID (centra)
    id_w = bbox_i[2] - bbox_i[0]
    x_i = (qr_width - id_w) // 2
    y_i = y_d + domain_h + 8
    draw.text((x_i, y_i), qr_id, fill="#000000", font=font_id)
    
    # 9. Skala om för PDF om nödvändigt
    if target_size:
        final_img = final_img.resize((target_size, target_size), Image.Resampling.LANCZOS)
    
    return final_img


def create_qr_code(qr_id: str, user_id: Optional[int] = None) -> str:
    """
    Skapa QR-kod bild med ReturnaDisc-design och spara den.
    """
    
    logger = logging.getLogger(__name__)
    
    # Konfiguration
    qr_folder = os.environ.get('QR_FOLDER', getattr(Config, 'QR_FOLDER', 'static/qr'))
    public_url = getattr(Config, 'PUBLIC_URL', 'http://localhost:5000')
    
    logger.info(f"=== QR CODE DEBUG ===")
    logger.info(f"qr_id: {qr_id}")
    
    # Skapa mappen
    try:
        os.makedirs(qr_folder, exist_ok=True)
    except Exception as e:
        logger.error(f"Failed to create folder: {e}")
        raise
        
    filename = f"qr_{qr_id}.png"
    filepath = os.path.join(qr_folder, filename)
    
    # Skapa QR med design
    final_img = create_qr_with_design(qr_id, public_url)
    
    # Spara bilden
    logger.info(f"Saving to: {filepath}")
    try:
        final_img.save(filepath, 'PNG', quality=95)
        logger.info(f"File saved successfully")
    except Exception as e:
        logger.error(f"Failed to save file: {e}")
        raise
    
    logger.info(f"=== END QR DEBUG ===")
    return filename


def create_small_qr_for_pdf(qr_id: str, size: int = 200) -> io.BytesIO:
    """
    Skapa en QR-kod med design för PDF-användning.
    """
    public_url = getattr(Config, 'PUBLIC_URL', 'http://localhost:5000')
    
    # Skapa QR med design och skala ner
    final_img = create_qr_with_design(qr_id, public_url, target_size=size)
    
    img_buffer = io.BytesIO()
    final_img.save(img_buffer, format='PNG')
    img_buffer.seek(0)
    
    return img_buffer


def generate_qr_pdf_for_order(qr_codes: List[Dict], base_url: str) -> str:
    """
    Generera PDF med QR-koder för en order.
    """
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
        y = y_start - (row % rows) * (qr_size + y_spacing)
        
        qr_id = qr_data['qr_id']
        
        # Skapa QR med design direkt (ingen extra text under)
        try:
            qr_buffer = create_small_qr_for_pdf(qr_id, size=qr_size)
            c.drawImage(ImageReader(qr_buffer), x, y, width=qr_size, height=qr_size)
        except Exception as e:
            logger.error(f"Kunde inte rita QR {qr_id} i PDF: {e}")
    
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
