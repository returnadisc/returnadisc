"""Hjälpfunktioner - NYA med 5-6 tecken, utan förväxlingsbara bokstäver."""
import os
import secrets
import string
import logging
import threading
from datetime import datetime
from typing import Optional

import qrcode
from PIL import Image, ImageDraw
from werkzeug.utils import secure_filename
from sendgrid import SendGridAPIClient
from sendgrid.helpers.mail import Mail

from config import Config
from database import db

logger = logging.getLogger(__name__)

# Förbjudna tecken: 0, O, I, 1, Q (förväxlingsbara)
ALLOWED_CHARS = 'ABCDEFGHJKLMNPRSTUVWXYZ23456789'


def generate_qr_id(length: int = 5) -> str:
    """Generera QR-ID utan förväxlingsbara tecken."""
    return ''.join(secrets.choice(ALLOWED_CHARS) for _ in range(length))


def allowed_file(filename: str) -> bool:
    """Kolla om filändelse är tillåten."""
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in Config.ALLOWED_EXTENSIONS


def save_uploaded_photo(file, prefix: str) -> Optional[str]:
    """Spara och komprimera uppladdad bild."""
    if not file or not allowed_file(file.filename):
        return None
    
    ext = secure_filename(file.filename).rsplit('.', 1)[1].lower()
    filename = f"{prefix}_{int(datetime.now().timestamp())}.jpg"
    filepath = os.path.join(Config.UPLOAD_FOLDER, filename)
    
    try:
        img = Image.open(file.stream)
        if img.mode in ('RGBA', 'LA', 'P'):
            img = img.convert('RGB')
        
        max_size = (1920, 1920)
        img.thumbnail(max_size, Image.Resampling.LANCZOS)
        img.save(filepath, 'JPEG', quality=85, optimize=True)
        
        return filepath.replace('\\', '/')
    except Exception as e:
        logger.error(f"Failed to process image: {e}")
        return None


def generate_qr_pdf(count: int, base_url: str) -> str:
    """Generera PDF med QR-koder."""
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.units import cm
    from reportlab.pdfgen import canvas
    
    os.makedirs(Config.PDF_FOLDER, exist_ok=True)
    os.makedirs(Config.QR_FOLDER, exist_ok=True)
    
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    pdf_path = os.path.join(Config.PDF_FOLDER, f"qr_labels_{timestamp}.pdf")
    
    c = canvas.Canvas(pdf_path, pagesize=A4)
    width, height = A4
    
    qr_size = 2.5 * cm
    margin_x = 1.5 * cm
    margin_y = 2 * cm
    spacing_x = 1 * cm
    spacing_y = 1.5 * cm
    
    x = margin_x
    y = height - margin_y
    col = 0
    per_row = 4
    
    for i in range(count):
        qr_id = generate_qr_id()
        qr_url = f"{base_url}/found/{qr_id}"
        
        # Skapa QR-bild
        img = qrcode.make(qr_url, border=1)
        img_path = os.path.join(Config.QR_FOLDER, f"{qr_id}.png")
        img.save(img_path)
        
        # Spara i databas
        db.create_qr(qr_id)
        
        # Rita i PDF
        c.drawImage(img_path, x, y - qr_size, qr_size, qr_size)
        
        c.setFont("Helvetica-Bold", 8)
        c.drawCentredString(x + qr_size/2, y - qr_size - 0.2*cm, "returnadisc.se")
        
        c.setFont("Helvetica", 6)
        c.drawCentredString(x + qr_size/2, y - qr_size - 0.5*cm, qr_id)
        
        x += qr_size + spacing_x
        col += 1
        
        if col >= per_row:
            col = 0
            x = margin_x
            y -= qr_size + spacing_y
            
            if y < margin_y + qr_size:
                c.showPage()
                y = height - margin_y
    
    c.save()
    return pdf_path


def send_email_async(to_email: str, subject: str, html_content: str):
    """Skicka mail asynkront."""
    def send():
        if not Config.SENDGRID_API_KEY:
            logger.warning("Ingen SendGrid API key")
            return
        
        try:
            sg = SendGridAPIClient(Config.SENDGRID_API_KEY.strip())
            message = Mail(
                from_email=Config.MAIL_DEFAULT_SENDER,
                to_emails=to_email,
                subject=subject,
                html_content=html_content
            )
            response = sg.send(message)
            logger.info(f"Email skickat till {to_email}, status: {response.status_code}")
        except Exception as e:
            logger.error(f"Failed to send email: {e}")
    
    thread = threading.Thread(target=send)
    thread.start()


def sanitize_input(text: str, max_length: int = 1000) -> str:
    """Rensa användar-input."""
    import bleach
    if not text:
        return ""
    text = text[:max_length]
    allowed_tags = ['b', 'i', 'em', 'strong', 'p', 'br']
    return bleach.clean(text, tags=allowed_tags, strip=True)