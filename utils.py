<<<<<<< HEAD
﻿"""Utils."""
import logging
import os
import re
import secrets
import qrcode
from datetime import datetime
from threading import Thread
from PIL import Image, ImageDraw, ImageFont

from flask import current_app
from werkzeug.utils import secure_filename
from reportlab.pdfgen import canvas
from reportlab.lib.pagesizes import A4
from sendgrid import SendGridAPIClient
from sendgrid.helpers.mail import Mail, Attachment, FileContent, FileName, FileType, Disposition

logger = logging.getLogger(__name__)


def send_email_async(to_email, subject, html_content, attachments=None):
    """Skicka email asynkront via SendGrid med valfria bilagor."""
    def send():
        try:
            sg = SendGridAPIClient(os.environ.get('SENDGRID_API_KEY'))
            
            message = Mail(
                from_email='noreply@returnadisc.se',
                to_emails=to_email,
                subject=subject,
                html_content=html_content
            )
            
            # Lägg till bilagor om det finns
            if attachments:
                for file_path in attachments:
                    if os.path.exists(file_path):
                        with open(file_path, 'rb') as f:
                            data = f.read()
                            
                        # Bestäm filtyp baserat på filändelse
                        if file_path.lower().endswith('.pdf'):
                            file_type = "application/pdf"
                        elif file_path.lower().endswith('.png'):
                            file_type = "image/png"
                        elif file_path.lower().endswith(('.jpg', '.jpeg')):
                            file_type = "image/jpeg"
                        else:
                            file_type = "application/octet-stream"
                        
                        encoded = base64.b64encode(data).decode()
                        attachment = Attachment()
                        attachment.file_content = FileContent(encoded)
                        attachment.file_name = FileName(os.path.basename(file_path))
                        attachment.file_type = FileType(file_type)
                        attachment.disposition = Disposition('attachment')
                        message.add_attachment(attachment)
            
            response = sg.send(message)
            logger.info(f"Email sent to {to_email}: {response.status_code}")
            
        except Exception as e:
            logger.error(f"Failed to send email to {to_email}: {str(e)}")
    
    Thread(target=send).start()
    return True


def save_uploaded_photo(photo, prefix):
    """Spara uppladdad bild."""
    if not photo or photo.filename == '':
        return None
    
    filename = secure_filename(f"{prefix}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.jpg")
    filepath = os.path.join('static', 'uploads', filename)
    os.makedirs(os.path.dirname(filepath), exist_ok=True)
    photo.save(filepath)
    return '/' + filepath.replace('\\', '/')


def sanitize_input(text):
    """Rensa input."""
    if not text:
        return ''
    text = re.sub(r'[<>\"\'%;()&+]', '', text)
    return text.strip()


def generate_random_qr_id(length=5):
    """Generera slumpmässig QR-kod. Undvik Q, I, O, 0, 1."""
    alphabet = 'ABCDEFGHJKLMNPRSTUVWXYZ23456789'
    return ''.join(secrets.choice(alphabet) for _ in range(length))


def generate_qr_pdf(qr_id, base_url):
    """Generera PDF med QR-kod."""
    from config import Config
    
    pdf_path = f"static/pdfs/qr_{qr_id}.pdf"
    os.makedirs(os.path.dirname(pdf_path), exist_ok=True)
=======
﻿"""Hjälpfunktioner - NYA med 5-6 tecken, utan förväxlingsbara bokstäver."""
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
>>>>>>> 9429973fcd56ea78bdf3b3958182bb9ff21391be
    
    c = canvas.Canvas(pdf_path, pagesize=A4)
    width, height = A4
    
<<<<<<< HEAD
    qr_path = f"static/qr/qr_{qr_id}.png"
    if os.path.exists(qr_path):
        c.drawImage(qr_path, width/2 - 100, height/2 - 100, width=200, height=200)
    
    c.drawString(100, 100, f"ID: {qr_id}")
    c.drawString(100, 80, f"URL: {base_url}/found/{qr_id}")
=======
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
>>>>>>> 9429973fcd56ea78bdf3b3958182bb9ff21391be
    
    c.save()
    return pdf_path


<<<<<<< HEAD
def create_qr_code(qr_id, user_id=None):
    """
    Skapa QR-kod bild:
    - QR-kod i mitten (mindre för att få plats med text)
    - returnadisc.se direkt under (nära)
    - ID underst (blått)
    """
    from config import Config
    
    url = f"{Config.PUBLIC_URL}/found/{qr_id}"
    
    qr = qrcode.QRCode(
        version=2,
        error_correction=qrcode.constants.ERROR_CORRECT_H,
        box_size=10,
        border=2,
    )
    qr.add_data(url)
    qr.make(fit=True)
    
    # Större bild för att få plats med allt
    size = 400
    img = Image.new('RGB', (size, size), 'white')
    draw = ImageDraw.Draw(img)
    
    qr_img = qr.make_image(fill_color="black", back_color="white")
    qr_img = qr_img.convert('RGB')
    
    # Mindre QR för att få plats med text
    qr_size = 250
    qr_img = qr_img.resize((qr_size, qr_size))
    
    # QR i mitten, lägre för att ge plats åt text ovanför
    qr_y = 50
    qr_pos = ((size - qr_size) // 2, qr_y)
    img.paste(qr_img, qr_pos)
    
    try:
        font_url = ImageFont.truetype("arial.ttf", 28)
        font_id = ImageFont.truetype("arial.ttf", 42)
    except:
        font_url = ImageFont.load_default()
        font_id = ImageFont.load_default()
    
    # returnadisc.se - nära under QR (bara 5px mellanrum)
    url_text = "returnadisc.se"
    bbox = draw.textbbox((0, 0), url_text, font=font_url)
    text_width = bbox[2] - bbox[0]
    url_y = qr_y + qr_size + 5
    draw.text(((size - text_width) // 2, url_y), url_text, fill='#6b7280', font=font_url)
    
    # ID - under returnadisc.se (tight)
    id_text = qr_id
    bbox = draw.textbbox((0, 0), id_text, font=font_id)
    text_width = bbox[2] - bbox[0]
    id_y = url_y + 35
    draw.text(((size - text_width) // 2, id_y), id_text, fill='#2563eb', font=font_id)
    
    filename = f"qr_{qr_id}.png"
    filepath = os.path.join('static', 'qr', filename)
    os.makedirs(os.path.dirname(filepath), exist_ok=True)
    img.save(filepath, 'PNG', quality=95)
    
    return filename
=======
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
>>>>>>> 9429973fcd56ea78bdf3b3958182bb9ff21391be
