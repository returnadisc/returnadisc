"""Utils."""
import logging
import os
import re
import secrets
import base64
import qrcode
from datetime import datetime
from threading import Thread
from PIL import Image, ImageDraw, ImageFont

from flask import current_app
from werkzeug.utils import secure_filename
from reportlab.pdfgen import canvas
from reportlab.lib.pagesizes import A4
from reportlab.lib.units import cm
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


def create_qr_code(qr_id, user_id=None):
    """
    Skapa QR-kod bild för skärmvisning:
    - QR-kod i mitten
    - returnadisc.se direkt under
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
    
    # Större bild för skärmvisning
    size = 400
    img = Image.new('RGB', (size, size), 'white')
    draw = ImageDraw.Draw(img)
    
    qr_img = qr.make_image(fill_color="black", back_color="white")
    qr_img = qr_img.convert('RGB')
    
    # Mindre QR för att få plats med text
    qr_size = 250
    qr_img = qr_img.resize((qr_size, qr_size))
    
    # QR i mitten
    qr_y = 40
    qr_pos = ((size - qr_size) // 2, qr_y)
    img.paste(qr_img, qr_pos)
    
    try:
        font_url = ImageFont.truetype("arial.ttf", 28)
        font_id = ImageFont.truetype("arial.ttf", 48)
    except:
        font_url = ImageFont.load_default()
        font_id = ImageFont.load_default()
    
    # returnadisc.se - under QR
    url_text = "returnadisc.se"
    bbox = draw.textbbox((0, 0), url_text, font=font_url)
    text_width = bbox[2] - bbox[0]
    url_y = qr_y + qr_size + 15
    draw.text(((size - text_width) // 2, url_y), url_text, fill='#6b7280', font=font_url)
    
    # ID - under returnadisc.se (stor och blå)
    id_text = qr_id
    bbox = draw.textbbox((0, 0), id_text, font=font_id)
    text_width = bbox[2] - bbox[0]
    id_y = url_y + 40
    draw.text(((size - text_width) // 2, id_y), id_text, fill='#2563eb', font=font_id)
    
    filename = f"qr_{qr_id}.png"
    filepath = os.path.join('static', 'qr', filename)
    os.makedirs(os.path.dirname(filepath), exist_ok=True)
    img.save(filepath, 'PNG', quality=95)
    
    return filename


def create_small_qr_for_pdf(qr_id, base_url):
    """
    Skapa liten QR-kod för utskrift (2.5 cm):
    - QR-kod 2.5 cm
    - returnadisc.se (liten text)
    - ID (tydlig text)
    """
    from config import Config
    
    url = f"{base_url}/found/{qr_id}"
    
    qr = qrcode.QRCode(
        version=2,
        error_correction=qrcode.constants.ERROR_CORRECT_H,
        box_size=10,
        border=2,
    )
    qr.add_data(url)
    qr.make(fit=True)
    
    # 2.5 cm = ~118 pixlar vid 120 DPI (lämplig för utskrift)
    # Men vi gör större för bättre kvalitet, sen skalas ner i PDF
    qr_size_px = 236  # 2.5 cm vid 240 DPI
    
    # Total bildstorlek: QR + textutrymme
    total_size = 280
    img = Image.new('RGB', (total_size, total_size), 'white')
    draw = ImageDraw.Draw(img)
    
    qr_img = qr.make_image(fill_color="black", back_color="white")
    qr_img = qr_img.convert('RGB')
    
    # QR-kod i mitten (2.5 cm motsvarande)
    qr_display_size = 200
    qr_img = qr_img.resize((qr_display_size, qr_display_size))
    qr_y = 20
    qr_pos = ((total_size - qr_display_size) // 2, qr_y)
    img.paste(qr_img, qr_pos)
    
    try:
        font_url = ImageFont.truetype("arial.ttf", 14)
        font_id = ImageFont.truetype("arial.ttf", 22)
    except:
        font_url = ImageFont.load_default()
        font_id = ImageFont.load_default()
    
    # returnadisc.se - liten text under QR
    url_text = "returnadisc.se"
    bbox = draw.textbbox((0, 0), url_text, font=font_url)
    text_width = bbox[2] - bbox[0]
    url_y = qr_y + qr_display_size + 5
    draw.text(((total_size - text_width) // 2, url_y), url_text, fill='#6b7280', font=font_url)
    
    # ID - tydlig text underst
    id_text = qr_id
    bbox = draw.textbbox((0, 0), id_text, font=font_id)
    text_width = bbox[2] - bbox[0]
    id_y = url_y + 22
    draw.text(((total_size - text_width) // 2, id_y), id_text, fill='#2563eb', font=font_id)
    
    return img


def generate_qr_pdf(count, base_url):
    """Generera PDF med flera QR-koder för utskrift (2.5 cm per QR)."""
    from database import db
    
    pdf_path = "static/pdfs/qr_batch.pdf"
    os.makedirs(os.path.dirname(pdf_path), exist_ok=True)
    
    # Generera nya QR-koder
    qr_codes = []
    for _ in range(count):
        qr_id = generate_random_qr_id()
        
        # Spara i databasen
        try:
            db.create_qr(qr_id)
            # Skapa vanlig QR-bild för webben
            create_qr_code(qr_id)
            qr_codes.append(qr_id)
        except Exception as e:
            logger.error(f"Failed to create QR {qr_id}: {e}")
            continue
    
    if not qr_codes:
        raise Exception("Inga QR-koder kunde skapas")
    
    # Skapa PDF
    c = canvas.Canvas(pdf_path, pagesize=A4)
    width, height = A4
    
    # Exakt storlek 2.5 cm
    qr_size = 2.5 * cm
    gap = 0.8 * cm
    
    x_start = 1.5 * cm
    y_start = height - 2 * cm
    
    qr_index = 0
    
    for qr_id in qr_codes:
        # Beräkna position
        col = qr_index % 5
        row = qr_index // 5
        
        x = x_start + col * (qr_size + gap)
        y = y_start - row * (qr_size + gap + 0.5 * cm)
        
        if y < 2 * cm:
            c.showPage()
            qr_index = 0
            col = 0
            row = 0
            x = x_start
            y = y_start
        
        # Skapa liten QR-bild för PDF
        qr_img = create_small_qr_for_pdf(qr_id, base_url)
        
        # Spara temporärt
        temp_path = f"static/pdfs/temp_{qr_id}.png"
        qr_img.save(temp_path, 'PNG')
        
        # Rita i PDF
        c.drawImage(temp_path, x, y - qr_size, width=qr_size, height=qr_size)
        
        # Rensa temporär fil
        os.remove(temp_path)
        
        qr_index += 1
    
    c.save()
    return pdf_path