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


def crop_qr_tight(qr_img):
    """Beskär QR-kod aggressivt - ta bort ALLT vitt runt kanterna."""
    # Konvertera till RGB om nödvändigt
    if qr_img.mode != 'RGB':
        qr_img = qr_img.convert('RGB')
    
    width, height = qr_img.size
    
    # Hitta bounds genom att scanna pixlar
    left = width
    right = 0
    top = height
    bottom = 0
    
    # Ladda pixeldata
    pixels = qr_img.load()
    
    # Hitta första och sista raden med svart (eller mörk)
    for y in range(height):
        for x in range(width):
            r, g, b = pixels[x, y]
            # Om pixeln är mörk (inte vit)
            if r < 200 or g < 200 or b < 200:
                if y < top:
                    top = y
                if y > bottom:
                    bottom = y
                if x < left:
                    left = x
                if x > right:
                    right = x
    
    # Om vi hittade något, beskär
    if left < right and top < bottom:
        # Lägg till liten padding (2 pixlar)
        left = max(0, left - 2)
        top = max(0, top - 2)
        right = min(width, right + 2)
        bottom = min(height, bottom + 2)
        return qr_img.crop((left, top, right, bottom))
    
    return qr_img


def create_qr_code(qr_id, user_id=None):
    """
    Skapa QR-kod bild för skärmvisning:
    - QR-kod i mitten (tight crop)
    - returnadisc.se direkt under
    - ID underst (blått)
    """
    from config import Config
    
    url = f"{Config.PUBLIC_URL}/found/{qr_id}"
    
    # Skapa QR med INGEN border för tightaste möjliga
    qr = qrcode.QRCode(
        version=2,
        error_correction=qrcode.constants.ERROR_CORRECT_H,
        box_size=10,
        border=0,  # INGEN border - vi hanterar allt själva
    )
    qr.add_data(url)
    qr.make(fit=True)
    
    # Generera QR-bild
    qr_img = qr.make_image(fill_color="black", back_color="white")
    qr_img = qr_img.convert('RGB')
    
    # BESKÄR bort allt vitt runt QR-koden
    qr_cropped = crop_qr_tight(qr_img)
    
    # Nu bygger vi slutbilden med beskärdd QR + text
    # QR-storlek: ca 280x280 för bra kvalitet
    qr_display_size = 280
    qr_resized = qr_cropped.resize((qr_display_size, qr_display_size), Image.Resampling.LANCZOS)
    
    # Typsnitt
    try:
        font_url = ImageFont.truetype("arial.ttf", 28)
        font_id = ImageFont.truetype("arial.ttf", 48)
    except:
        font_url = ImageFont.load_default()
        font_id = ImageFont.load_default()
    
    # Mät text för att beräkna bildstorlek
    test_img = Image.new('RGB', (600, 400), 'white')
    test_draw = ImageDraw.Draw(test_img)
    
    url_bbox = test_draw.textbbox((0, 0), "returnadisc.se", font=font_url)
    id_bbox = test_draw.textbbox((0, 0), qr_id, font=font_id)
    
    url_height = url_bbox[3] - url_bbox[1]
    id_height = id_bbox[3] - id_bbox[1]
    url_width = url_bbox[2] - url_bbox[0]
    id_width = id_bbox[2] - id_bbox[1]
    
    # Beräkna total bildstorlek - justerad padding
    top_padding = 20        # ÄNDRAT: Tidigare 0, nu 20 pixlar padding i toppen
    qr_to_url_gap = 12      # Mellan QR och URL
    url_to_id_gap = 6       # Mellan URL och ID
    bottom_padding = 20     # Under ID
    
    total_width = max(qr_display_size, url_width, id_width) + 40  # 20px padding vardera sida
    total_height = (top_padding +
                    qr_display_size + 
                    qr_to_url_gap + 
                    url_height + 
                    url_to_id_gap + 
                    id_height + 
                    bottom_padding)
    
    # Skapa slutgiltig bild
    img = Image.new('RGB', (total_width, total_height), 'white')
    draw = ImageDraw.Draw(img)
    
    # QR centrerad med padding i toppen
    qr_x = (total_width - qr_display_size) // 2
    qr_y = top_padding  # ÄNDRAT: Använder top_padding istället för 0
    img.paste(qr_resized, (qr_x, qr_y))
    
    # returnadisc.se - centrerad under QR
    url_x = (total_width - url_width) // 2
    url_y = qr_y + qr_display_size + qr_to_url_gap
    draw.text((url_x, url_y), "returnadisc.se", fill='#6b7280', font=font_url)
    
    # ID - centrerad underst, blått
    id_x = (total_width - id_width) // 2
    id_y = url_y + url_height + url_to_id_gap
    draw.text((id_x, id_y), qr_id, fill='#2563eb', font=font_id)
    
    # Spara
    filename = f"qr_{qr_id}.png"
    filepath = os.path.join('static', 'qr', filename)
    os.makedirs(os.path.dirname(filepath), exist_ok=True)
    img.save(filepath, 'PNG', quality=95)
    
    return filename


def create_small_qr_for_pdf(qr_id, base_url):
    """
    Skapa liten QR-kod för utskrift (2.5 cm):
    - QR-kod 2.5 cm (tight crop)
    - returnadisc.se (liten text)
    - ID (tydlig text)
    """
    from config import Config
    
    url = f"{base_url}/found/{qr_id}"
    
    # Skapa QR med INGEN border
    qr = qrcode.QRCode(
        version=1,
        error_correction=qrcode.constants.ERROR_CORRECT_M,
        box_size=12,
        border=0,
    )
    qr.add_data(url)
    qr.make(fit=True)
    
    # Generera bild
    qr_img = qr.make_image(fill_color="black", back_color="white")
    qr_img = qr_img.convert('RGB')
    
    # BESKÄR aggressivt
    qr_cropped = crop_qr_tight(qr_img)
    
    # Resize till exakt 2.5 cm (236 pixlar vid 240 DPI)
    target_qr_size = 236
    qr_resized = qr_cropped.resize((target_qr_size, target_qr_size), Image.Resampling.LANCZOS)
    
    # Skapa bild med QR + text, minimal padding
    padding = 8
    
    # Typsnitt
    try:
        font_url = ImageFont.truetype("arial.ttf", 12)
        font_id = ImageFont.truetype("arial.ttf", 20)
    except:
        font_url = ImageFont.load_default()
        font_id = ImageFont.load_default()
    
    # Mät text för att beräkna slutgiltig storlek
    test_img = Image.new('RGB', (400, 200), 'white')
    test_draw = ImageDraw.Draw(test_img)
    
    url_bbox = test_draw.textbbox((0, 0), "returnadisc.se", font=font_url)
    id_bbox = test_draw.textbbox((0, 0), qr_id, font=font_id)
    
    url_height = url_bbox[3] - url_bbox[1]
    id_height = id_bbox[3] - id_bbox[1]
    
    # Beräkna total storlek
    text_gap = 2
    qr_to_text_gap = 4
    
    content_height = target_qr_size + qr_to_text_gap + url_height + text_gap + id_height
    total_width = target_qr_size + (padding * 2)
    total_height = content_height + padding + 4
    
    # Skapa slutgiltig bild
    img = Image.new('RGB', (total_width, total_height), 'white')
    draw = ImageDraw.Draw(img)
    
    # Klistra in QR
    qr_x = padding
    qr_y = padding
    img.paste(qr_resized, (qr_x, qr_y))
    
    # URL-text centrerad
    url_text = "returnadisc.se"
    url_width = url_bbox[2] - url_bbox[0]
    url_x = (total_width - url_width) // 2
    url_y = qr_y + target_qr_size + qr_to_text_gap
    draw.text((url_x, url_y), url_text, fill='#6b7280', font=font_url)
    
    # ID-text centrerad
    id_width = id_bbox[2] - id_bbox[0]
    id_x = (total_width - id_width) // 2
    id_y = url_y + url_height + text_gap
    draw.text((id_x, id_y), qr_id, fill='#2563eb', font=font_id)
    
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
    
    
def generate_qr_pdf_for_order(qr_codes, base_url):
    """
    Generera PDF för en specifik order med färdiga QR-koder.
    qr_codes: lista med dicts innehållande 'qr_id'
    """
    import os
    from reportlab.pdfgen import canvas
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.units import cm
    
    pdf_path = "static/pdfs/order_qr_batch.pdf"
    os.makedirs(os.path.dirname(pdf_path), exist_ok=True)
    
    c = canvas.Canvas(pdf_path, pagesize=A4)
    width, height = A4
    
    # Exakt storlek 2.5 cm
    qr_size = 2.5 * cm
    gap = 0.8 * cm
    
    x_start = 1.5 * cm
    y_start = height - 2 * cm
    
    qr_index = 0
    
    for qr_item in qr_codes:
        qr_id = qr_item['qr_id'] if isinstance(qr_item, dict) else qr_item
        
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