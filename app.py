import os
import sqlite3
from datetime import datetime
from flask import Flask, request, session, redirect, url_for
import qrcode
from sendgrid import SendGridAPIClient
from sendgrid.helpers.mail import Mail
from utils import generate_disc_id
from reportlab.lib.pagesizes import A4
from reportlab.pdfgen import canvas
from reportlab.lib.units import cm
from reportlab.lib.colors import black, HexColor
from PIL import Image, ImageDraw
import tempfile
from flask import send_file
from werkzeug.security import generate_password_hash, check_password_hash
import secrets
import time



ADMIN_EMAIL = "admin@returnadisc.se"
ADMIN_PASSWORD_HASH = generate_password_hash("admin123")



BASE_URL = "https://toxicological-loida-viscously.ngrok-free.dev"




def current_user():
    user_id = session.get("user_id")
    if not user_id:
        return None

    conn = sqlite3.connect(DB_PATH, timeout=10)
    cur = conn.cursor()
    cur.execute(
        "SELECT id, name, email FROM users WHERE id = ?",
        (user_id,)
    )
    row = cur.fetchone()
    conn.close()

    if not row:
        return None

    return {
        "id": row[0],
        "name": row[1],
        "email": row[2]
    }



def page(content):
    return f"""
    <html>
    <head>
        <meta name="viewport" content="width=device-width, initial-scale=1">
        <style>
            body {{
                margin: 0;
                font-family: system-ui, -apple-system, BlinkMacSystemFont, sans-serif;
                background: #f2f4f8;
            }}

            .card {{
                max-width: 420px;
                margin: 40px auto;
                background: white;
                padding: 24px;
                border-radius: 16px;
                box-shadow: 0 10px 25px rgba(0,0,0,0.1);
                text-align: center;
            }}

            h1, h2 {{
                margin-top: 0;
            }}

            input, textarea {{
                width: 100%;
                padding: 14px;
                margin: 8px 0;
                border-radius: 10px;
                border: 1px solid #ccc;
                font-size: 16px;
            }}

            button {{
                width: 100%;
                padding: 16px;
                margin-top: 12px;
                border: none;
                border-radius: 12px;
                background: #2563eb;
                color: white;
                font-size: 16px;
                font-weight: 600;
            }}

            button:hover {{
                background: #1e40af;
            }}

            .secondary {{
                background: #e5e7eb;
                color: #111827;
            }}
        </style>
    </head>
    <body>
        <div class="card">
            {content}
        </div>
    </body>
    </html>
    """


DB_PATH = "database.db"

def ensure_tables():
    conn = sqlite3.connect(DB_PATH, timeout=10)
    cur = conn.cursor()

    cur.execute("""
    CREATE TABLE IF NOT EXISTS discs (
        disc_id TEXT PRIMARY KEY,
        disc_name TEXT,
        owner_name TEXT,
        owner_email TEXT,
        user_id INTEGER,
        is_active INTEGER DEFAULT 0,
        created_at TEXT,
        activated_at TEXT
    )
    """)

    # säkerställ att user_id finns i gamla databaser
    try:
        cur.execute("ALTER TABLE discs ADD COLUMN user_id INTEGER")
    except:
        pass



    cur.execute("""
    CREATE TABLE IF NOT EXISTS handovers (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        disc_id TEXT,
        action TEXT,
        note TEXT,
        created_at TEXT,
        latitude REAL,
        longitude REAL
    )
    """)

    cur.execute("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        email TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        reset_token TEXT,
        created_at TEXT NOT NULL
    )

    """)

    try:
        cur.execute("ALTER TABLE users ADD COLUMN reset_token TEXT")
        cur.execute("ALTER TABLE users ADD COLUMN password TEXT")
    except:
        pass




    conn.commit()
    conn.close()

app = Flask(__name__)
app.config["SESSION_COOKIE_SECURE"] = True
os.environ["ADMIN_KEY"] = "hemlig123"
app.secret_key = os.environ.get("SECRET_KEY", "dev-secret-change-me")
ensure_tables()



SENDGRID_API_KEY = os.environ.get("SENDGRID_API_KEY")

print("SendGrid key loaded:", bool(SENDGRID_API_KEY))


# ---------- DB HELPERS ----------

def get_disc(disc_id):
    conn = sqlite3.connect(DB_PATH, timeout=10)
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()
    cur.execute("SELECT * FROM discs WHERE disc_id = ?", (disc_id,))
    disc = cur.fetchone()
    conn.close()
    return disc

# ---------- MAIL ----------

def send_owner_mail(to_email, subject, body):

    print("=== SENDING MAIL ===")
    print("To:", to_email)

    if not SENDGRID_API_KEY:
        print("NO SENDGRID KEY")
        return

    message = Mail(
        from_email="noreply@returnadisc.se",
        to_emails=to_email,
        subject=subject,
        html_content=body
    )

    try:
        sg = SendGridAPIClient(SENDGRID_API_KEY)
        response = sg.send(message)

        print("MAIL STATUS:", response.status_code)

    except Exception as e:
        print("MAIL FAILED:")
        print(e)



# ---------- ROUTES ----------

@app.route("/found/<disc_id>", methods=["GET"])
def found(disc_id):

    disc = get_disc(disc_id)

    if not disc or not disc["is_active"]:
        return page("""
        <h2>Discen är inte aktiverad</h2>

        <p>
            Den här QR-koden är inte kopplad till någon ägare ännu.
        </p>

        <p>
            Ägaren behöver logga in och aktivera sin disc först.
        </p>

        <a href="/">
            <button>OK</button>
        </a>
        """)

    html = f"""
    <h2>Du har hittat en disc 🥏</h2>

    <h3>Vad vill du göra?</h3>

    <p>
        <a href="/found/{disc_id}/hide">
            <button style="font-size:18px;padding:16px 24px;">
                📍 Jag gömmer discen
            </button>
        </a>
    </p>

    <p>Skickar position 📡 + foto till ägaren 📷</p>

    <hr>

    <p>
        <a href="/found/{disc_id}/meet">
            <button class="secondary">
                🤝 Jag vill mötas
            </button>
        </a>
    </p>

    <p>
        <a href="/found/{disc_id}/note">
            <button class="secondary">
                ✍️ Lämna meddelande
            </button>
        </a>
    </p>
    """

    return page(html)



@app.route("/found/<disc_id>/hide", methods=["GET", "POST"])
def found_hide(disc_id):

    disc = get_disc(disc_id)

    if not disc or not disc["is_active"]:
        return page("<p>Disc ej aktiv.</p>")

    if request.method == "POST":

        note = request.form.get("note", "").strip()

        photo = request.files.get("photo")
        photo_path = None
        image_html = ""

        if photo and photo.filename:
            filename = f"{disc_id}_{int(time.time())}.jpg"
            photo_path = f"static/uploads/{filename}"
            photo.save(photo_path)

        latitude = request.form.get("latitude")
        longitude = request.form.get("longitude")

        conn = sqlite3.connect(DB_PATH, timeout=10)
        cur = conn.cursor()

        cur.execute("""
        INSERT INTO handovers (disc_id, action, note, created_at, latitude, longitude)
        VALUES (?, ?, ?, ?, ?, ?)
        """, (
            disc_id,
            "gömde",
            note,
            datetime.utcnow().isoformat(),
            latitude,
            longitude
        ))

        cur.execute("""
        SELECT disc_name, owner_email
        FROM discs
        WHERE disc_id = ?
        """, (disc_id,))

        disc_row = cur.fetchone()

        conn.commit()
        conn.close()

        maps_link = ""
        if latitude and longitude:
            maps_link = (
                f'<p><a href="https://maps.google.com/?q={latitude},{longitude}">'
                f'📍 Öppna position i Google Maps</a></p>'
            )

        if photo_path:
            base_url = os.environ.get("BASE_URL", request.host_url.rstrip("/"))
            image_url = f"{base_url}/{photo_path}"

            image_html = (
                f'<p><a href="{image_url}">Visa bilden</a></p>'
                f'<p><img src="{image_url}" width="300"></p>'
            )

        instructions = ""

        if maps_link and image_html:
            instructions = "Följ kartan och bilden nedan för att hitta din disc."
        elif maps_link:
            instructions = "Följ kartlänken nedan för att hitta din disc."
        elif image_html:
            instructions = "Se bilden nedan för att hitta din disc."

        mail_body = f"""
        <p>Goda nyheter — någon har gömt din disc på en säker plats 🥏.</p>
        <p>{instructions}</p>
        <p>{note}</p>
        {maps_link}
        {image_html}
        """

        send_owner_mail(
            disc_row[1],
            f"Din disc {disc_row[0]} är gömd",
            mail_body
        )

        return page("""
        <h2>Tack för hjälpen! 🥏</h2>

        <p>En disc är på väg hem tack vare dig.</p>

        <a href="/">
            <button>returnadisc.se</button>
        </a>
        """)

    html = """
    <h2>Ge discen ett tryggt gömställe 📍</h2>

    <p id="gps">📡 Hämtar position...</p>

    <form method="post" enctype="multipart/form-data">

        <textarea name="note" placeholder="Var gömde du discen?"></textarea>

        <input type="file" id="photo" name="photo" accept="image/*" capture="environment" style="display:none">

        <button type="button" onclick="document.getElementById('photo').click()">
            📸 Ta foto (valfritt)
        </button>

        <p id="photo-status"></p>

        <input type="hidden" name="latitude" id="lat">
        <input type="hidden" name="longitude" id="lng">

        <button type="submit">Skicka till ägaren</button>

    </form>

    <script>
    navigator.geolocation.getCurrentPosition(function(pos) {
        document.getElementById("lat").value = pos.coords.latitude;
        document.getElementById("lng").value = pos.coords.longitude;
        document.getElementById("gps").innerText = "✅ Position sparad";
    });

    document.getElementById("photo").addEventListener("change", function() {
        document.getElementById("photo-status").innerText = "✅ Bild vald";
    });
    </script>
    """

    return page(html)




@app.route("/found/<disc_id>/meet", methods=["GET", "POST"])
def found_meet(disc_id):

    disc = get_disc(disc_id)

    if not disc or not disc["is_active"]:
        return page("<p>Disc ej aktiv.</p>")

    if request.method == "POST":

        note = request.form.get("note", "").strip()

        conn = sqlite3.connect(DB_PATH, timeout=10)
        cur = conn.cursor()

        cur.execute("""
        INSERT INTO handovers (disc_id, action, note, created_at)
        VALUES (?, ?, ?, ?)
        """, (
            disc_id,
            "möte",
            note,
            datetime.utcnow().isoformat()
        ))

        cur.execute("""
        SELECT disc_name, owner_email
        FROM discs
        WHERE disc_id = ?
        """, (disc_id,))

        disc_row = cur.fetchone()

        conn.commit()
        conn.close()

        send_owner_mail(
            disc_row[1],
            f"Någon vill mötas för {disc_row[0]}",
            f"<p>{note}</p>"
        )

        return page("""
        <h2>Meddelande skickat ✅</h2>
        <p>Ägaren har fått dina kontaktuppgifter.</p>
        """)

    html = """
    <h2>Lämna kontakt för möte 🤝</h2>

    <p>
        Lämna dina kontaktuppgifter så kan ägaren höra av sig.
    </p>

    <form method="post">
        <textarea name="note" placeholder="T.ex. namn + telefonnummer" required></textarea>

        <p>
            <button type="submit">
                Skicka till ägaren
            </button>
        </p>
    </form>
    """

    return page(html)



@app.route("/found/<disc_id>/note", methods=["GET", "POST"])
def found_note(disc_id):

    disc = get_disc(disc_id)

    if not disc or not disc["is_active"]:
        return page("<p>Disc ej aktiv.</p>")

    if request.method == "POST":

        note = request.form.get("note", "").strip()

        conn = sqlite3.connect(DB_PATH, timeout=10)
        cur = conn.cursor()

        cur.execute("""
        INSERT INTO handovers (disc_id, action, note, created_at)
        VALUES (?, ?, ?, ?)
        """, (
            disc_id,
            "meddelande",
            note,
            datetime.utcnow().isoformat()
        ))

        cur.execute("""
        SELECT disc_name, owner_email
        FROM discs
        WHERE disc_id = ?
        """, (disc_id,))

        disc_row = cur.fetchone()

        conn.commit()
        conn.close()


        send_owner_mail(
            disc_row[1],
            f"Meddelande om {disc_row[0]}",
            f"<p>{note}</p>"
        )

        return page("""
        <h2>Meddelande skickat ✅</h2>
        """)

    html = """
    <h2>Lämna meddelande ✍️</h2>

    <form method="post">
        <textarea name="note" placeholder="Skriv ditt meddelande..." required></textarea>

        <p>
            <button type="submit">
                Skicka
            </button>
        </p>
    </form>
    """

    return page(html)



@app.route("/admin/create", methods=["GET"])
def create_disc_web():
    if os.environ.get("ADMIN_KEY") != request.args.get("key"):
        return "Åtkomst nekad", 403

    html = """
    <h2>Admin – Skapa QR-PDF</h2>

    <form method="post" action="/admin/qr-pdf?key=""" + request.args.get("key") + """">
        <label>Antal QR:</label><br>
        <input name="count" type="number" min="1" max="500" value="10">
        <br><br>
        <button type="submit">Skapa QR-PDF</button>
    </form>

<form method="post" action="/admin/reset?key=""" + request.args.get("key") + """">
    <button style="background:red;color:white;">
        ⚠️ Nollställ databasen
    </button>
</form>


    """
    return page(html)





@app.route("/activate/<disc_id>", methods=["GET", "POST"])
def activate(disc_id):

    user = current_user()

    disc = get_disc(disc_id)

    if not disc:
        return "Disc finns inte", 404

    # Om redan aktiv → found
    if disc["is_active"]:
        return redirect(f"/found/{disc_id}")

    # Ej inloggad → visa login
    if not user:
        return page("""
        <h2>Aktivera disc</h2>

        <p>Du måste logga in för att registrera denna disc.</p>

        <a href="/login">
            <button>Logga in</button>
        </a>
        """)

    # POST = aktivera
    if request.method == "POST":

        disc_name = request.form.get("disc_name", "").strip()

        conn = sqlite3.connect(DB_PATH, timeout=10)
        cur = conn.cursor()

        cur.execute("""
        UPDATE discs
        SET disc_name = ?, owner_name = ?, owner_email = ?,
            user_id = ?, is_active = 1, activated_at = ?
        WHERE disc_id = ?
        """, (
            disc_name,
            user["name"],
            user["email"],
            user["id"],
            datetime.utcnow().isoformat(),
            disc_id
        ))

        conn.commit()
        conn.close()

        return page("""
        <h2>Disc aktiverad!</h2>

        <a href="/dashboard">
            <button>Till dashboard</button>
        </a>
        """)

    # GET = visa formulär
    html = f"""
    <h2>Aktivera din disc</h2>

    <p>Disc ID: <b>{disc_id}</b></p>

    <form method="post">
        <input name="disc_name" placeholder="Discens namn" required>
        <button type="submit">Aktivera</button>
    </form>
    """

    return page(html)




@app.route("/")
def home():
    html = """
    <h1>ReturnaDisc</h1>
    <p>QR-system för att hjälpa borttappade discar hitta hem.</p>

    <a href="/signup">
        <button>Ny användare – skapa konto</button>
    </a>

    <a href="/login">
        <button class="secondary">Logga in</button>
    </a>

    <hr style="margin:20px 0;">

    <p style="font-size:14px;color:#555;">
        Har du hittat en disc? Skanna QR-koden på discen för att hjälpa ägaren.
    </p>
    """
    return page(html)




@app.route("/how")
def how():
    html = """
    <div style="max-width:400px;margin:40px auto;font-family:sans-serif;">
        <h2>Så funkar ReturnaDisc</h2>
        <ol>
            <li>Skapa din disc och få en QR-kod</li>
            <li>Sätt QR-sticker på discen</li>
            <li>Om någon hittar den, skannar de koden</li>
            <li>Du får mail direkt</li>
        </ol>
        <a href="/">
            <button style="width:100%;padding:15px;">
                Tillbaka
            </button>
        </a>
    </div>
    """
    return page(html)

@app.route("/signup", methods=["GET", "POST"])
def signup():
    if request.method == "POST":
        name = request.form.get("name", "").strip()
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "").strip()
        password_hash = generate_password_hash(password)


        if not name or not email or not password:
            return page("<p>Fyll i alla fält.</p>")

        conn = sqlite3.connect(DB_PATH, timeout=10)
        cur = conn.cursor()

        try:
            cur.execute("""
            INSERT INTO users (name, email, password, created_at)
            VALUES (?, ?, ?, ?)
            """, (
                name,
                email,
                password_hash,
                datetime.utcnow().isoformat()
            ))

            conn.commit()

        except sqlite3.IntegrityError:
            conn.close()
            return page("<p>Det finns redan ett konto med den emailen.</p>")

        user_id = cur.lastrowid
        conn.close()

        session["user_id"] = user_id
        return redirect(url_for("dashboard"))

    html = """
    <h2>Skapa konto</h2>
    <form method="post">
        <input name="name" placeholder="Förnamn + Efternamn" required>
        <input name="email" type="email" placeholder="Email" required>
        <input name="password" type="password" placeholder="Lösenord" required>
        <button type="submit">Skapa konto</button>
    </form>
    """
    return page(html)



@app.route("/my-discs")
def my_discs():
    user = current_user()
    if not user:
        return redirect("/login")

    conn = sqlite3.connect(DB_PATH, timeout=10)
    cur = conn.cursor()

    cur.execute("""
    SELECT disc_id, disc_name, is_active, activated_at
    FROM discs
    WHERE user_id = ?
       OR owner_email = ?
    ORDER BY activated_at DESC
    """, (
        user["id"],
        user["email"]
    ))

    discs = cur.fetchall()
    conn.close()

    html = "<h2>Mina discar</h2>"

    if not discs:
        html += "<p>Du har inga registrerade discar ännu.</p>"
    else:
        html += "<ul>"
        for disc_id, disc_name, is_active, activated_at in discs:
            status = "Aktiv" if is_active else "Ej aktiverad"
            html += f"""
            <li>
                <b>{disc_name or "Namnlös disc"}</b><br>
                ID: {disc_id}<br>
                Status: {status}
            </li>
            <br>
            """
        html += "</ul>"

    return page(html)




@app.route("/login", methods=["GET", "POST"])
def login():
    error = ""
    message = session.pop("login_message", "")


    if request.method == "POST":

        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "").strip()

        conn = sqlite3.connect(DB_PATH, timeout=10)
        cur = conn.cursor()

        cur.execute(
            "SELECT id, password FROM users WHERE email = ?",
            (email,)
        )
        row = cur.fetchone()
        conn.close()

        if not row or not check_password_hash(row[1], password):
            error = "Fel email eller lösenord."

        else:
            session["user_id"] = row[0]
            return redirect("/dashboard")

    html = f"""
    <h2>Logga in</h2>

    {"<p style='color:red;'>" + error + "</p>" if error else ""}
    {"<div style='background:#ecfdf5;padding:12px;border-radius:8px;margin-bottom:12px;color:#065f46;'>" + message + "</div>" if message else ""}



    <form method="post">
        <input name="email" type="email" placeholder="Email" required>
        <input name="password" type="password" placeholder="Lösenord" required>
        <button type="submit">Logga in</button>
    </form>

    <p><a href="/forgot-password">Glömt lösenord?</a></p>
    """

    return page(html)






@app.route("/dashboard")
def dashboard():
    user = current_user()
    if not user:
        return redirect(url_for("login"))

    discs = get_user_discs(user["id"], user["email"])

    items = ""

    for d in discs:
        status = "🟢 Aktiv" if d[2] else "⚪ Inaktiv"

        items += f"""
        <div style="
            text-align:left;
            padding:16px;
            margin:12px 0;
            border-radius:12px;
            background:#f9fafb;
            border:1px solid #e5e7eb;
        ">
            <h3 style="margin:0 0 6px 0;">
                {d[1] if d[1] else "Namnlös disc"}
            </h3>

            <p style="margin:4px 0;">Status: {status}</p>
            <p style="margin:4px 0;">Hittad: {d[3]} gånger</p>

            <a href="/qr/{d[0]}">
                <button class="secondary">
                    Visa QR
                </button>
            </a>
        </div>
        """

    if not items:
        items = "<p>Du har inga registrerade discar ännu.</p>"

    html = f"""
    <h2>Välkommen, {user['name']}</h2>

    <p>
        <a href="/scan">
            <button style="font-size:18px;padding:14px 22px;">
                📷 Scanna QR för att aktivera disc
            </button>
        </a>
    </p>


    <a href="/create-qr">
        <button>Skapa nya QR-koder</button>
    </a>

    <p>Mina discar</p>

    {items}

    <a href="/logout">
        <button class="secondary">Logga ut</button>
    </a>
    """

    return page(html)




@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("home"))



def get_user_discs(user_id, user_email):
    conn = sqlite3.connect(DB_PATH, timeout=10)
    cur = conn.cursor()

    cur.execute("""
    SELECT disc_id, disc_name, is_active,
           (SELECT COUNT(*) FROM handovers WHERE handovers.disc_id = discs.disc_id)
    FROM discs
    WHERE user_id = ?
       OR owner_email = ?
    ORDER BY activated_at DESC
    """, (
        user_id,
        user_email
    ))

    rows = cur.fetchall()
    conn.close()
    return rows




@app.route("/qr/<disc_id>")
def view_qr(disc_id):
    user = current_user()
    if not user:
        return redirect(url_for("login"))

    conn = sqlite3.connect(DB_PATH, timeout=10)
    cur = conn.cursor()

    cur.execute("""
    SELECT disc_id
    FROM discs
    WHERE disc_id = ?
      AND user_id = ?
    """, (disc_id, user["id"]))


    row = cur.fetchone()
    conn.close()

    if not row:
        return "Ingen åtkomst", 403

    img_url = f"/static/qr/{disc_id}.png"

    html = f"""
    <h2>QR-kod</h2>
    <p>Visa denna för att låta någon skanna din disc.</p>

    <img src="{img_url}" style="width:100%;max-width:300px;">
    <p><b>Disc-ID:</b> {disc_id}</p>


    <a href="/dashboard">
        <button class="secondary">Tillbaka</button>
    </a>
    """
    return page(html)



@app.route("/admin/bulk", methods=["GET"])
def admin_bulk():
    if os.environ.get("ADMIN_KEY") != request.args.get("key"):
        return "Åtkomst nekad", 403

    from reportlab.lib.pagesizes import A4
    from reportlab.lib.units import cm
    from reportlab.pdfgen import canvas
    from PIL import Image, ImageDraw

    count = 10
    base_url = request.host_url.rstrip("/")
    os.makedirs("static/qr", exist_ok=True)

    pdf_path = "static/qr/bulk_qr.pdf"

    c = canvas.Canvas(pdf_path, pagesize=A4)
    width, height = A4

    label_size = 2.5 * cm
    qr_size = 1.9 * cm
    margin_x = 2 * cm
    margin_y = 2 * cm
    spacing_x = 4 * cm
    spacing_y = 4 * cm

    cols = int((width - margin_x * 2) // spacing_x)

    x = margin_x
    y = height - margin_y

    col = 0

    for i in range(count):
        disc_id = generate_disc_id()
        qr_url = f"{BASE_URL}/found/{disc_id}"


        # Skapa QR
        img = qrcode.make(qr_url).convert("RGBA")

        # Gör rund mask
        size = img.size
        mask = Image.new("L", size, 0)
        draw = ImageDraw.Draw(mask)
        draw.ellipse((0, 0, size[0], size[1]), fill=255)
        img.putalpha(mask)

        qr_path = f"static/qr/{disc_id}.png"
        img.save(qr_path)

        # Spara i DB
        conn = sqlite3.connect(DB_PATH, timeout=10)
        cur = conn.cursor()
        cur.execute(
            "INSERT INTO discs (disc_id, created_at) VALUES (?, datetime('now'))",
            (disc_id,)
        )
        conn.commit()
        conn.close()

        # Rita QR
        c.drawImage(qr_path, x, y - qr_size, qr_size, qr_size, mask="auto")

        # Centrerad text
        c.setFont("Helvetica", 8)
        c.drawCentredString(x + qr_size / 2, y - qr_size - 10, disc_id)

        col += 1
        x += spacing_x

        if col >= cols:
            col = 0
            x = margin_x
            y -= spacing_y

        if y < margin_y + qr_size:
            c.showPage()
            x = margin_x
            y = height - margin_y
            col = 0

    c.save()

    
    return page(f"""
        <h2>QR-koder skapade ✅</h2>

        <p>Antal genererade QR-koder: <b>{count}</b></p>

    <p>
        <a href="/{pdf_path}">
            <button style="font-size:18px;padding:14px 22px;">
                📄 Ladda ner PDF
            </button>
        </a>
    </p>

    <p>
        <a href="/admin/create">
            <button class="secondary">
                Skapa fler QR-koder
            </button>
        </a>
    </p>

    <p>
        <a href="/dashboard">
            <button class="secondary">
                Till dashboard
            </button>
        </a>
    </p>
    """)





def generate_qr_pdf(count, base_url):
    os.makedirs("static/qr", exist_ok=True)

    os.makedirs("static/pdfs", exist_ok=True)

    pdf_path = "static/pdfs/qr_labels.pdf"
    c = canvas.Canvas(pdf_path, pagesize=A4)

    width, height = A4

    qr_size = 2.5 * cm
    margin_x = 1.5 * cm
    margin_y = 2 * cm

    spacing_x = 1 * cm
    spacing_y = 1.5 * cm

    x = margin_x
    y = height - margin_y

    conn = sqlite3.connect(DB_PATH, timeout=10)
    cur = conn.cursor()

    per_row = 4
    col = 0

    for i in range(count):
        disc_id = generate_disc_id()
        qr_url = f"{BASE_URL}/activate/{disc_id}"


        cur.execute(
            "INSERT INTO discs (disc_id, created_at) VALUES (?, datetime('now'))",
            (disc_id,)
        )

        img = qrcode.make(qr_url)
        img_path = f"static/qr/{disc_id}.png"
        img.save(img_path)

        c.drawImage(img_path, x, y - qr_size, qr_size, qr_size)

        c.setFont("Helvetica", 8)
        c.setFont("Helvetica-Bold", 7)
        c.drawCentredString(x + qr_size / 2, y - qr_size - 0.15 * cm, "returnadisc.se")

        c.setFont("Helvetica", 6)
        c.drawCentredString(x + qr_size / 2, y - qr_size - 0.45 * cm, disc_id)




        x += qr_size + spacing_x
        col += 1

        if col >= per_row:
            col = 0
            x = margin_x
            y -= qr_size + spacing_y

            if y < 3 * cm:
                c.showPage()
                y = height - margin_y

    conn.commit()
    conn.close()

    c.save()

    return pdf_path




@app.route("/admin/qr-pdf", methods=["POST"])
def qr_pdf():
    if os.environ.get("ADMIN_KEY") != request.args.get("key"):
        return "Åtkomst nekad", 403

    count = int(request.form.get("count", 10))
    base_url = "https://toxicological-loida-viscously.ngrok-free.dev"


    pdf_path = generate_qr_pdf(count, base_url)

    return page(f"""
    <h2>QR-koder skapade ✅</h2>

    <p>Antal genererade QR-koder: <b>{count}</b></p>

    <p>
        <a href="/{pdf_path}">
            <button style="font-size:18px;padding:14px 22px;">
                📄 Ladda ner PDF
            </button>
        </a>
    </p>

    <p>
        <a href="/admin/create?key=hemlig123">
            <button class="secondary">
                Skapa fler QR-koder
            </button>
        </a>
    </p>
    """)


@app.route("/admin/reset-passwords")
def reset_passwords():
    conn = sqlite3.connect(DB_PATH, timeout=10)
    cur = conn.cursor()

    default_hash = generate_password_hash("changeme123")

    cur.execute("""
        UPDATE users
        SET password = ?
        WHERE password IS NULL OR password = ''
    """, (default_hash,))

    conn.commit()
    conn.close()

    return "Gamla konton uppdaterade. Lösenord: changeme123"


@app.route("/create-qr", methods=["GET", "POST"])
def create_qr():
    user = current_user()
    if not user:
        return redirect(url_for("login"))

    if request.method == "POST":
        count = int(request.form.get("count", 1))

        if count > 30:
            return page("""
            <h2>För många QR</h2>
            <p>Max 30 QR per gång.</p>
            <p>Behöver du fler? Kontakta returnadisc.se</p>
            <a href="/dashboard"><button>Tillbaka</button></a>
            """)

        pdf_path = generate_qr_pdf(count, BASE_URL)

        return send_file(pdf_path, as_attachment=True)

    html = """
    <h2>Skapa QR-koder</h2>
    <form method="post">
        <p>Hur många QR vill du skapa? (max 30 per gång)</p>
        <input type="number" name="count" min="1" max="30" value="5">
        <button type="submit">Skapa PDF</button>
    </form>

    <a href="/dashboard">
        <button class="secondary">Tillbaka</button>
    </a>
    """

    return page(html)


@app.route("/admin/login", methods=["GET", "POST"])
def admin_login():
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "").strip()

        if email == ADMIN_EMAIL and check_password_hash(ADMIN_PASSWORD_HASH, password):
            session["is_admin"] = True
            return redirect("/admin")

        return page("<p>Fel admin-uppgifter.</p>")

    html = """
    <h2>Admin login</h2>
    <form method="post">
        <input name="email" type="email" placeholder="Admin email" required>
        <input name="password" type="password" placeholder="Lösenord" required>
        <button type="submit">Logga in</button>
    </form>
    """
    return page(html)



@app.route("/admin")
def admin_dashboard():
    if not session.get("is_admin"):
        return redirect("/admin/login")

    conn = sqlite3.connect(DB_PATH, timeout=10)
    cur = conn.cursor()

    cur.execute("SELECT COUNT(*) FROM users")
    users = cur.fetchone()[0]

    cur.execute("SELECT COUNT(*) FROM discs")
    discs = cur.fetchone()[0]

    cur.execute("SELECT COUNT(*) FROM handovers")
    handovers = cur.fetchone()[0]

    conn.close()

    html = f"""
    <h2>Admin dashboard</h2>

    <p><b>Användare:</b> {users}</p>
    <p><b>Discar:</b> {discs}</p>
    <p><b>Hittade discar:</b> {handovers}</p>

    <a href="/dashboard">
        <button class="secondary">Till användarvy</button>
    </a>
    """

    return page(html)



@app.route("/forgot-password", methods=["GET", "POST"])
def forgot_password():

    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        token = secrets.token_urlsafe(32)

        conn = sqlite3.connect(DB_PATH, timeout=10)
        cur = conn.cursor()

        cur.execute(
            "SELECT id FROM users WHERE email = ?",
            (email,)
        )

        row = cur.fetchone()

        if not row:
            conn.close()
            return page("<p>Ingen användare med den emailen.</p>")

        cur.execute(
            "UPDATE users SET reset_token = ? WHERE email = ?",
            (token, email)
        )

        conn.commit()
        conn.close()

        reset_link = f"{BASE_URL}/reset-password/{token}"

        send_owner_mail(
            email,
            "Återställ lösenord",
            f"""
            <p>Klicka på länken för att sätta nytt lösenord:</p>
            <p><a href="{reset_link}">{reset_link}</a></p>
            """
        )

        session["login_message"] = "Reset-länk skickad. Kolla din mail."

        return redirect("/login")

    html = """
    <h2>Glömt lösenord</h2>

    <form method="post">
        <input name="email" type="email" placeholder="Din email" required>
        <button type="submit">Skicka reset-länk</button>
    </form>

    <a href="/login">
        <button class="secondary">Tillbaka</button>
    </a>
    """

    return page(html)






@app.route("/reset-password/<token>", methods=["GET", "POST"])
def reset_password(token):

    conn = sqlite3.connect(DB_PATH, timeout=10)
    cur = conn.cursor()

    cur.execute(
        "SELECT id FROM users WHERE reset_token = ?",
        (token,)
    )
    row = cur.fetchone()

    if not row:
        conn.close()
        return page("<p>Ogiltig eller utgången länk.</p>")

    user_id = row[0]

    if request.method == "POST":
        new_password = request.form.get("password", "").strip()

        if not new_password:
            conn.close()
            return page("<p>Ange ett lösenord.</p>")

        password_hash = generate_password_hash(new_password)

        cur.execute(
            "UPDATE users SET password = ?, reset_token = NULL WHERE id = ?",
            (password_hash, user_id)
        )

        conn.commit()
        conn.close()

        return page("""
        <h2>Lösenord uppdaterat</h2>
        <a href="/login"><button>Logga in</button></a>
        """)

    conn.close()

    html = """
    <h2>Sätt nytt lösenord</h2>
    <form method="post">
        <input name="password" type="password" placeholder="Nytt lösenord" required>
        <button type="submit">Spara</button>
    </form>
    """

    return page(html)




@app.route("/scan")
def scan():
    return page("""
    <h2>Scanna QR-kod</h2>

    <div id="reader" style="width:300px;"></div>

    <script src="https://unpkg.com/html5-qrcode@2.3.8"></script>

    <script>
    function onScanSuccess(decodedText) {
        window.location.href = decodedText;
    }

    const html5QrCode = new Html5Qrcode("reader");

    html5QrCode.start(
        { facingMode: "environment" },
        { fps: 10, qrbox: 250 },
        onScanSuccess
    );
    </script>
    """)



@app.route("/admin/reset", methods=["POST"])
def admin_reset():

    if os.environ.get("ADMIN_KEY") != request.args.get("key"):
        return "Åtkomst nekad", 403

    conn = sqlite3.connect(DB_PATH, timeout=10)
    cur = conn.cursor()

    cur.execute("DELETE FROM handovers")
    cur.execute("DELETE FROM discs")
    cur.execute("DELETE FROM users")

    conn.commit()
    conn.close()

    return page("""
    <h2>Databasen är nollställd ✅</h2>

    <p>Alla användare och discar är raderade.</p>

    <a href="/admin/create?key=hemlig123">
        <button>Till admin</button>
    </a>
    """)






if __name__ == "__main__":

    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=True)


