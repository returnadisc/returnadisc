import os
import sqlite3
from datetime import datetime
from flask import Flask, request
import qrcode
from sendgrid import SendGridAPIClient
from sendgrid.helpers.mail import Mail
def page(html):
    return html


app = Flask(__name__)
ensure_tables()
def ensure_tables():
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()

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

    conn.commit()
    conn.close()

ensure_tables()


DB_PATH = "database.db"

def ensure_tables():
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()

    # Discs table safety (om den saknas i prod)
    cur.execute("""
    CREATE TABLE IF NOT EXISTS discs (
        disc_id TEXT PRIMARY KEY,
        disc_name TEXT,
        owner_name TEXT,
        owner_email TEXT,
        is_active INTEGER DEFAULT 0,
        created_at TEXT,
        activated_at TEXT
    )
    """)

    # Handovers table
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

    conn.commit()
    conn.close()


BASE_URL = os.environ.get("BASE_URL", "http://192.168.0.105:5000")
SENDGRID_API_KEY = os.environ.get("SENDGRID_API_KEY")

# ---------- DB HELPERS ----------

def get_disc(disc_id):
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()
    cur.execute("SELECT * FROM discs WHERE disc_id = ?", (disc_id,))
    disc = cur.fetchone()
    conn.close()
    return disc

# ---------- MAIL ----------

def send_owner_mail(to_email, subject, body):
    if not SENDGRID_API_KEY:
        print("No SendGrid key set")
        return

    message = Mail(
        from_email="r.ingemarsson@gmail.com",
        to_emails=to_email,
        subject=subject,
        html_content=body
    )

    try:
        sg = SendGridAPIClient(SENDGRID_API_KEY)
        sg.send(message)
    except Exception as e:
        print("Mail error:", e)

# ---------- ROUTES ----------

@app.route("/found/<disc_id>", methods=["GET", "POST"])
def found(disc_id):
    disc = get_disc(disc_id)

    if not disc or not disc["is_active"]:
        return "Disc ej aktiv", 404

    if request.method == "POST":
        action = request.form.get("action", "")
        note = request.form.get("note", "")

        latitude = request.form.get("latitude")
        longitude = request.form.get("longitude")

        conn = sqlite3.connect(DB_PATH)
        cur = conn.cursor()

        cur.execute("""
        INSERT INTO handovers (disc_id, action, note, created_at, latitude, longitude)
        VALUES (?, ?, ?, ?, ?, ?)
        """, (
            disc_id,
            action,
            note,
            datetime.utcnow().isoformat(),
            latitude,
            longitude
        ))

        conn.commit()
        conn.close()

        maps_link = ""
        if action == "gömde" and latitude and longitude:
            maps_link = (
                f"<p><a href='https://maps.google.com/?q="
                f"{latitude},{longitude}'>Öppna i Google Maps</a></p>"
            )

        send_owner_mail(
            disc["owner_email"],
            f"Din disc {disc['disc_name']} har hittats",
            f"""
            <p>Disc: <b>{disc['disc_name']}</b></p>
            <p>Åtgärd: <b>{action}</b></p>
            <p>Meddelande:</p>
            <p>{note}</p>
            {maps_link}
            """
        )

        return "<h2>Tack!</h2><p>Ägaren har fått ett mail.</p>"

    html = f"""
    <h2>Vad gjorde du med discen?</h2>

    <form method="post">
        <input type="hidden" name="action" value="kontaktade">
        <button style="width:100%;padding:15px;margin:10px 0;">
            Jag kontaktade ägaren
        </button>
    </form>

    <form method="post" onsubmit="getLocation(event)">
        <input type="hidden" name="action" value="gömde">
        <input type="hidden" id="lat" name="latitude">
        <input type="hidden" id="lng" name="longitude">

        <textarea name="note" placeholder="Var gömde du discen?"
            style="width:100%;height:80px;"></textarea>

        <button style="width:100%;padding:15px;margin:10px 0;">
            Jag gömde discen
        </button>
    </form>

    <form method="post">
        <input type="hidden" name="action" value="behåller">

        <textarea name="note" placeholder="Hur kan ägaren nå dig?"
            style="width:100%;height:80px;"></textarea>

        <button style="width:100%;padding:15px;margin:10px 0;">
            Jag behåller den tills vi ses
        </button>
    </form>

    <script>
        function getLocation(e) {{
            if (!navigator.geolocation) {{
                return;
            }}

            e.preventDefault();

            navigator.geolocation.getCurrentPosition(function(pos) {{
                document.getElementById("lat").value = pos.coords.latitude;
                document.getElementById("lng").value = pos.coords.longitude;
                e.target.submit();
            }}, function() {{
                alert("Kunde inte hämta GPS-position");
            }});
        }}
    </script>
    """
    return html


@app.route("/create", methods=["GET", "POST"])
def create_disc_web():
    if request.method == "POST":
        from utils import generate_disc_id

        disc_name = request.form["disc_name"]
        disc_id = generate_disc_id()

        conn = sqlite3.connect(DB_PATH)
        cur = conn.cursor()

        cur.execute(
            "INSERT INTO discs (disc_id, disc_name, created_at) VALUES (?, ?, datetime('now'))",
            (disc_id, disc_name)
        )

        conn.commit()
        conn.close()

        url = f"{BASE_URL}/activate/{disc_id}"

        os.makedirs("static/qr", exist_ok=True)
        qr_path = f"static/qr/{disc_id}.png"

        img = qrcode.make(url)
        img.save(qr_path)

        return f"""
        <h2>Disc skapad!</h2>
        <p><b>ID:</b> {disc_id}</p>
        <p><b>QR-kod:</b></p>
        <img src="/{qr_path}">
        <p><a href="/create">Skapa en till</a></p>
        """

    html = """
    <h2>Skapa ny disc</h2>
    <form method="post">
        <input name="disc_name" placeholder="Discens namn" required><br><br>
        <button type="submit">Skapa disc</button>
    </form>
    """
    return html



@app.route("/activate/<disc_id>", methods=["GET", "POST"])
def activate(disc_id):
    disc = get_disc(disc_id)

    if not disc:
        return "Disc finns inte", 404

    if disc["is_active"]:
        return f"""
        <h2>Den här discen är registrerad</h2>
        <p><b>Disc:</b> {disc["disc_name"]}</p>
        <p><b>Ägare:</b> {disc["owner_name"]}</p>

        <a href="mailto:{disc['owner_email']}">
            <button>Maila ägaren</button>
        </a>

        <p>
            <a href="/found/{disc_id}">
                <button>Jag hittade den här discen</button>
            </a>
        </p>
        """

    if request.method == "POST":
        disc_name = request.form["disc_name"]
        owner_name = request.form["owner_name"]
        owner_email = request.form["owner_email"]

        conn = sqlite3.connect(DB_PATH)
        cur = conn.cursor()
        cur.execute("""
        UPDATE discs
        SET disc_name = ?, owner_name = ?, owner_email = ?,
            is_active = 1, activated_at = ?
        WHERE disc_id = ?
        """, (disc_name, owner_name, owner_email,
              datetime.utcnow().isoformat(), disc_id))
        conn.commit()
        conn.close()

        send_owner_mail(
            owner_email,
            "Din disc är nu aktiv 🎉",
            f"""
            <p>Hej {owner_name}!</p>
            <p>Din disc <b>{disc_name}</b> är nu registrerad hos ReturnaDisc.</p>
            """
        )

        return "Disc aktiverad!"

    html = """
    <h2>Aktivera din disc</h2>
    <form method="post">
        <input name="disc_name" placeholder="Discens namn" required><br><br>
        <input name="owner_name" placeholder="Ditt namn" required><br><br>
        <input name="owner_email" type="email" placeholder="Din email" required><br><br>
        <button type="submit">Aktivera</button>
    </form>
    """
    return html





if __name__ == "__main__":

    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)

