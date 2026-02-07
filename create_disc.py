from utils import generate_disc_id
import sqlite3
from datetime import datetime

conn = sqlite3.connect("database.db")
cur = conn.cursor()

disc_id = generate_disc_id()
created_at = datetime.utcnow().isoformat()

cur.execute(
    "INSERT INTO discs (disc_id, created_at) VALUES (?, ?)",
    (disc_id, created_at)
)

conn.commit()
conn.close()

print("Ny disc skapad:")
print(disc_id)
print("Aktiverings-URL:")
print(f"http://127.0.0.1:5000/activate/{disc_id}")
