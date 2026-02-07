"""Database-hantering - NY STRUKTUR: QR = Spelare, inte Disc."""
import sqlite3
import logging
import os
from contextlib import contextmanager
from typing import Optional, List, Dict, Any

logger = logging.getLogger(__name__)

DB_PATH = os.environ.get('DATABASE_URL', 'database.db')


class Database:
    """Database-hanterare."""
    
    def __init__(self, db_path: str = None):
        self.db_path = db_path or DB_PATH
    
    @contextmanager
    def get_connection(self):
        conn = sqlite3.connect(self.db_path, timeout=20, detect_types=sqlite3.PARSE_DECLTYPES)
        conn.row_factory = sqlite3.Row
        try:
            yield conn
            conn.commit()
        except Exception as e:
            conn.rollback()
            logger.error(f"Database error: {e}")
            raise
        finally:
            conn.close()
    
    def init_tables(self):
        """Skapa alla tabeller - NY STRUKTUR."""
        with self.get_connection() as conn:
            cur = conn.cursor()
            
            # Users (samma)
            cur.execute("""
                CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT NOT NULL,
                    email TEXT UNIQUE NOT NULL,
                    password TEXT NOT NULL,
                    reset_token TEXT,
                    hero_points INTEGER DEFAULT 0,
                    member_since TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    total_returns INTEGER DEFAULT 0,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
            
            # QR-koder (NY - varje QR tillhör en spelare)
            cur.execute("""
                CREATE TABLE IF NOT EXISTS qr_codes (
                    qr_id TEXT PRIMARY KEY,
                    user_id INTEGER,
                    is_active BOOLEAN DEFAULT 0,
                    activated_at TIMESTAMP,
                    total_scans INTEGER DEFAULT 0,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (user_id) REFERENCES users(id)
                )
            """)
            
            # Handovers (ändrad - kopplad till QR, inte disc)
            cur.execute("""
                CREATE TABLE IF NOT EXISTS handovers (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    qr_id TEXT,
                    finder_name TEXT,  -- Om inloggad, annars anonym
                    finder_user_id INTEGER,
                    action TEXT NOT NULL,  -- 'gömde', 'meddelande'
                    note TEXT,
                    photo_path TEXT,
                    latitude REAL,
                    longitude REAL,
                    confirmed BOOLEAN DEFAULT 0,  -- För hero points
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (qr_id) REFERENCES qr_codes(qr_id),
                    FOREIGN KEY (finder_user_id) REFERENCES users(id)
                )
            """)
            
            # Clubs (NY - för framtida klubb-funktion)
            cur.execute("""
                CREATE TABLE IF NOT EXISTS clubs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT NOT NULL,
                    email TEXT UNIQUE NOT NULL,
                    password TEXT NOT NULL,
                    logo_url TEXT,
                    member_count INTEGER DEFAULT 0,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
            
            # Indexes
            cur.execute("CREATE INDEX IF NOT EXISTS idx_qr_user ON qr_codes(user_id)")
            cur.execute("CREATE INDEX IF NOT EXISTS idx_handovers_qr ON handovers(qr_id)")
            cur.execute("CREATE INDEX IF NOT EXISTS idx_users_email ON users(email)")
            
            logger.info("Database initialized with NEW structure")
    
    # --- Users ---
    def create_user(self, name: str, email: str, password_hash: str) -> int:
        with self.get_connection() as conn:
            cur = conn.cursor()
            cur.execute("""
                INSERT INTO users (name, email, password, created_at)
                VALUES (?, ?, ?, datetime('now'))
            """, (name, email.lower(), password_hash))
            return cur.lastrowid
    
    def get_user_by_email(self, email: str) -> Optional[Dict]:
        with self.get_connection() as conn:
            cur = conn.cursor()
            cur.execute("SELECT * FROM users WHERE email = ?", (email.lower(),))
            row = cur.fetchone()
            return dict(row) if row else None
    
    def get_user_by_id(self, user_id: int) -> Optional[Dict]:
        with self.get_connection() as conn:
            cur = conn.cursor()
            cur.execute("""
                SELECT id, name, email, hero_points, member_since, total_returns 
                FROM users WHERE id = ?
            """, (user_id,))
            row = cur.fetchone()
            return dict(row) if row else None
    
    def add_hero_point(self, user_id: int):
        with self.get_connection() as conn:
            cur = conn.cursor()
            cur.execute("""
                UPDATE users SET hero_points = hero_points + 1, total_returns = total_returns + 1 
                WHERE id = ?
            """, (user_id,))
    
    # --- QR Codes ---
    def create_qr(self, qr_id: str):
        """Skapa ny QR-kod."""
        with self.get_connection() as conn:
            cur = conn.cursor()
            cur.execute("""
                INSERT INTO qr_codes (qr_id) 
                VALUES (?)
            """, (qr_id,))
    
    def get_qr(self, qr_id: str) -> Optional[Dict]:
        """Hämta QR-kod."""
        with self.get_connection() as conn:
            cur = conn.cursor()
            cur.execute("SELECT * FROM qr_codes WHERE qr_id = ?", (qr_id,))
            row = cur.fetchone()
            return dict(row) if row else None
    
    def activate_qr(self, qr_id: str, user_id: int):
        """Aktivera QR-kod för användare."""
        with self.get_connection() as conn:
            cur = conn.cursor()
            cur.execute("""
                UPDATE qr_codes 
                SET user_id = ?, is_active = 1, activated_at = datetime('now')
                WHERE qr_id = ?
            """, (user_id, qr_id))
    
    def get_user_qr(self, user_id: int) -> Optional[Dict]:
        """Hämta användarens QR-kod."""
        with self.get_connection() as conn:
            cur = conn.cursor()
            cur.execute("""
                SELECT * FROM qr_codes WHERE user_id = ? LIMIT 1
            """, (user_id,))
            row = cur.fetchone()
            return dict(row) if row else None
    
    def increment_qr_scans(self, qr_id: str):
        """Öka räknare för QR-scanningar."""
        with self.get_connection() as conn:
            cur = conn.cursor()
            cur.execute("""
                UPDATE qr_codes SET total_scans = total_scans + 1 WHERE qr_id = ?
            """, (qr_id,))
    
    # --- Handovers ---
    def create_handover(self, qr_id: str, action: str, note: str,
                       finder_user_id: Optional[int] = None,
                       finder_name: Optional[str] = None,
                       photo_path: Optional[str] = None,
                       latitude: Optional[float] = None,
                       longitude: Optional[float] = None) -> int:
        with self.get_connection() as conn:
            cur = conn.cursor()
            cur.execute("""
                INSERT INTO handovers 
                (qr_id, finder_user_id, finder_name, action, note, photo_path, latitude, longitude, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, datetime('now'))
            """, (qr_id, finder_user_id, finder_name, action, note, photo_path, latitude, longitude))
            return cur.lastrowid
    
    def confirm_handover(self, handover_id: int):
        with self.get_connection() as conn:
            cur = conn.cursor()
            cur.execute("""
                UPDATE handovers SET confirmed = 1 WHERE id = ?
            """, (handover_id,))
    
    def get_user_stats(self, user_id: int) -> Dict:
        with self.get_connection() as conn:
            cur = conn.cursor()
            cur.execute("""
                SELECT hero_points, total_returns, member_since 
                FROM users WHERE id = ?
            """, (user_id,))
            row = cur.fetchone()
            return {
                'hero_points': row[0],
                'total_returns': row[1],
                'member_since': row[2]
            }
    
    # --- Admin ---
    def get_stats(self) -> Dict[str, int]:
        with self.get_connection() as conn:
            cur = conn.cursor()
            cur.execute("SELECT COUNT(*) FROM users")
            users = cur.fetchone()[0]
            cur.execute("SELECT COUNT(*) FROM qr_codes WHERE is_active = 1")
            active_qrs = cur.fetchone()[0]
            cur.execute("SELECT COUNT(*) FROM handovers")
            handovers = cur.fetchone()[0]
            return {
                'users': users,
                'active_qrs': active_qrs,
                'handovers': handovers
            }

def set_reset_token(self, email: str, token: str) -> bool:
    """Sätt password-reset token."""
    with self.get_connection() as conn:
        cur = conn.cursor()
        cur.execute(
            "UPDATE users SET reset_token = ? WHERE email = ?",
            (token, email.lower())
        )
        return cur.rowcount > 0

db = Database(DB_PATH)