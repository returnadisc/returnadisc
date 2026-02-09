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
            
            # Users (uppdaterad med last_login)
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
                    is_premium BOOLEAN DEFAULT 0,
                    last_login TIMESTAMP,
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
                    finder_name TEXT,
                    finder_user_id INTEGER,
                    action TEXT NOT NULL,
                    note TEXT,
                    photo_path TEXT,
                    latitude REAL,
                    longitude REAL,
                    confirmed BOOLEAN DEFAULT 0,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (qr_id) REFERENCES qr_codes(qr_id),
                    FOREIGN KEY (finder_user_id) REFERENCES users(id)
                )
            """)
            
            # NYTT: Missing discs - för community-kartan
            cur.execute("""
                CREATE TABLE IF NOT EXISTS missing_discs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER NOT NULL,
                    disc_name TEXT NOT NULL,
                    description TEXT,
                    latitude REAL NOT NULL,
                    longitude REAL NOT NULL,
                    course_name TEXT,
                    hole_number TEXT,
                    status TEXT DEFAULT 'missing',
                    found_by_user_id INTEGER,
                    found_at TIMESTAMP,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (user_id) REFERENCES users(id),
                    FOREIGN KEY (found_by_user_id) REFERENCES users(id)
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
            
            # Lägg till last_login om den saknas (för befintliga databaser)
            try:
                cur.execute("SELECT last_login FROM users LIMIT 1")
            except sqlite3.OperationalError:
                cur.execute("ALTER TABLE users ADD COLUMN last_login TIMESTAMP")
                logger.info("La till kolumnen last_login i users-tabellen")
            
            # Indexes
            cur.execute("CREATE INDEX IF NOT EXISTS idx_qr_user ON qr_codes(user_id)")
            cur.execute("CREATE INDEX IF NOT EXISTS idx_handovers_qr ON handovers(qr_id)")
            cur.execute("CREATE INDEX IF NOT EXISTS idx_users_email ON users(email)")
            cur.execute("CREATE INDEX IF NOT EXISTS idx_missing_user ON missing_discs(user_id)")
            cur.execute("CREATE INDEX IF NOT EXISTS idx_missing_status ON missing_discs(status)")
            cur.execute("CREATE INDEX IF NOT EXISTS idx_missing_location ON missing_discs(latitude, longitude)")
            
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
                SELECT id, name, email, hero_points, member_since, total_returns, is_premium 
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
    
    # --- Missing Discs (NYTT) ---
    def report_missing_disc(self, user_id: int, disc_name: str, description: str,
                           latitude: float, longitude: float,
                           course_name: str = None, hole_number: str = None) -> int:
        """Rapportera saknad disc."""
        with self.get_connection() as conn:
            cur = conn.cursor()
            cur.execute("""
                INSERT INTO missing_discs 
                (user_id, disc_name, description, latitude, longitude, course_name, hole_number, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, datetime('now'))
            """, (user_id, disc_name, description, latitude, longitude, course_name, hole_number))
            return cur.lastrowid
    
    def get_user_missing_discs(self, user_id: int) -> List[Dict]:
        """Hämta användarens saknade discar."""
        with self.get_connection() as conn:
            cur = conn.cursor()
            cur.execute("""
                SELECT * FROM missing_discs 
                WHERE user_id = ? 
                ORDER BY created_at DESC
            """, (user_id,))
            return [dict(row) for row in cur.fetchall()]
    
    def get_all_missing_discs(self, status: str = 'missing') -> List[Dict]:
        with self.get_connection() as conn:
            cur = conn.cursor()
            cur.execute("""
                SELECT m.*, u.name as reporter_name 
                FROM missing_discs m
                LEFT JOIN users u ON m.user_id = u.id
                WHERE m.status = ?
                ORDER BY m.created_at DESC
            """, (status,))
            return [dict(row) for row in cur.fetchall()]
    
    def mark_disc_found(self, disc_id: int, found_by_user_id: int = None):
        """Markera disc som hittad."""
        with self.get_connection() as conn:
            cur = conn.cursor()
            if found_by_user_id:
                cur.execute("""
                    UPDATE missing_discs 
                    SET status = 'found', found_by_user_id = ?, found_at = datetime('now')
                    WHERE id = ?
                """, (found_by_user_id, disc_id))
            else:
                cur.execute("""
                    UPDATE missing_discs 
                    SET status = 'found', found_at = datetime('now')
                    WHERE id = ?
                """, (disc_id,))
    
    def delete_missing_disc(self, disc_id: int, user_id: int):
        """Ta bort egen rapport."""
        with self.get_connection() as conn:
            cur = conn.cursor()
            cur.execute("""
                DELETE FROM missing_discs 
                WHERE id = ? AND user_id = ?
            """, (disc_id, user_id))
    
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
            cur.execute("SELECT SUM(total_scans) FROM qr_codes")
            total_scans = cur.fetchone()[0] or 0
            cur.execute("SELECT COUNT(*) FROM missing_discs WHERE status = 'missing'")
            missing_count = cur.fetchone()[0]
            return {
                'users': users,
                'active_qrs': active_qrs,
                'handovers': handovers,
                'total_scans': total_scans,
                'missing_discs': missing_count
            }
    
    # --- Password Reset ---
    def set_reset_token(self, email: str, token: str) -> bool:
        """Sätt password-reset token."""
        with self.get_connection() as conn:
            cur = conn.cursor()
            cur.execute(
                "UPDATE users SET reset_token = ? WHERE email = ?",
                (token, email.lower())
            )
            return cur.rowcount > 0
    
    def get_user_by_token(self, token: str) -> Optional[Dict]:
        """Hämta användare via reset token."""
        with self.get_connection() as conn:
            cur = conn.cursor()
            cur.execute("SELECT * FROM users WHERE reset_token = ?", (token,))
            row = cur.fetchone()
            return dict(row) if row else None
    
    def update_password(self, user_id: int, password_hash: str):
        """Uppdatera lösenord och rensa token."""
        with self.get_connection() as conn:
            cur = conn.cursor()
            cur.execute(
                "UPDATE users SET password = ?, reset_token = NULL WHERE id = ?",
                (password_hash, user_id)
            )
    
    def clear_reset_token(self, user_id: int):
        """Rensa reset token efter användning."""
        with self.get_connection() as conn:
            cur = conn.cursor()
            cur.execute("UPDATE users SET reset_token = NULL WHERE id = ?", (user_id,))
    
    # --- Database Reset ---
    def reset_database(self):
        """Nollställ databasen."""
        import os
        if os.path.exists(self.db_path):
            os.remove(self.db_path)
        self.init_tables()
        return True

    def create_user_with_qr(self, name: str, email: str, password_hash: str) -> tuple:
        """Skapa användare och generera QR-kod automatiskt."""
        from utils import generate_random_qr_id, create_qr_code
        
        with self.get_connection() as conn:
            cur = conn.cursor()
            
            # 1. Skapa användare
            cur.execute("""
                INSERT INTO users (name, email, password, created_at)
                VALUES (?, ?, ?, datetime('now'))
            """, (name, email.lower(), password_hash))
            user_id = cur.lastrowid
            
            # 2. Generera unik QR-kod
            max_attempts = 10
            for _ in range(max_attempts):
                qr_id = generate_random_qr_id()
                
                # Kolla om QR redan finns
                cur.execute("SELECT 1 FROM qr_codes WHERE qr_id = ?", (qr_id,))
                if not cur.fetchone():
                    break
            
            # 3. Skapa QR i databasen (aktiverad direkt)
            cur.execute("""
                INSERT INTO qr_codes (qr_id, user_id, is_active, activated_at, created_at)
                VALUES (?, ?, 1, datetime('now'), datetime('now'))
            """, (qr_id, user_id))
            
            # 4. Generera QR-bild
            qr_filename = create_qr_code(qr_id, user_id)
            
            return user_id, qr_id, qr_filename
            
            
    def find_matching_missing_disc(self, user_id: int, found_lat: float, found_lng: float) -> Optional[Dict]:
        """Hitta vilken saknad disc som troligen hittats baserat på position."""
        user_discs = self.get_user_missing_discs(user_id)
    
        if not user_discs:
            return None
    
        if len(user_discs) == 1:
            # Endast en saknad disc, anta att det är den
            return {**user_discs[0], 'confidence': 'high', 'distance': 0}
    
        # Beräkna avstånd till varje saknad disc
        matches = []
        for disc in user_discs:
            dist = self._calculate_distance(
                found_lat, found_lng,
                disc['latitude'], disc['longitude']
            )
            matches.append({**disc, 'distance': dist})
    
        # Sortera efter avstånd
        matches.sort(key=lambda x: x['distance'])
    
        # Om närmaste är inom 500m, anta det är den
        if matches[0]['distance'] < 0.5:  # 0.5km = 500m
            return {**matches[0], 'confidence': 'high'}
    
        # Om osäker (flera inom 2km), returnera alla nära
        close_matches = [m for m in matches if m['distance'] < 2.0]
        if close_matches:
            return {
                'multiple': True,
                'matches': close_matches,
                'best_guess': close_matches[0]
            }
    
        # Ingen match nära, returnera närmaste ändå men markera osäker
        return {**matches[0], 'confidence': 'low'}


    def _calculate_distance(self, lat1, lng1, lat2, lng2):
        """Haversine-formel för avstånd i km."""
        import math
        R = 6371
        dLat = math.radians(lat2 - lat1)
        dLng = math.radians(lng2 - lng1)
        a = (math.sin(dLat/2) * math.sin(dLat/2) +
             math.cos(math.radians(lat1)) * math.cos(math.radians(lat2)) *
             math.sin(dLng/2) * math.sin(dLng/2))
        c = 2 * math.atan2(math.sqrt(a), math.sqrt(1-a))
        return R * c
        
    def get_user_missing_stats(self, user_id: int) -> Dict:
        """Hämta antal saknade och återfunna discar för en användare."""
        with self.get_connection() as conn:
            cur = conn.cursor()
            cur.execute("""
                SELECT 
                    COUNT(*) as total_missing,
                    SUM(CASE WHEN status = 'found' THEN 1 ELSE 0 END) as found_count
                FROM missing_discs 
                WHERE user_id = ?
            """, (user_id,))
            row = cur.fetchone()
            return {
                'missing': row[0] or 0,
                'found': row[1] or 0
            }
    
    def get_global_missing_stats(self) -> Dict:
        """Hämta global statistik för saknade discar."""
        with self.get_connection() as conn:
            cur = conn.cursor()
            cur.execute("""
                SELECT 
                    COUNT(*) as total_missing,
                    SUM(CASE WHEN status = 'found' THEN 1 ELSE 0 END) as found_count
                FROM missing_discs
            """)
            row = cur.fetchone()
            return {
                'total_missing': row[0] or 0,
                'total_found': row[1] or 0
            }
    
    def get_all_users_with_stats(self) -> List[Dict]:
        """Hämta alla användare med statistik."""
        with self.get_connection() as conn:
            cur = conn.cursor()
            cur.execute("""
                SELECT 
                    u.id, u.name, u.email, u.created_at, u.last_login,
                    COUNT(DISTINCT m.id) as missing_count,
                    COUNT(DISTINCT CASE WHEN m.status = 'found' THEN m.id END) as found_count,
                    COUNT(DISTINCT h.id) as handovers_count
                FROM users u
                LEFT JOIN missing_discs m ON u.id = m.user_id
                LEFT JOIN handovers h ON u.id = h.finder_user_id
                GROUP BY u.id
                ORDER BY u.created_at DESC
            """)
            return [dict(row) for row in cur.fetchall()]
    
    def update_last_login(self, user_id: int):
        """Uppdatera senaste inloggning."""
        with self.get_connection() as conn:
            cur = conn.cursor()
            cur.execute("""
                UPDATE users SET last_login = datetime('now') WHERE id = ?
            """, (user_id,))
    
    def get_admin_stats(self) -> Dict:
        """Hämta omfattande admin-statistik."""
        with self.get_connection() as conn:
            cur = conn.cursor()
            
            # Användare
            cur.execute("SELECT COUNT(*) FROM users")
            users = cur.fetchone()[0]
            
            # QR-koder
            cur.execute("SELECT COUNT(*) FROM qr_codes WHERE is_active = 1")
            active_qrs = cur.fetchone()[0]
            
            cur.execute("SELECT COUNT(*) FROM qr_codes WHERE is_active = 0")
            inactive_qrs = cur.fetchone()[0]
            
            # Saknade discar
            cur.execute("SELECT COUNT(*) FROM missing_discs WHERE status = 'missing'")
            missing_discs = cur.fetchone()[0]
            
            cur.execute("SELECT COUNT(*) FROM missing_discs WHERE status = 'found'")
            found_discs = cur.fetchone()[0]
            
            # Handovers
            cur.execute("SELECT COUNT(*) FROM handovers")
            handovers = cur.fetchone()[0]
            
            # QR-scanningar totalt
            cur.execute("SELECT SUM(total_scans) FROM qr_codes")
            total_scans = cur.fetchone()[0] or 0
            
            # Aktiva idag (senaste 24h) - använd finder_user_id istället för user_id
            cur.execute("""
                SELECT COUNT(DISTINCT finder_user_id) 
                FROM handovers 
                WHERE created_at > datetime('now', '-1 day')
            """)
            active_today = cur.fetchone()[0]
            
            # Nya användare denna vecka
            cur.execute("""
                SELECT COUNT(*) FROM users 
                WHERE created_at > datetime('now', '-7 days')
            """)
            new_this_week = cur.fetchone()[0]
            
            return {
                'users': users,
                'active_qrs': active_qrs,
                'inactive_qrs': inactive_qrs,
                'missing_discs': missing_discs,
                'found_discs': found_discs,
                'handovers': handovers,
                'total_scans': total_scans,
                'active_today': active_today,
                'new_this_week': new_this_week,
                'return_rate': round((found_discs / (missing_discs + found_discs) * 100), 1) if (missing_discs + found_discs) > 0 else 0
            }
        
        
db = Database(DB_PATH)