"""Database-hantering med Repository Pattern och kryptering."""
import sqlite3
import logging
import os
import math
import base64
from contextlib import contextmanager
from typing import Optional, List, Dict, Tuple, Any
from dataclasses import dataclass, asdict
from datetime import datetime
from abc import ABC, abstractmethod
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

logger = logging.getLogger(__name__)

DB_PATH = os.environ.get('DATABASE_URL', 'database.db')

# ============================================================================
# Kryptering för PII
# ============================================================================

class EncryptionService:
    """Hantering av kryptering för personuppgifter (GDPR)."""
    
    _instance = None
    _cipher = None
    
    @classmethod
    def get_instance(cls):
        if cls._instance is None:
            cls._instance = cls()
        return cls._instance
    
    def __init__(self):
        if self._cipher is not None:
            return
            
        key = os.environ.get('PII_ENCRYPTION_KEY')
        if not key:
            secret = os.environ.get('SECRET_KEY', 'fallback-secret-do-not-use')
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=b'returnadisc_salt_v1',
                iterations=480000,
            )
            key = base64.urlsafe_b64encode(kdf.derive(secret.encode()))
        
        self._cipher = Fernet(key)
    
    def encrypt(self, data: str) -> str:
        if not data:
            return data
        return self._cipher.encrypt(data.encode()).decode()
    
    def decrypt(self, encrypted: str) -> str:
        if not encrypted:
            return encrypted
        try:
            return self._cipher.decrypt(encrypted.encode()).decode()
        except Exception as e:
            logger.error(f"Dekrypteringsfel: {e}")
            return "[KRYPTERAD]"
    
    def hash_email(self, email: str) -> str:
        import hashlib
        return hashlib.sha256(email.lower().strip().encode()).hexdigest()


encryption = EncryptionService.get_instance()


# ============================================================================
# Modell-klasser
# ============================================================================

@dataclass
class User:
    id: Optional[int] = None
    name: str = ""
    email: str = ""
    email_hash: str = ""
    password: str = ""
    reset_token: Optional[str] = None
    member_since: Optional[datetime] = None
    total_returns: int = 0
    is_premium: bool = False
    last_login: Optional[datetime] = None
    created_at: Optional[datetime] = None
    is_active: bool = True
    deleted_at: Optional[datetime] = None
    
    def to_dict(self, include_sensitive: bool = False) -> Dict[str, Any]:
        data = asdict(self)
        if not include_sensitive:
            data.pop('email_hash', None)
            if self.email and not self.email.startswith('gAAAA'):
                data['email'] = self.email
        return data


@dataclass
class QRCode:
    qr_id: str = ""
    user_id: Optional[int] = None
    is_active: bool = False
    activated_at: Optional[datetime] = None
    total_scans: int = 0
    created_at: Optional[datetime] = None
    
    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class Handover:
    id: Optional[int] = None
    qr_id: Optional[str] = None
    finder_name: Optional[str] = None
    finder_user_id: Optional[int] = None
    action: str = ""
    note: Optional[str] = None
    photo_path: Optional[str] = None
    latitude: Optional[float] = None
    longitude: Optional[float] = None
    confirmed: bool = False
    created_at: Optional[datetime] = None
    
    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class MissingDisc:
    id: Optional[int] = None
    user_id: int = 0
    disc_name: str = ""
    description: str = ""
    latitude: float = 0.0
    longitude: float = 0.0
    course_name: Optional[str] = None
    hole_number: Optional[str] = None
    status: str = "missing"
    found_by_user_id: Optional[int] = None
    found_at: Optional[datetime] = None
    created_at: Optional[datetime] = None
    
    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class UserStats:
    total_returns: int = 0
    member_since: Optional[datetime] = None
    missing: int = 0
    found: int = 0


@dataclass
class AdminStats:
    users: int = 0
    active_qrs: int = 0
    inactive_qrs: int = 0
    missing_discs: int = 0
    found_discs: int = 0
    handovers: int = 0
    total_scans: int = 0
    active_today: int = 0
    new_this_week: int = 0
    return_rate: float = 0.0


@dataclass
class MatchResult:
    disc: MissingDisc
    confidence: str
    distance: float
    multiple: bool = False


# ============================================================================
# Database Connection Manager
# ============================================================================

class DatabaseConnection:
    def __init__(self, db_path: str = None):
        self.db_path = db_path or DB_PATH
    
    @contextmanager
    def get_connection(self):
        conn = sqlite3.connect(
            self.db_path, 
            timeout=20, 
            detect_types=sqlite3.PARSE_DECLTYPES
        )
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
    
    @contextmanager
    def transaction(self):
        with self.get_connection() as conn:
            try:
                yield conn
            except Exception:
                conn.rollback()
                raise
            else:
                conn.commit()
    
    def execute(
        self, 
        query: str, 
        params: Tuple = (), 
        fetch_one: bool = False
    ) -> Optional[Dict]:
        with self.get_connection() as conn:
            cur = conn.cursor()
            cur.execute(query, params)
            
            if fetch_one:
                row = cur.fetchone()
                return dict(row) if row else None
            return None
    
    def execute_many(
        self, 
        query: str, 
        params: List[Tuple] = None
    ) -> int:
        with self.get_connection() as conn:
            cur = conn.cursor()
            if params:
                cur.executemany(query, params)
            else:
                cur.execute(query)
            return cur.rowcount
    
    def fetch_all(self, query: str, params: Tuple = ()) -> List[Dict]:
        with self.get_connection() as conn:
            cur = conn.cursor()
            cur.execute(query, params)
            return [dict(row) for row in cur.fetchall()]
    
    def fetch_one(self, query: str, params: Tuple = ()) -> Optional[Dict]:
        return self.execute(query, params, fetch_one=True)
    
    def last_insert_id(self) -> int:
        with self.get_connection() as conn:
            return conn.cursor().lastrowid


# ============================================================================
# Base Repository
# ============================================================================

class BaseRepository(ABC):
    def __init__(self, db: DatabaseConnection):
        self.db = db
    
    @abstractmethod
    def row_to_model(self, row: Dict) -> Any:
        pass


# ============================================================================
# User Repository
# ============================================================================

class UserRepository(BaseRepository):
    TABLE = "users"
    
    def row_to_model(self, row: Dict, decrypt: bool = True) -> User:
        email = row.get('email', '')
        if decrypt and email.startswith('gAAAA'):
            email = encryption.decrypt(email)
        
        return User(
            id=row.get('id'),
            name=row.get('name', ''),
            email=email,
            email_hash=row.get('email_hash', ''),
            password=row.get('password', ''),
            reset_token=row.get('reset_token'),
            member_since=row.get('member_since'),
            total_returns=row.get('total_returns', 0),
            is_premium=bool(row.get('is_premium', 0)),
            last_login=row.get('last_login'),
            created_at=row.get('created_at'),
            is_active=bool(row.get('is_active', 1)),
            deleted_at=row.get('deleted_at')
        )
    
    def create(self, name: str, email: str, password_hash: str) -> int:
        encrypted_email = encryption.encrypt(email)
        email_hash = encryption.hash_email(email)
        
        query = """
            INSERT INTO users (name, email, email_hash, password, created_at, is_active)
            VALUES (?, ?, ?, ?, datetime('now'), 1)
        """
        self.db.execute(query, (name, encrypted_email, email_hash, password_hash))
        return self.db.last_insert_id()
    
    def get_by_email(self, email: str) -> Optional[User]:
        email_hash = encryption.hash_email(email)
        query = "SELECT * FROM users WHERE email_hash = ? AND is_active = 1"
        row = self.db.fetch_one(query, (email_hash,))
        
        if row:
            return self.row_to_model(row)
        
        query = "SELECT * FROM users WHERE email = ? AND is_active = 1"
        row = self.db.fetch_one(query, (email.lower(),))
        return self.row_to_model(row) if row else None
    
    def get_by_id(self, user_id: int, include_password: bool = False) -> Optional[User]:
        if include_password:
            query = "SELECT * FROM users WHERE id = ? AND is_active = 1"
        else:
            query = """
                SELECT id, name, email, email_hash, member_since, 
                       total_returns, is_premium, last_login, created_at, is_active, deleted_at
                FROM users WHERE id = ? AND is_active = 1
            """
        row = self.db.fetch_one(query, (user_id,))
        return self.row_to_model(row) if row else None
    
    def get_by_token(self, token: str) -> Optional[User]:
        query = "SELECT * FROM users WHERE reset_token = ? AND is_active = 1"
        row = self.db.fetch_one(query, (token,))
        return self.row_to_model(row) if row else None
    
    def soft_delete(self, user_id: int) -> bool:
        query = """
            UPDATE users 
            SET is_active = 0, deleted_at = datetime('now'),
                name = '[BORTTAGEN]', email = '[BORTTAGEN]',
                email_hash = '', password = '[BORTTAGEN]'
            WHERE id = ?
        """
        self.db.execute(query, (user_id,))
        return True
    
    def update_password(self, user_id: int, password_hash: str) -> None:
        query = """
            UPDATE users 
            SET password = ?, reset_token = NULL 
            WHERE id = ?
        """
        self.db.execute(query, (password_hash, user_id))
    
    def set_reset_token(self, email: str, token: str) -> bool:
        email_hash = encryption.hash_email(email)
        query = "UPDATE users SET reset_token = ? WHERE email_hash = ?"
        self.db.execute(query, (token, email_hash))
        return True
    
    def clear_reset_token(self, user_id: int) -> None:
        query = "UPDATE users SET reset_token = NULL WHERE id = ?"
        self.db.execute(query, (user_id,))
    
    def update_last_login(self, user_id: int) -> None:
        query = "UPDATE users SET last_login = datetime('now') WHERE id = ?"
        self.db.execute(query, (user_id,))
    
    def increment_returns(self, user_id: int) -> bool:
        """Öka total returns."""
        query = """
            UPDATE users 
            SET total_returns = total_returns + 1 
            WHERE id = ?
        """
        self.db.execute(query, (user_id,))
        return True
    
    def get_all_with_stats(self, active_only: bool = True) -> List[Dict]:
        where_clause = "WHERE u.is_active = 1" if active_only else ""
        
        query = f"""
            SELECT 
                u.id, u.name, u.email, u.created_at, u.last_login, u.is_active,
                COUNT(DISTINCT m.id) as missing_count,
                COUNT(DISTINCT CASE WHEN m.status = 'found' THEN m.id END) as found_count,
                COUNT(DISTINCT h.id) as handovers_count
            FROM users u
            LEFT JOIN missing_discs m ON u.id = m.user_id
            LEFT JOIN handovers h ON u.id = h.finder_user_id
            {where_clause}
            GROUP BY u.id
            ORDER BY u.created_at DESC
        """
        rows = self.db.fetch_all(query)
        
        for row in rows:
            if row.get('email', '').startswith('gAAAA'):
                row['email'] = encryption.decrypt(row['email'])
        
        return rows


# ============================================================================
# QR Code Repository
# ============================================================================

class QRCodeRepository(BaseRepository):
    def row_to_model(self, row: Dict) -> QRCode:
        return QRCode(
            qr_id=row.get('qr_id', ''),
            user_id=row.get('user_id'),
            is_active=bool(row.get('is_active', 0)),
            activated_at=row.get('activated_at'),
            total_scans=row.get('total_scans', 0),
            created_at=row.get('created_at')
        )
    
    def create(self, qr_id: str) -> bool:
        try:
            query = "INSERT INTO qr_codes (qr_id) VALUES (?)"
            self.db.execute(query, (qr_id,))
            return True
        except sqlite3.IntegrityError:
            logger.warning(f"QR-kod {qr_id} finns redan")
            return False
    
    def get_by_id(self, qr_id: str) -> Optional[QRCode]:
        query = "SELECT * FROM qr_codes WHERE qr_id = ?"
        row = self.db.fetch_one(query, (qr_id,))
        return self.row_to_model(row) if row else None
    
    def get_by_user(self, user_id: int) -> Optional[QRCode]:
        query = "SELECT * FROM qr_codes WHERE user_id = ? LIMIT 1"
        row = self.db.fetch_one(query, (user_id,))
        return self.row_to_model(row) if row else None
    
    def activate(self, qr_id: str, user_id: int) -> None:
        query = """
            UPDATE qr_codes 
            SET user_id = ?, is_active = 1, activated_at = datetime('now')
            WHERE qr_id = ?
        """
        self.db.execute(query, (user_id, qr_id))
    
    def increment_scans(self, qr_id: str) -> None:
        query = "UPDATE qr_codes SET total_scans = total_scans + 1 WHERE qr_id = ?"
        self.db.execute(query, (qr_id,))
    
    def get_all_with_users(self) -> List[Dict]:
        query = """
            SELECT q.qr_id, q.is_active, q.activated_at, q.total_scans,
                   u.name, u.email, u.created_at, u.last_login
            FROM qr_codes q
            LEFT JOIN users u ON q.user_id = u.id
            ORDER BY q.created_at DESC
        """
        rows = self.db.fetch_all(query)
        
        for row in rows:
            if row.get('email', '').startswith('gAAAA'):
                row['email'] = encryption.decrypt(row['email'])
        
        return rows
    
    def get_stats(self) -> Dict[str, int]:
        queries = {
            'active': "SELECT COUNT(*) FROM qr_codes WHERE is_active = 1",
            'inactive': "SELECT COUNT(*) FROM qr_codes WHERE is_active = 0",
            'total_scans': "SELECT SUM(total_scans) FROM qr_codes"
        }
        return {
            key: self.db.fetch_one(query).get(f'COUNT(*)', 0) or 0 
            if 'COUNT' in query else
            self.db.fetch_one(query).get(f'SUM(total_scans)', 0) or 0
            for key, query in queries.items()
        }


# ============================================================================
# Missing Disc Repository
# ============================================================================

class MissingDiscRepository(BaseRepository):
    def row_to_model(self, row: Dict) -> MissingDisc:
        return MissingDisc(
            id=row.get('id'),
            user_id=row.get('user_id', 0),
            disc_name=row.get('disc_name', ''),
            description=row.get('description', ''),
            latitude=row.get('latitude', 0.0),
            longitude=row.get('longitude', 0.0),
            course_name=row.get('course_name'),
            hole_number=row.get('hole_number'),
            status=row.get('status', 'missing'),
            found_by_user_id=row.get('found_by_user_id'),
            found_at=row.get('found_at'),
            created_at=row.get('created_at')
        )
    
    def create(self, disc: MissingDisc) -> int:
        query = """
            INSERT INTO missing_discs 
            (user_id, disc_name, description, latitude, longitude, 
             course_name, hole_number, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, datetime('now'))
        """
        self.db.execute(query, (
            disc.user_id, disc.disc_name, disc.description,
            disc.latitude, disc.longitude, disc.course_name, disc.hole_number
        ))
        return self.db.last_insert_id()
    
    def get_by_id(self, disc_id: int) -> Optional[MissingDisc]:
        query = "SELECT * FROM missing_discs WHERE id = ?"
        row = self.db.fetch_one(query, (disc_id,))
        return self.row_to_model(row) if row else None
    
    def get_by_user(self, user_id: int) -> List[MissingDisc]:
        query = """
            SELECT * FROM missing_discs 
            WHERE user_id = ? 
            ORDER BY created_at DESC
        """
        rows = self.db.fetch_all(query, (user_id,))
        return [self.row_to_model(row) for row in rows]
    
    def get_all(self, status: str = 'missing') -> List[MissingDisc]:
        query = """
            SELECT m.*, u.name as reporter_name 
            FROM missing_discs m
            LEFT JOIN users u ON m.user_id = u.id
            WHERE m.status = ?
            ORDER BY m.created_at DESC
        """
        rows = self.db.fetch_all(query, (status,))
        return [self.row_to_model(row) for row in rows]
    
    def mark_found(self, disc_id: int, found_by_user_id: Optional[int] = None) -> None:
        if found_by_user_id:
            query = """
                UPDATE missing_discs 
                SET status = 'found', found_by_user_id = ?, found_at = datetime('now')
                WHERE id = ?
            """
            self.db.execute(query, (found_by_user_id, disc_id))
        else:
            query = """
                UPDATE missing_discs 
                SET status = 'found', found_at = datetime('now')
                WHERE id = ?
            """
            self.db.execute(query, (disc_id,))
    
    def delete(self, disc_id: int, user_id: int) -> bool:
        query = "DELETE FROM missing_discs WHERE id = ? AND user_id = ?"
        self.db.execute(query, (disc_id, user_id))
        return True
    
    def get_user_stats(self, user_id: int) -> Tuple[int, int]:
        query = """
            SELECT 
                COUNT(*) as total,
                SUM(CASE WHEN status = 'found' THEN 1 ELSE 0 END) as found
            FROM missing_discs 
            WHERE user_id = ?
        """
        row = self.db.fetch_one(query, (user_id,))
        return row.get('total', 0) or 0, row.get('found', 0) or 0
    
    def get_global_stats(self) -> Tuple[int, int]:
        query = """
            SELECT 
                COUNT(*) as total,
                SUM(CASE WHEN status = 'found' THEN 1 ELSE 0 END) as found
            FROM missing_discs
        """
        row = self.db.fetch_one(query)
        return row.get('total', 0) or 0, row.get('found', 0) or 0
    
    def find_nearby(
        self, 
        user_id: int, 
        lat: float, 
        lng: float, 
        radius_km: float = 2.0
    ) -> List[Tuple[MissingDisc, float]]:
        discs = self.get_by_user(user_id)
        matches = []
        
        for disc in discs:
            dist = self._calculate_distance(lat, lng, disc.latitude, disc.longitude)
            if dist <= radius_km:
                matches.append((disc, dist))
        
        matches.sort(key=lambda x: x[1])
        return matches
    
    @staticmethod
    def _calculate_distance(lat1: float, lng1: float, lat2: float, lng2: float) -> float:
        R = 6371
        d_lat = math.radians(lat2 - lat1)
        d_lng = math.radians(lng2 - lng1)
        a = (
            math.sin(d_lat / 2) * math.sin(d_lat / 2) +
            math.cos(math.radians(lat1)) * math.cos(math.radians(lat2)) *
            math.sin(d_lng / 2) * math.sin(d_lng / 2)
        )
        c = 2 * math.atan2(math.sqrt(a), math.sqrt(1 - a))
        return R * c


# ============================================================================
# Handover Repository
# ============================================================================

class HandoverRepository(BaseRepository):
    def row_to_model(self, row: Dict) -> Handover:
        return Handover(
            id=row.get('id'),
            qr_id=row.get('qr_id'),
            finder_name=row.get('finder_name'),
            finder_user_id=row.get('finder_user_id'),
            action=row.get('action', ''),
            note=row.get('note'),
            photo_path=row.get('photo_path'),
            latitude=row.get('latitude'),
            longitude=row.get('longitude'),
            confirmed=bool(row.get('confirmed', 0)),
            created_at=row.get('created_at')
        )
    
    def create(self, handover: Handover) -> int:
        query = """
            INSERT INTO handovers 
            (qr_id, finder_user_id, finder_name, action, note, 
             photo_path, latitude, longitude, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, datetime('now'))
        """
        self.db.execute(query, (
            handover.qr_id, handover.finder_user_id, handover.finder_name,
            handover.action, handover.note, handover.photo_path,
            handover.latitude, handover.longitude
        ))
        return self.db.last_insert_id()
    
    def confirm(self, handover_id: int) -> None:
        query = "UPDATE handovers SET confirmed = 1 WHERE id = ?"
        self.db.execute(query, (handover_id,))
    
    def get_count(self) -> int:
        query = "SELECT COUNT(*) as count FROM handovers"
        row = self.db.fetch_one(query)
        return row.get('count', 0) if row else 0
    
    def get_active_today(self) -> int:
        query = """
            SELECT COUNT(DISTINCT finder_user_id) as count
            FROM handovers 
            WHERE created_at > datetime('now', '-1 day')
        """
        row = self.db.fetch_one(query)
        return row.get('count', 0) if row else 0


# ============================================================================
# Unit of Work
# ============================================================================

class UnitOfWork:
    def __init__(self, db: DatabaseConnection):
        self.db = db
        self.conn: Optional[sqlite3.Connection] = None
    
    def __enter__(self):
        self.conn = sqlite3.connect(
            self.db.db_path, 
            timeout=20, 
            detect_types=sqlite3.PARSE_DECLTYPES
        )
        self.conn.row_factory = sqlite3.Row
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        if exc_type:
            self.conn.rollback()
        else:
            self.conn.commit()
        self.conn.close()
    
    def execute(self, query: str, params: Tuple = ()) -> int:
        cur = self.conn.cursor()
        cur.execute(query, params)
        return cur.lastrowid
    
    def get_cursor(self):
        return self.conn.cursor()


# ============================================================================
# Service Layer
# ============================================================================

class UserService:
    def __init__(
        self, 
        db: DatabaseConnection,
        user_repo: UserRepository,
        qr_repo: QRCodeRepository
    ):
        self.db = db
        self.users = user_repo
        self.qrs = qr_repo
    
    def create_user_with_qr(
        self, 
        name: str, 
        email: str, 
        password_hash: str,
        qr_generator: callable
    ) -> Tuple[int, str, str]:
        max_attempts = 10
        
        with UnitOfWork(self.db) as uow:
            cur = uow.get_cursor()
            encrypted_email = encryption.encrypt(email)
            email_hash = encryption.hash_email(email)
            
            cur.execute("""
                INSERT INTO users (name, email, email_hash, password, created_at, is_active)
                VALUES (?, ?, ?, ?, datetime('now'), 1)
            """, (name, encrypted_email, email_hash, password_hash))
            user_id = cur.lastrowid
            
            qr_id = None
            for attempt in range(max_attempts):
                candidate = qr_generator()
                
                try:
                    cur.execute("""
                        INSERT INTO qr_codes (qr_id, user_id, is_active, activated_at, created_at)
                        VALUES (?, ?, 1, datetime('now'), datetime('now'))
                    """, (candidate, user_id))
                    qr_id = candidate
                    break
                except sqlite3.IntegrityError:
                    if attempt == max_attempts - 1:
                        raise RuntimeError("Kunde inte generera unik QR-kod")
                    continue
            
            if not qr_id:
                raise RuntimeError("QR-kod generering misslyckades")
        
        from utils import create_qr_code
        qr_filename = create_qr_code(qr_id, user_id)
        
        return user_id, qr_id, qr_filename
    
    def get_stats(self, user_id: int) -> UserStats:
        user = self.users.get_by_id(user_id)
        if not user:
            return UserStats()
        
        missing, found = MissingDiscRepository(self.db).get_user_stats(user_id)
        
        return UserStats(
            total_returns=user.total_returns,
            member_since=user.member_since,
            missing=missing,
            found=found
        )


class MatchingService:
    def __init__(
        self, 
        missing_repo: MissingDiscRepository
    ):
        self.missing = missing_repo
    
    def find_match(
        self, 
        user_id: int, 
        found_lat: float, 
        found_lng: float
    ) -> Optional[MatchResult]:
        nearby = self.missing.find_nearby(user_id, found_lat, found_lng, radius_km=5.0)
        
        if not nearby:
            return None
        
        if len(nearby) == 1:
            disc, dist = nearby[0]
            confidence = 'high' if dist < 0.5 else 'low'
            return MatchResult(disc=disc, confidence=confidence, distance=dist)
        
        best_dist = nearby[0][1]
        
        if best_dist < 0.5:
            disc, dist = nearby[0]
            return MatchResult(disc=disc, confidence='high', distance=dist)
        
        close_matches = [(d, dist) for d, dist in nearby if dist < 2.0]
        if close_matches:
            disc, dist = close_matches[0]
            return MatchResult(
                disc=disc, 
                confidence='medium', 
                distance=dist,
                multiple=len(close_matches) > 1
            )
        
        disc, dist = nearby[0]
        return MatchResult(disc=disc, confidence='low', distance=dist)


class AdminService:
    def __init__(
        self,
        db: DatabaseConnection,
        user_repo: UserRepository,
        qr_repo: QRCodeRepository,
        handover_repo: HandoverRepository,
        missing_repo: MissingDiscRepository
    ):
        self.db = db
        self.users = user_repo
        self.qrs = qr_repo
        self.handovers = handover_repo
        self.missing = missing_repo
    
    def get_stats(self) -> AdminStats:
        qr_stats = self.qrs.get_stats()
        missing_total, missing_found = self.missing.get_global_stats()
        
        total_missing = missing_total + missing_found
        return_rate = (
            round((missing_found / total_missing * 100), 1) 
            if total_missing > 0 else 0.0
        )
        
        return AdminStats(
            users=len(self.users.get_all_with_stats()),
            active_qrs=qr_stats.get('active', 0),
            inactive_qrs=qr_stats.get('inactive', 0),
            missing_discs=missing_total,
            found_discs=missing_found,
            handovers=self.handovers.get_count(),
            total_scans=qr_stats.get('total_scans', 0),
            active_today=self.handovers.get_active_today(),
            new_this_week=self._get_new_users_this_week(),
            return_rate=return_rate
        )
    
    def _get_new_users_this_week(self) -> int:
        query = """
            SELECT COUNT(*) as count FROM users 
            WHERE created_at > datetime('now', '-7 days') AND is_active = 1
        """
        row = self.db.fetch_one(query)
        return row.get('count', 0) if row else 0
    
    def reset_database(self, confirm: bool = False) -> bool:
        if not confirm:
            logger.warning("reset_database anropad utan confirm=True")
            return False
        
        db_path = self.db.db_path
        
        if os.path.exists(db_path):
            backup_path = f"{db_path}.backup.{int(os.path.getmtime(db_path))}"
            os.rename(db_path, backup_path)
            logger.info(f"Databas backupad till {backup_path}")
        
        DatabaseManager(self.db).init_tables()
        logger.critical("Databasen är nollställd!")
        return True


# ============================================================================
# Database Manager
# ============================================================================

class DatabaseManager:
    def __init__(self, db: DatabaseConnection):
        self.db = db
    
    def init_tables(self) -> None:
        schema = self._get_schema()
        
        with self.db.get_connection() as conn:
            cur = conn.cursor()
            
            for table_sql in schema:
                cur.execute(table_sql)
            
            self._migrate_last_login(cur)
            self._migrate_soft_delete(cur)
            self._migrate_email_encryption(cur)
            self._create_indexes(cur)
            
            logger.info("Database initialized")
    
    def _get_schema(self) -> List[str]:
        return [
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                email TEXT UNIQUE NOT NULL,
                email_hash TEXT,
                password TEXT NOT NULL,
                reset_token TEXT,
                member_since TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                total_returns INTEGER DEFAULT 0,
                is_premium BOOLEAN DEFAULT 0,
                last_login TIMESTAMP,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                is_active BOOLEAN DEFAULT 1,
                deleted_at TIMESTAMP
            )
            """,
            """
            CREATE TABLE IF NOT EXISTS qr_codes (
                qr_id TEXT PRIMARY KEY,
                user_id INTEGER,
                is_active BOOLEAN DEFAULT 0,
                activated_at TIMESTAMP,
                total_scans INTEGER DEFAULT 0,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users(id)
            )
            """,
            """
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
            """,
            """
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
            """,
            """
            CREATE TABLE IF NOT EXISTS clubs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                email TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL,
                logo_url TEXT,
                member_count INTEGER DEFAULT 0,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
            """
        ]
    
    def _migrate_last_login(self, cursor) -> None:
        try:
            cursor.execute("SELECT last_login FROM users LIMIT 1")
        except sqlite3.OperationalError:
            cursor.execute("ALTER TABLE users ADD COLUMN last_login TIMESTAMP")
            logger.info("La till kolumnen last_login")
    
    def _migrate_soft_delete(self, cursor) -> None:
        try:
            cursor.execute("SELECT is_active FROM users LIMIT 1")
        except sqlite3.OperationalError:
            cursor.execute("ALTER TABLE users ADD COLUMN is_active BOOLEAN DEFAULT 1")
            cursor.execute("ALTER TABLE users ADD COLUMN deleted_at TIMESTAMP")
            logger.info("La till soft delete kolumner")
    
    def _migrate_email_encryption(self, cursor) -> None:
        try:
            cursor.execute("SELECT email_hash FROM users LIMIT 1")
        except sqlite3.OperationalError:
            cursor.execute("ALTER TABLE users ADD COLUMN email_hash TEXT")
            logger.info("La till email_hash kolumn")
            
            cursor.execute("SELECT id, email FROM users WHERE email_hash IS NULL OR email_hash = ''")
            rows = cursor.fetchall()
            for row in rows:
                email_hash = encryption.hash_email(row['email'])
                cursor.execute(
                    "UPDATE users SET email_hash = ? WHERE id = ?",
                    (email_hash, row['id'])
                )
            logger.info(f"Indexerade {len(rows)} befintliga användare")
    
    def _create_indexes(self, cursor) -> None:
        indexes = [
            ("idx_qr_user", "qr_codes(user_id)"),
            ("idx_handovers_qr", "handovers(qr_id)"),
            ("idx_users_email", "users(email)"),
            ("idx_users_email_hash", "users(email_hash)"),
            ("idx_users_active", "users(is_active)"),
            ("idx_missing_user", "missing_discs(user_id)"),
            ("idx_missing_status", "missing_discs(status)"),
            ("idx_missing_location", "missing_discs(latitude, longitude)")
        ]
        
        for name, columns in indexes:
            cursor.execute(f"CREATE INDEX IF NOT EXISTS {name} ON {columns}")


# ============================================================================
# Facade / Main Database Class
# ============================================================================

class Database:
    def __init__(self, db_path: str = None):
        self._db = DatabaseConnection(db_path or DB_PATH)
        self._init_repositories()
        self._init_services()
    
    def _init_repositories(self) -> None:
        self._users = UserRepository(self._db)
        self._qrs = QRCodeRepository(self._db)
        self._handovers = HandoverRepository(self._db)
        self._missing = MissingDiscRepository(self._db)
    
    def _init_services(self) -> None:
        self._user_service = UserService(self._db, self._users, self._qrs)
        self._matching = MatchingService(self._missing)
        self._admin = AdminService(
            self._db, self._users, self._qrs, self._handovers, self._missing
        )
        self._manager = DatabaseManager(self._db)
    
    def init_tables(self) -> None:
        self._manager.init_tables()
    
    def reset_database(self, confirm: bool = False) -> bool:
        return self._admin.reset_database(confirm)
    
    def create_user(self, name: str, email: str, password_hash: str) -> int:
        return self._users.create(name, email, password_hash)
    
    def get_user_by_email(self, email: str) -> Optional[Dict]:
        user = self._users.get_by_email(email)
        return user.to_dict() if user else None
    
    def get_user_by_id(self, user_id: int) -> Optional[Dict]:
        user = self._users.get_by_id(user_id)
        return user.to_dict() if user else None
    
    def get_user_by_token(self, token: str) -> Optional[Dict]:
        user = self._users.get_by_token(token)
        return user.to_dict() if user else None
    
    def update_password(self, user_id: int, password_hash: str) -> None:
        self._users.update_password(user_id, password_hash)
    
    def set_reset_token(self, email: str, token: str) -> bool:
        return self._users.set_reset_token(email, token)
    
    def clear_reset_token(self, user_id: int) -> None:
        self._users.clear_reset_token(user_id)
    
    def update_last_login(self, user_id: int) -> None:
        self._users.update_last_login(user_id)
    
    def increment_returns(self, user_id: int) -> bool:
        return self._users.increment_returns(user_id)
    
    def soft_delete_user(self, user_id: int) -> bool:
        return self._users.soft_delete(user_id)
    
    def create_qr(self, qr_id: str) -> bool:
        return self._qrs.create(qr_id)
    
    def get_qr(self, qr_id: str) -> Optional[Dict]:
        qr = self._qrs.get_by_id(qr_id)
        return qr.to_dict() if qr else None
    
    def activate_qr(self, qr_id: str, user_id: int) -> None:
        self._qrs.activate(qr_id, user_id)
    
    def get_user_qr(self, user_id: int) -> Optional[Dict]:
        qr = self._qrs.get_by_user(user_id)
        return qr.to_dict() if qr else None
    
    def increment_qr_scans(self, qr_id: str) -> None:
        self._qrs.increment_scans(qr_id)
    
    def create_handover(
        self, 
        qr_id: str, 
        action: str, 
        note: str,
        finder_user_id: Optional[int] = None,
        finder_name: Optional[str] = None,
        photo_path: Optional[str] = None,
        latitude: Optional[float] = None,
        longitude: Optional[float] = None
    ) -> int:
        handover = Handover(
            qr_id=qr_id,
            action=action,
            note=note,
            finder_user_id=finder_user_id,
            finder_name=finder_name,
            photo_path=photo_path,
            latitude=latitude,
            longitude=longitude
        )
        return self._handovers.create(handover)
    
    def confirm_handover(self, handover_id: int) -> None:
        self._handovers.confirm(handover_id)
    
    def report_missing_disc(
        self,
        user_id: int,
        disc_name: str,
        description: str,
        latitude: float,
        longitude: float,
        course_name: str = None,
        hole_number: str = None
    ) -> int:
        disc = MissingDisc(
            user_id=user_id,
            disc_name=disc_name,
            description=description,
            latitude=latitude,
            longitude=longitude,
            course_name=course_name,
            hole_number=hole_number
        )
        return self._missing.create(disc)
    
    def get_user_missing_discs(self, user_id: int) -> List[Dict]:
        discs = self._missing.get_by_user(user_id)
        return [d.to_dict() for d in discs]
    
    def get_all_missing_discs(self, status: str = 'missing') -> List[Dict]:
        discs = self._missing.get_all(status)
        return [d.to_dict() for d in discs]
    
    def mark_disc_found(self, disc_id: int, found_by_user_id: int = None) -> None:
        self._missing.mark_found(disc_id, found_by_user_id)
    
    def delete_missing_disc(self, disc_id: int, user_id: int) -> bool:
        return self._missing.delete(disc_id, user_id)
    
    def get_user_stats(self, user_id: int) -> Dict:
        stats = self._user_service.get_stats(user_id)
        return {
            'total_returns': stats.total_returns,
            'member_since': stats.member_since
        }
    
    def get_user_missing_stats(self, user_id: int) -> Dict:
        stats = self._user_service.get_stats(user_id)
        return {
            'missing': stats.missing,
            'found': stats.found
        }
    
    def get_global_missing_stats(self) -> Dict:
        total, found = self._missing.get_global_stats()
        return {
            'total_missing': total,
            'total_found': found
        }
    
    def get_stats(self) -> Dict[str, int]:
        admin_stats = self._admin.get_stats()
        return {
            'users': admin_stats.users,
            'active_qrs': admin_stats.active_qrs,
            'handovers': admin_stats.handovers,
            'total_scans': admin_stats.total_scans,
            'missing_discs': admin_stats.missing_discs
        }
    
    def get_admin_stats(self) -> Dict:
        stats = self._admin.get_stats()
        return {
            'users': stats.users,
            'active_qrs': stats.active_qrs,
            'inactive_qrs': stats.inactive_qrs,
            'missing_discs': stats.missing_discs,
            'found_discs': stats.found_discs,
            'handovers': stats.handovers,
            'total_scans': stats.total_scans,
            'active_today': stats.active_today,
            'new_this_week': stats.new_this_week,
            'return_rate': stats.return_rate
        }
    
    def create_user_with_qr(
        self, 
        name: str, 
        email: str, 
        password_hash: str
    ) -> Tuple[int, str, str]:
        from utils import generate_random_qr_id
        return self._user_service.create_user_with_qr(
            name, email, password_hash, generate_random_qr_id
        )
    
    def find_matching_missing_disc(
        self,
        user_id: int,
        found_lat: float,
        found_lng: float
    ) -> Optional[Dict]:
        match = self._matching.find_match(user_id, found_lat, found_lng)
        if not match:
            return None
        
        result = {
            **match.disc.to_dict(),
            'confidence': match.confidence,
            'distance': match.distance
        }
        
        if match.multiple:
            nearby = self._missing.find_nearby(user_id, found_lat, found_lng)
            result['multiple'] = True
            result['matches'] = [
                {**d.to_dict(), 'distance': dist} 
                for d, dist in nearby[:3]
            ]
        
        return result
    
    def get_all_users_with_stats(self) -> List[Dict]:
        return self._users.get_all_with_stats()
    
    def get_all_qr_codes_with_users(self) -> List[Dict]:
        return self._qrs.get_all_with_users()


db = Database(DB_PATH)