"""Database-hantering med Repository Pattern och kryptering."""
import sqlite3
import psycopg2
import psycopg2.extras
from urllib.parse import urlparse
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


# Kolla om vi är på Railway (qr-mappen finns)
if os.path.isdir('/app/static/qr'):
    # Skapa egen mapp för databas om den inte finns
    db_dir = '/app/data'
    if not os.path.exists(db_dir):
        os.makedirs(db_dir)
    DB_PATH = os.path.join(db_dir, 'database.db')
else:
    # Lokal utveckling
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
# SQL Dialect Helper - NYTT för PostgreSQL/SQLite kompatibilitet
# ============================================================================

class SQLDialect:
    """Hjälpklass för databasspecifik SQL-syntax."""
    
    def __init__(self, is_postgres: bool = False):
        self.is_postgres = is_postgres
    
    def now_minus_days(self, days: int) -> str:
        """Returnera SQL för nuvarande tid minus X dagar."""
        if self.is_postgres:
            return f"CURRENT_TIMESTAMP - INTERVAL '{days} days'"
        return f"datetime('now', '-{days} days')"
    
    def now_minus_months(self, months: int) -> str:
        """Returnera SQL för nuvarande tid minus X månader."""
        if self.is_postgres:
            return f"CURRENT_TIMESTAMP - INTERVAL '{months} months'"
        return f"datetime('now', '-{months} months')"
    
    def current_date(self) -> str:
        """Returnera SQL för nuvarande datum."""
        if self.is_postgres:
            return "CURRENT_DATE"
        return "date('now')"
    
    def current_timestamp(self) -> str:
        """Returnera SQL för nuvarande timestamp."""
        if self.is_postgres:
            return "CURRENT_TIMESTAMP"
        return "datetime('now')"
    
    def date_diff_days(self, col1: str, col2: str) -> str:
        """Returnera SQL för skillnad i dagar mellan två datum."""
        if self.is_postgres:
            return f"EXTRACT(DAY FROM ({col1} - {col2}))"
        return f"julianday({col1}) - julianday({col2})"
    
    def strftime(self, format_str: str, col: str) -> str:
        """Returnera SQL för datumformatering."""
        if self.is_postgres:
            # Konvertera SQLite strftime-format till PostgreSQL TO_CHAR-format
            pg_format = format_str.replace('%Y', 'YYYY').replace('%m', 'MM').replace('%d', 'DD')
            return f"TO_CHAR({col}, '{pg_format}')"
        return f"strftime('{format_str}', {col})"
    
    def random(self) -> str:
        """Returnera SQL för slumpmässigt tal."""
        if self.is_postgres:
            return "RANDOM()"
        return "RANDOM()"
    
    def random_order(self) -> str:
        """Returnera SQL för slumpmässig sortering."""
        if self.is_postgres:
            return "RANDOM()"
        return "RANDOM()"
    
    def limit_offset(self, limit: int, offset: int = 0) -> str:
        """Returnera SQL för LIMIT och OFFSET."""
        if self.is_postgres:
            return f"LIMIT {limit} OFFSET {offset}"
        return f"LIMIT {limit} OFFSET {offset}"
    
    def coalesce(self, *args) -> str:
        """Returnera SQL för COALESCE/IFNULL."""
        args_str = ', '.join(str(a) for a in args)
        if self.is_postgres:
            return f"COALESCE({args_str})"
        return f"COALESCE({args_str})"
    
    def boolean(self, value: bool) -> str:
        """Returnera SQL för boolean-värde."""
        if self.is_postgres:
            return "TRUE" if value else "FALSE"
        return "1" if value else "0"
    
    def auto_increment(self) -> str:
        """Returnera SQL för auto-increment kolumn."""
        if self.is_postgres:
            return "SERIAL"
        return "INTEGER PRIMARY KEY AUTOINCREMENT"
    
    def placeholder(self, index: int = 0) -> str:
        """Returnera SQL placeholder (? eller %s)."""
        if self.is_postgres:
            return "%s"
        return "?"
    
    def cast_text(self, col: str) -> str:
        """Casta kolumn till text."""
        if self.is_postgres:
            return f"CAST({col} AS TEXT)"
        return f"CAST({col} AS TEXT)"


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
    premium_until: Optional[datetime] = None
    premium_started_at: Optional[datetime] = None
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
    
    def has_active_premium(self) -> bool:
        """Kontrollera om användaren har aktivt premium."""
        if not self.is_premium:
            return False
        if self.premium_until is None:
            return True
        return datetime.now() < self.premium_until


@dataclass
class PremiumSubscription:
    id: Optional[int] = None
    user_id: int = 0
    status: str = "active"
    started_at: Optional[datetime] = None
    expires_at: Optional[datetime] = None
    payment_method: Optional[str] = None
    payment_id: Optional[str] = None
    amount_paid: Optional[float] = None
    currency: str = "SEK"
    is_launch_offer: bool = False
    created_at: Optional[datetime] = None
    
    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)
    
    def is_active(self) -> bool:
        """Kontrollera om prenumerationen är aktiv."""
        if self.status != 'active':
            return False
        if self.expires_at is None:
            return True
        return datetime.now() < self.expires_at


@dataclass
class QRCode:
    qr_id: str = ""
    user_id: Optional[int] = None
    is_active: bool = False
    is_enabled: bool = True
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
class Order:
    id: Optional[int] = None
    order_number: str = ""
    user_id: int = 0
    qr_id: Optional[str] = None
    package_type: str = ""
    quantity: int = 0
    total_amount: float = 0.0
    currency: str = "SEK"
    status: str = "pending"
    payment_method: str = ""
    payment_id: Optional[str] = None
    shipping_name: str = ""
    shipping_address: str = ""
    shipping_postal_code: str = ""
    shipping_city: str = ""
    shipping_country: str = "SE"
    created_at: Optional[datetime] = None
    paid_at: Optional[datetime] = None
    shipped_at: Optional[datetime] = None
    
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
    premium_users: int = 0


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
        self.database_url = os.environ.get("DATABASE_URL")
        self.dialect = SQLDialect(is_postgres=bool(self.database_url))

    @contextmanager
    def get_connection(self):
        # Railway / PostgreSQL
        if self.database_url:
            url = urlparse(self.database_url)
            conn = psycopg2.connect(
                host=url.hostname,
                port=url.port,
                user=url.username,
                password=url.password,
                dbname=url.path[1:]
            )
            conn.cursor_factory = psycopg2.extras.RealDictCursor
            try:
                yield conn
                conn.commit()
            except Exception:
                conn.rollback()
                raise
            finally:
                conn.close()
        # Lokal SQLite
        else:
            conn = sqlite3.connect(self.db_path)
            conn.row_factory = sqlite3.Row
            try:
                yield conn
                conn.commit()
            except Exception:
                conn.rollback()
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
    
    def _adapt_query(self, query: str) -> str:
        """Anpassa query för PostgreSQL om nödvändigt."""
        if not self.database_url:
            return query
        
        # Ersätt ? med %s för PostgreSQL
        # Men var försiktig med att inte ersätta ? i strängar
        # Detta är en enkel implementation - i produktion bör du använda en riktig parser
        adapted = query.replace("?", "%s")
        
        # Hantera SQLite-specifika datumfunktioner som inte redan hanterats
        # datetime('now') -> CURRENT_TIMESTAMP
        adapted = adapted.replace("datetime('now')", "CURRENT_TIMESTAMP")
        # date('now') -> CURRENT_DATE
        adapted = adapted.replace("date('now')", "CURRENT_DATE")
        
        return adapted
    
    def execute(self, query: str, params: Tuple = (), fetch_one: bool = False):
        """FIXAD: Använder nu get_connection() context manager istället för self.conn"""
        with self.get_connection() as conn:
            cur = conn.cursor()
            
            # PostgreSQL använder %s istället för ?
            if self.database_url:
                query = query.replace("?", "%s")
                # Ersätt även datumfunktioner
                query = query.replace("datetime('now')", "CURRENT_TIMESTAMP")
                query = query.replace("date('now')", "CURRENT_DATE")
            
            adapted_query = self._adapt_query(query)
            cur.execute(adapted_query, params)
            
            # Hantera lastrowid olika för PostgreSQL vs SQLite
            if self.database_url:
                # För PostgreSQL, försök hämta RETURNING
                if 'RETURNING' in query.upper():
                    row = cur.fetchone()
                    return row[0] if row else None
                return None
            else:
                # SQLite använder lastrowid
                return cur.lastrowid

    def execute_many(
        self, 
        query: str, 
        params: List[Tuple] = None
    ) -> int:
        with self.get_connection() as conn:
            cur = conn.cursor()
            adapted_query = self._adapt_query(query)
            if params:
                cur.executemany(adapted_query, params)
            else:
                cur.execute(adapted_query)
            return cur.rowcount
    
    def fetch_all(self, query: str, params: Tuple = ()) -> List[Dict]:
        with self.get_connection() as conn:
            cur = conn.cursor()
            adapted_query = self._adapt_query(query)
            cur.execute(adapted_query, params)
            return [dict(row) for row in cur.fetchall()]

    def fetch_one(self, query: str, params: Tuple = ()) -> Optional[Dict]:
        with self.get_connection() as conn:
            cur = conn.cursor()
            adapted_query = self._adapt_query(query)
            cur.execute(adapted_query, params)
            row = cur.fetchone()
            return dict(row) if row else None
    
    def last_insert_id(self, cursor=None) -> int:
        """Hämta senaste insert ID. OBS: För PostgreSQL krävs RETURNING."""
        if self.database_url:
            # För PostgreSQL ska vi använda RETURNING i INSERT istället
            # Detta är en fallback som inte bör användas
            logger.warning("last_insert_id() anropad för PostgreSQL - använd RETURNING istället!")
            return None
        else:
            # SQLite
            if cursor:
                return cursor.lastrowid
            # Om ingen cursor ges, hämta från ny connection (inte idealiskt)
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
        if decrypt and email and email.startswith('gAAAA'):
            email = encryption.decrypt(email)
        
        def parse_timestamp(val):
            if not val:
                return None
            if isinstance(val, datetime):
                return val
            try:
                # Hantera både ISO-format och PostgreSQL timestamp
                if isinstance(val, str):
                    return datetime.fromisoformat(val.replace('Z', '+00:00'))
                return val
            except:
                return None
        
        return User(
            id=row.get('id'),
            name=row.get('name', ''),
            email=email,
            email_hash=row.get('email_hash', ''),
            password=row.get('password', ''),
            reset_token=row.get('reset_token'),
            member_since=parse_timestamp(row.get('member_since')),
            total_returns=row.get('total_returns', 0),
            is_premium=bool(row.get('is_premium', 0)),
            premium_until=parse_timestamp(row.get('premium_until')),
            premium_started_at=parse_timestamp(row.get('premium_started_at')),
            last_login=parse_timestamp(row.get('last_login')),
            created_at=parse_timestamp(row.get('created_at')),
            is_active=bool(row.get('is_active', 1)),
            deleted_at=parse_timestamp(row.get('deleted_at'))
        )
    
    def create(self, name: str, email: str, password_hash: str) -> int:
        encrypted_email = encryption.encrypt(email)
        email_hash = encryption.hash_email(email)
        
        if self.db.database_url:
            # PostgreSQL - använd RETURNING
            query = """
                INSERT INTO users (name, email, email_hash, password, created_at, is_active)
                VALUES (%s, %s, %s, %s, CURRENT_TIMESTAMP, TRUE)
                RETURNING id
            """
            with self.db.get_connection() as conn:
                cur = conn.cursor()
                cur.execute(query, (name, encrypted_email, email_hash, password_hash))
                row = cur.fetchone()
                return row['id'] if row else None
        else:
            # SQLite
            query = """
                INSERT INTO users (name, email, email_hash, password, created_at, is_active)
                VALUES (?, ?, ?, ?, CURRENT_TIMESTAMP, 1)
            """
            self.db.execute(query, (name, encrypted_email, email_hash, password_hash))
            return self.db.last_insert_id()
    
    def get_by_email(self, email: str) -> Optional[User]:
        email_hash = encryption.hash_email(email)
        query = f"SELECT * FROM users WHERE email_hash = {self.db.dialect.placeholder()} AND is_active = {self.db.dialect.boolean(True)}"
        row = self.db.fetch_one(query, (email_hash,))
        
        if row:
            return self.row_to_model(row)
        
        # Fallback för äldre användare utan hash
        query = f"SELECT * FROM users WHERE email = {self.db.dialect.placeholder()} AND is_active = {self.db.dialect.boolean(True)}"
        row = self.db.fetch_one(query, (email.lower(),))
        return self.row_to_model(row) if row else None
    
    def get_by_id(self, user_id: int, include_password: bool = False) -> Optional[User]:
        if include_password:
            query = f"SELECT * FROM users WHERE id = {self.db.dialect.placeholder()} AND is_active = {self.db.dialect.boolean(True)}"
        else:
            query = f"""
                SELECT id, name, email, email_hash, member_since, 
                       total_returns, is_premium, premium_until, premium_started_at,
                       last_login, created_at, is_active, deleted_at
                FROM users WHERE id = {self.db.dialect.placeholder()} AND is_active = {self.db.dialect.boolean(True)}
            """
        row = self.db.fetch_one(query, (user_id,))
        return self.row_to_model(row) if row else None
    
    def get_by_token(self, token: str) -> Optional[User]:
        query = f"SELECT * FROM users WHERE reset_token = {self.db.dialect.placeholder()} AND is_active = {self.db.dialect.boolean(True)}"
        row = self.db.fetch_one(query, (token,))
        return self.row_to_model(row) if row else None
    
    def soft_delete(self, user_id: int) -> bool:
        query = f"""
            UPDATE users 
            SET is_active = {self.db.dialect.boolean(False)}, deleted_at = {self.db.dialect.current_timestamp()},
                name = '[BORTTAGEN]', email = '[BORTTAGEN]',
                email_hash = '', password = '[BORTTAGEN]'
            WHERE id = {self.db.dialect.placeholder()}
        """
        self.db.execute(query, (user_id,))
        return True
    
    def update_password(self, user_id: int, password_hash: str) -> None:
        query = f"""
            UPDATE users 
            SET password = {self.db.dialect.placeholder()}, reset_token = NULL 
            WHERE id = {self.db.dialect.placeholder()}
        """
        self.db.execute(query, (password_hash, user_id))
    
    def set_reset_token(self, email: str, token: str) -> bool:
        email_hash = encryption.hash_email(email)
        query = f"UPDATE users SET reset_token = {self.db.dialect.placeholder()} WHERE email_hash = {self.db.dialect.placeholder()}"
        self.db.execute(query, (token, email_hash))
        return True
    
    def clear_reset_token(self, user_id: int) -> None:
        query = f"UPDATE users SET reset_token = NULL WHERE id = {self.db.dialect.placeholder()}"
        self.db.execute(query, (user_id,))
    
    def update_last_login(self, user_id: int) -> None:
        query = f"UPDATE users SET last_login = {self.db.dialect.current_timestamp()} WHERE id = {self.db.dialect.placeholder()}"
        self.db.execute(query, (user_id,))
    
    def increment_returns(self, user_id: int) -> bool:
        query = f"""
            UPDATE users 
            SET total_returns = total_returns + 1 
            WHERE id = {self.db.dialect.placeholder()}
        """
        self.db.execute(query, (user_id,))
        return True
    
    def activate_premium(self, user_id: int, expires_at: Optional[datetime] = None) -> bool:
        query = f"""
            UPDATE users 
            SET is_premium = {self.db.dialect.boolean(True)}, premium_started_at = {self.db.dialect.current_timestamp()},
                premium_until = {self.db.dialect.placeholder()}
            WHERE id = {self.db.dialect.placeholder()}
        """
        expires_str = expires_at.isoformat() if expires_at else None
        self.db.execute(query, (expires_str, user_id))
        return True
    
    def deactivate_premium(self, user_id: int) -> bool:
        query = f"""
            UPDATE users 
            SET is_premium = {self.db.dialect.boolean(False)}, premium_until = NULL
            WHERE id = {self.db.dialect.placeholder()}
        """
        self.db.execute(query, (user_id,))
        return True
    
    def get_all_with_stats(self, active_only: bool = True) -> List[Dict]:
        where_clause = f"WHERE u.is_active = {self.db.dialect.boolean(True)}" if active_only else ""
        
        # Använd databasspecifik datumfunktion
        date_expr = self.db.dialect.now_minus_days(7)
        
        query = f"""
            SELECT 
                u.id, u.name, u.email, u.created_at, u.last_login, u.is_active,
                u.is_premium, u.premium_until, u.premium_started_at,
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
            email = row.get('email')
            if email and email.startswith('gAAAA'):
                row['email'] = encryption.decrypt(email)
        
        return rows
    
    def get_premium_count(self) -> int:
        query = f"""
            SELECT COUNT(*) as count FROM users 
            WHERE is_premium = {self.db.dialect.boolean(True)} AND is_active = {self.db.dialect.boolean(True)}
            AND (premium_until IS NULL OR premium_until > {self.db.dialect.current_timestamp()})
        """
        row = self.db.fetch_one(query)
        return row.get('count', 0) if row else 0


# ============================================================================
# Premium Subscription Repository
# ============================================================================

class PremiumSubscriptionRepository(BaseRepository):
    TABLE = "premium_subscriptions"
    
    def row_to_model(self, row: Dict) -> PremiumSubscription:
        return PremiumSubscription(
            id=row.get('id'),
            user_id=row.get('user_id', 0),
            status=row.get('status', 'active'),
            started_at=row.get('started_at'),
            expires_at=row.get('expires_at'),
            payment_method=row.get('payment_method'),
            payment_id=row.get('payment_id'),
            amount_paid=row.get('amount_paid'),
            currency=row.get('currency', 'SEK'),
            is_launch_offer=bool(row.get('is_launch_offer', 0)),
            created_at=row.get('created_at')
        )
    
    def create(self, subscription: PremiumSubscription) -> int:
        if self.db.database_url:
            # PostgreSQL
            query = """
                INSERT INTO premium_subscriptions 
                (user_id, status, started_at, expires_at, payment_method, 
                 payment_id, amount_paid, currency, is_launch_offer, created_at)
                VALUES (%s, %s, CURRENT_TIMESTAMP, %s, %s, %s, %s, %s, %s, CURRENT_TIMESTAMP)
                RETURNING id
            """
            with self.db.get_connection() as conn:
                cur = conn.cursor()
                cur.execute(query, (
                    subscription.user_id,
                    subscription.status,
                    subscription.expires_at.isoformat() if subscription.expires_at else None,
                    subscription.payment_method,
                    subscription.payment_id,
                    subscription.amount_paid,
                    subscription.currency,
                    subscription.is_launch_offer  # ÄNDRAT: Boolean direkt för PostgreSQL
                ))
                row = cur.fetchone()
                return row['id'] if row else None
        else:
            # SQLite
            query = """
                INSERT INTO premium_subscriptions 
                (user_id, status, started_at, expires_at, payment_method, 
                 payment_id, amount_paid, currency, is_launch_offer, created_at)
                VALUES (?, ?, CURRENT_TIMESTAMP, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
            """
            self.db.execute(query, (
                subscription.user_id,
                subscription.status,
                subscription.expires_at.isoformat() if subscription.expires_at else None,
                subscription.payment_method,
                subscription.payment_id,
                subscription.amount_paid,
                subscription.currency,
                1 if subscription.is_launch_offer else 0  # SQLite använder 1/0
            ))
            return self.db.last_insert_id()
    
    def get_by_id(self, sub_id: int) -> Optional[PremiumSubscription]:
        query = f"SELECT * FROM premium_subscriptions WHERE id = {self.db.dialect.placeholder()}"
        row = self.db.fetch_one(query, (sub_id,))
        return self.row_to_model(row) if row else None
    
    def get_by_user(self, user_id: int, active_only: bool = True) -> List[PremiumSubscription]:
        status_clause = f"AND status = 'active'" if active_only else ""
        query = f"""
            SELECT * FROM premium_subscriptions 
            WHERE user_id = {self.db.dialect.placeholder()} {status_clause}
            ORDER BY created_at DESC
        """
        rows = self.db.fetch_all(query, (user_id,))
        return [self.row_to_model(row) for row in rows]
    
    def get_active_for_user(self, user_id: int) -> Optional[PremiumSubscription]:
        query = f"""
            SELECT * FROM premium_subscriptions 
            WHERE user_id = {self.db.dialect.placeholder()} AND status = 'active'
            AND (expires_at IS NULL OR expires_at > {self.db.dialect.current_timestamp()})
            ORDER BY created_at DESC
            LIMIT 1
        """
        rows = self.db.fetch_all(query, (user_id,))
        return self.row_to_model(rows[0]) if rows else None
    
    def cancel_subscription(self, sub_id: int) -> bool:
        query = f"""
            UPDATE premium_subscriptions 
            SET status = 'cancelled'
            WHERE id = {self.db.dialect.placeholder()}
        """
        self.db.execute(query, (sub_id,))
        return True
    
    def update_status(self, sub_id: int, status: str) -> bool:
        query = f"UPDATE premium_subscriptions SET status = {self.db.dialect.placeholder()} WHERE id = {self.db.dialect.placeholder()}"
        self.db.execute(query, (status, sub_id))
        return True


# ============================================================================
# QR Code Repository
# ============================================================================

class QRCodeRepository(BaseRepository):
    def row_to_model(self, row: Dict) -> QRCode:
        return QRCode(
            qr_id=row.get('qr_id', ''),
            user_id=row.get('user_id'),
            is_active=bool(row.get('is_active', 0)),
            is_enabled=bool(row.get('is_enabled', 1)),
            activated_at=row.get('activated_at'),
            total_scans=row.get('total_scans', 0),
            created_at=row.get('created_at')
        )
    
    def create(self, qr_id: str) -> bool:
        try:
            query = f"INSERT INTO qr_codes (qr_id) VALUES ({self.db.dialect.placeholder()})"
            self.db.execute(query, (qr_id,))
            return True
        except (sqlite3.IntegrityError, psycopg2.IntegrityError) as e:
            logger.warning(f"QR-kod {qr_id} finns redan: {e}")
            return False
    
    def get_by_id(self, qr_id: str) -> Optional[QRCode]:
        query = f"SELECT * FROM qr_codes WHERE qr_id = {self.db.dialect.placeholder()}"
        row = self.db.fetch_one(query, (qr_id,))
        return self.row_to_model(row) if row else None
    
    def get_by_user(self, user_id: int) -> List[QRCode]:
        query = f"SELECT * FROM qr_codes WHERE user_id = {self.db.dialect.placeholder()} ORDER BY created_at DESC"
        rows = self.db.fetch_all(query, (user_id,))
        return [self.row_to_model(row) for row in rows]
    
    def get_active_for_user(self, user_id: int) -> List[QRCode]:
        """Hämta alla aktiva och aktiverade QR-koder för användare."""
        query = f"""
            SELECT * FROM qr_codes 
            WHERE user_id = {self.db.dialect.placeholder()} 
            AND is_active = {self.db.dialect.boolean(True)} 
            AND is_enabled = {self.db.dialect.boolean(True)} 
            ORDER BY created_at DESC
        """
        rows = self.db.fetch_all(query, (user_id,))
        return [self.row_to_model(row) for row in rows]
    
    def activate(self, qr_id: str, user_id: int) -> None:
        query = f"""
            UPDATE qr_codes 
            SET user_id = {self.db.dialect.placeholder()}, 
                is_active = {self.db.dialect.boolean(True)}, 
                is_enabled = {self.db.dialect.boolean(True)}, 
                activated_at = {self.db.dialect.current_timestamp()}
            WHERE qr_id = {self.db.dialect.placeholder()}
        """
        self.db.execute(query, (user_id, qr_id))
    
    def assign_to_user(self, qr_id: str, user_id: int) -> bool:
        """Tilldela en inaktiv QR-kod till en användare."""
        qr = self.get_by_id(qr_id)
        if not qr:
            raise ValueError("QR-koden finns inte")
        if qr.user_id is not None:
            raise ValueError("QR-koden är redan tilldelad")
        
        query = f"""
            UPDATE qr_codes 
            SET user_id = {self.db.dialect.placeholder()}, 
                is_active = {self.db.dialect.boolean(True)}, 
                is_enabled = {self.db.dialect.boolean(True)}, 
                activated_at = {self.db.dialect.current_timestamp()}
            WHERE qr_id = {self.db.dialect.placeholder()}
        """
        self.db.execute(query, (user_id, qr_id))
        return True
    
    def toggle_enabled(self, qr_id: str, user_id: int, enabled: bool) -> bool:
        """Aktivera/inaktivera en QR-kod (användaren måste äga den)."""
        qr = self.get_by_id(qr_id)
        if not qr or qr.user_id != user_id:
            return False
        
        query = f"UPDATE qr_codes SET is_enabled = {self.db.dialect.boolean(enabled)} WHERE qr_id = {self.db.dialect.placeholder()}"
        self.db.execute(query, (qr_id,))
        return True
    
    def increment_scans(self, qr_id: str) -> None:
        query = f"UPDATE qr_codes SET total_scans = total_scans + 1 WHERE qr_id = {self.db.dialect.placeholder()}"
        self.db.execute(query, (qr_id,))
    
    def get_all_with_users(self) -> List[Dict]:
        query = """
            SELECT q.qr_id, q.is_active, q.is_enabled, q.activated_at, q.total_scans,
                   u.id as user_id, u.name, u.email, u.is_premium, u.created_at, u.last_login
            FROM qr_codes q
            LEFT JOIN users u ON q.user_id = u.id
            ORDER BY q.created_at DESC
        """
        
        rows = self.db.fetch_all(query)
        
        for row in rows:
            email = row.get('email')
            if email and email.startswith('gAAAA'):
                row['email'] = encryption.decrypt(email)
            
            if row.get('user_id') and not row.get('name'):
                logger.warning(f"QR {row.get('qr_id')} har user_id {row.get('user_id')} men ingen name!")
                user_row = self.db.fetch_one(
                    "SELECT name, email FROM users WHERE id = ?", 
                    (row.get('user_id'),)
                )
                if user_row:
                    row['name'] = user_row.get('name', 'Okänd')
                    email = user_row.get('email', '')
                    if email and email.startswith('gAAAA'):
                        row['email'] = encryption.decrypt(email)
                    else:
                        row['email'] = email
            
            if row.get('user_id'):
                row['is_active'] = True
        
        return rows
    
    def get_stats(self) -> Dict[str, int]:
        # Använd COALESCE för att hantera NULL-värden i båda databaser
        queries = {
            'active': f"SELECT COUNT(*) FROM qr_codes WHERE is_active = {self.db.dialect.boolean(True)}",
            'inactive': f"SELECT COUNT(*) FROM qr_codes WHERE is_active = {self.db.dialect.boolean(False)}",
            'enabled': f"SELECT COUNT(*) FROM qr_codes WHERE is_active = {self.db.dialect.boolean(True)} AND is_enabled = {self.db.dialect.boolean(True)}",
            'disabled': f"SELECT COUNT(*) FROM qr_codes WHERE is_active = {self.db.dialect.boolean(True)} AND is_enabled = {self.db.dialect.boolean(False)}",
            'total_scans': f"SELECT {self.db.dialect.coalesce('SUM(total_scans)', 0)} FROM qr_codes"
        }
        return {
            key: self.db.fetch_one(query).get(f'COUNT(*)', 0) or 0 
            if 'COUNT' in query else
            self.db.fetch_one(query).get(f'coalesce', 0) or 0
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
        if self.db.database_url:
            # PostgreSQL
            query = """
                INSERT INTO missing_discs 
                (user_id, disc_name, description, latitude, longitude, 
                 course_name, hole_number, created_at)
                VALUES (%s, %s, %s, %s, %s, %s, %s, CURRENT_TIMESTAMP)
                RETURNING id
            """
            with self.db.get_connection() as conn:
                cur = conn.cursor()
                cur.execute(query, (
                    disc.user_id, disc.disc_name, disc.description,
                    disc.latitude, disc.longitude, disc.course_name, disc.hole_number
                ))
                row = cur.fetchone()
                return row['id'] if row else None
        else:
            # SQLite
            query = """
                INSERT INTO missing_discs 
                (user_id, disc_name, description, latitude, longitude, 
                 course_name, hole_number, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
            """
            self.db.execute(query, (
                disc.user_id, disc.disc_name, disc.description,
                disc.latitude, disc.longitude, disc.course_name, disc.hole_number
            ))
            return self.db.last_insert_id()
    
    def get_by_id(self, disc_id: int) -> Optional[MissingDisc]:
        query = f"SELECT * FROM missing_discs WHERE id = {self.db.dialect.placeholder()}"
        row = self.db.fetch_one(query, (disc_id,))
        return self.row_to_model(row) if row else None
    
    def get_by_user(self, user_id: int) -> List[MissingDisc]:
        query = f"""
            SELECT * FROM missing_discs 
            WHERE user_id = {self.db.dialect.placeholder()} 
            ORDER BY created_at DESC
        """
        rows = self.db.fetch_all(query, (user_id,))
        return [self.row_to_model(row) for row in rows]
    
    def get_all(self, status: str = 'missing') -> List[MissingDisc]:
        query = f"""
            SELECT m.*, u.name as reporter_name 
            FROM missing_discs m
            LEFT JOIN users u ON m.user_id = u.id
            WHERE m.status = {self.db.dialect.placeholder()}
            ORDER BY m.created_at DESC
        """
        rows = self.db.fetch_all(query, (status,))
        return [self.row_to_model(row) for row in rows]
    
    def mark_found(self, disc_id: int, found_by_user_id: Optional[int] = None) -> None:
        if found_by_user_id:
            query = f"""
                UPDATE missing_discs 
                SET status = 'found', found_by_user_id = {self.db.dialect.placeholder()}, 
                    found_at = {self.db.dialect.current_timestamp()}
                WHERE id = {self.db.dialect.placeholder()}
            """
            self.db.execute(query, (found_by_user_id, disc_id))
        else:
            query = f"""
                UPDATE missing_discs 
                SET status = 'found', found_at = {self.db.dialect.current_timestamp()}
                WHERE id = {self.db.dialect.placeholder()}
            """
            self.db.execute(query, (disc_id,))
    
    def delete(self, disc_id: int, user_id: int) -> bool:
        query = f"DELETE FROM missing_discs WHERE id = {self.db.dialect.placeholder()} AND user_id = {self.db.dialect.placeholder()}"
        self.db.execute(query, (disc_id, user_id))
        return True
    
    def get_user_stats(self, user_id: int) -> Tuple[int, int]:
        query = f"""
            SELECT 
                COUNT(*) as total,
                SUM(CASE WHEN status = 'found' THEN 1 ELSE 0 END) as found
            FROM missing_discs 
            WHERE user_id = {self.db.dialect.placeholder()}
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
        if self.db.database_url:
            # PostgreSQL
            query = """
                INSERT INTO handovers 
                (qr_id, finder_user_id, finder_name, action, note, 
                 photo_path, latitude, longitude, created_at)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, CURRENT_TIMESTAMP)
                RETURNING id
            """
            with self.db.get_connection() as conn:
                cur = conn.cursor()
                cur.execute(query, (
                    handover.qr_id, handover.finder_user_id, handover.finder_name,
                    handover.action, handover.note, handover.photo_path,
                    handover.latitude, handover.longitude
                ))
                row = cur.fetchone()
                return row['id'] if row else None
        else:
            # SQLite
            query = """
                INSERT INTO handovers 
                (qr_id, finder_user_id, finder_name, action, note, 
                 photo_path, latitude, longitude, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
            """
            self.db.execute(query, (
                handover.qr_id, handover.finder_user_id, handover.finder_name,
                handover.action, handover.note, handover.photo_path,
                handover.latitude, handover.longitude
            ))
            return self.db.last_insert_id()
    
    def confirm(self, handover_id: int) -> None:
        query = f"UPDATE handovers SET confirmed = {self.db.dialect.boolean(True)} WHERE id = {self.db.dialect.placeholder()}"
        self.db.execute(query, (handover_id,))
    
    def get_count(self) -> int:
        query = "SELECT COUNT(*) as count FROM handovers"
        row = self.db.fetch_one(query)
        return row.get('count', 0) if row else 0
    
    def get_active_today(self) -> int:
        """FIXAD för PostgreSQL - använd databasspecifik datumfunktion."""
        date_expr = self.db.dialect.now_minus_days(1)
        query = f"""
            SELECT COUNT(DISTINCT finder_user_id) as count
            FROM handovers 
            WHERE created_at > {date_expr}
        """
        row = self.db.fetch_one(query)
        return row.get('count', 0) if row else 0


# ============================================================================
# Order Repository
# ============================================================================

class OrderRepository(BaseRepository):
    TABLE = "orders"
    
    def row_to_model(self, row: Dict) -> Order:
        return Order(
            id=row.get('id'),
            order_number=row.get('order_number', ''),
            user_id=row.get('user_id', 0),
            qr_id=row.get('qr_id'),
            package_type=row.get('package_type', ''),
            quantity=row.get('quantity', 0),
            total_amount=row.get('total_amount', 0.0),
            currency=row.get('currency', 'SEK'),
            status=row.get('status', 'pending'),
            payment_method=row.get('payment_method', ''),
            payment_id=row.get('payment_id'),
            shipping_name=row.get('shipping_name', ''),
            shipping_address=row.get('shipping_address', ''),
            shipping_postal_code=row.get('shipping_postal_code', ''),
            shipping_city=row.get('shipping_city', ''),
            shipping_country=row.get('shipping_country', 'SE'),
            created_at=row.get('created_at'),
            paid_at=row.get('paid_at'),
            shipped_at=row.get('shipped_at')
        )
    
    def create(self, order: Order) -> int:
        if self.db.database_url:
            # PostgreSQL
            query = """
                INSERT INTO orders 
                (order_number, user_id, qr_id, package_type, quantity, total_amount,
                 currency, status, payment_method, payment_id, shipping_name,
                 shipping_address, shipping_postal_code, shipping_city, shipping_country,
                 created_at)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, CURRENT_TIMESTAMP)
                RETURNING id
            """
            with self.db.get_connection() as conn:
                cur = conn.cursor()
                cur.execute(query, (
                    order.order_number, order.user_id, order.qr_id, order.package_type,
                    order.quantity, order.total_amount, order.currency, order.status,
                    order.payment_method, order.payment_id, order.shipping_name,
                    order.shipping_address, order.shipping_postal_code, order.shipping_city,
                    order.shipping_country
                ))
                row = cur.fetchone()
                return row['id'] if row else None
        else:
            # SQLite
            query = """
                INSERT INTO orders 
                (order_number, user_id, qr_id, package_type, quantity, total_amount,
                 currency, status, payment_method, payment_id, shipping_name,
                 shipping_address, shipping_postal_code, shipping_city, shipping_country,
                 created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
            """
            self.db.execute(query, (
                order.order_number, order.user_id, order.qr_id, order.package_type,
                order.quantity, order.total_amount, order.currency, order.status,
                order.payment_method, order.payment_id, order.shipping_name,
                order.shipping_address, order.shipping_postal_code, order.shipping_city,
                order.shipping_country
            ))
            return self.db.last_insert_id()
    
    def get_by_id(self, order_id: int) -> Optional[Order]:
        query = f"SELECT * FROM orders WHERE id = {self.db.dialect.placeholder()}"
        row = self.db.fetch_one(query, (order_id,))
        return self.row_to_model(row) if row else None
    
    def get_by_order_number(self, order_number: str) -> Optional[Order]:
        query = f"SELECT * FROM orders WHERE order_number = {self.db.dialect.placeholder()}"
        row = self.db.fetch_one(query, (order_number,))
        return self.row_to_model(row) if row else None
    
    def get_all_with_user_info(self, status: str = None, limit: int = 100) -> List[Dict]:
        """Hämta alla ordrar med användarinfo - UTAN dubletter."""
        where_clause = "WHERE 1=1"
        params = []
        if status:
            where_clause += f" AND o.status = {self.db.dialect.placeholder()}"
            params.append(status)
        
        limit_clause = self.db.dialect.limit_offset(limit, 0)
            
        query = f"""
            SELECT DISTINCT
                o.id,
                o.order_number,
                o.user_id,
                o.qr_id,
                o.package_type,
                o.quantity,
                o.total_amount,
                o.currency,
                o.status,
                o.payment_method,
                o.payment_id,
                o.shipping_name,
                o.shipping_address,
                o.shipping_postal_code,
                o.shipping_city,
                o.shipping_country,
                o.created_at,
                o.paid_at,
                o.shipped_at,
                u.name as user_name,
                u.email as user_email,
                u.is_premium as user_is_premium
            FROM orders o
            LEFT JOIN users u ON o.user_id = u.id
            {where_clause}
            ORDER BY o.created_at DESC
            {limit_clause}
        """

        rows = self.db.fetch_all(query, tuple(params))
        
        # Dekryptera email
        for row in rows:
            email = row.get('user_email')
            if email and email.startswith('gAAAA'):
                row['user_email'] = encryption.decrypt(email)
        
        return rows
    
    def get_order_stats(self) -> Dict:
        query = """
            SELECT 
                COUNT(*) as total_orders,
                SUM(CASE WHEN status = 'paid' THEN 1 ELSE 0 END) as paid_orders,
                SUM(CASE WHEN status = 'shipped' THEN 1 ELSE 0 END) as shipped_orders,
                SUM(CASE WHEN status = 'pending' THEN 1 ELSE 0 END) as pending_orders,
                SUM(CASE WHEN status = 'delivered' THEN 1 ELSE 0 END) as delivered_orders,
                SUM(total_amount) as total_revenue,
                SUM(CASE WHEN status = 'paid' THEN total_amount ELSE 0 END) as paid_revenue
            FROM orders
        """
        return self.db.fetch_one(query) or {}
    
    def update_status(self, order_id: int, status: str) -> bool:
        query = f"UPDATE orders SET status = {self.db.dialect.placeholder()} WHERE id = {self.db.dialect.placeholder()}"
        self.db.execute(query, (status, order_id))
        return True
    
    def mark_as_paid(self, order_id: int, payment_id: str = None) -> bool:
        query = f"""
            UPDATE orders 
            SET status = 'paid', paid_at = {self.db.dialect.current_timestamp()}, 
                payment_id = {self.db.dialect.placeholder()}
            WHERE id = {self.db.dialect.placeholder()}
        """
        self.db.execute(query, (payment_id, order_id))
        return True
    
    def mark_as_shipped(self, order_id: int) -> bool:
        query = f"""
            UPDATE orders 
            SET status = 'shipped', shipped_at = {self.db.dialect.current_timestamp()} 
            WHERE id = {self.db.dialect.placeholder()}
        """
        self.db.execute(query, (order_id,))
        return True
    
    def generate_order_number(self) -> str:
        """Generera unikt ordernummer: RET-YYYYMMDD-XXX"""
        today = datetime.now().strftime("%Y%m%d")
        
        # Räkna dagens ordrar - använd databasspecifik datumfunktion
        if self.db.database_url:
            # PostgreSQL
            query = """
                SELECT COUNT(*) as count FROM orders 
                WHERE DATE(created_at) = CURRENT_DATE
            """
        else:
            # SQLite
            query = "SELECT COUNT(*) as count FROM orders WHERE date(created_at) = date('now')"
        
        row = self.db.fetch_one(query)
        count = (row.get('count', 0) if row else 0) + 1
        
        return f"RET-{today}-{count:03d}"


# ============================================================================
# Unit of Work
# ============================================================================

class UnitOfWork:
    def __init__(self, db: DatabaseConnection):
        self.db = db
        self.conn = None
    
    def __enter__(self):
        # Skapa en ny connection för transaktionen
        if self.db.database_url:
            import psycopg2
            from urllib.parse import urlparse
            url = urlparse(self.db.database_url)
            self.conn = psycopg2.connect(
                host=url.hostname,
                port=url.port,
                user=url.username,
                password=url.password,
                dbname=url.path[1:]
            )
            self.conn.cursor_factory = psycopg2.extras.RealDictCursor
        else:
            import sqlite3
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
    
    def execute(self, query: str, params: Tuple = ()):
        cur = self.conn.cursor()
        
        # PostgreSQL använder %s istället för ?
        if self.db.database_url:
            query = query.replace("?", "%s")
            # Ersätt även datumfunktioner
            query = query.replace("datetime('now')", "CURRENT_TIMESTAMP")
            query = query.replace("date('now')", "CURRENT_DATE")
        
        adapted_query = self._adapt_query(query)
        cur.execute(adapted_query, params)

        
        # Hantera lastrowid olika för PostgreSQL vs SQLite
        if self.db.database_url:
            # För PostgreSQL, försök hämta RETURNING
            if 'RETURNING' in query.upper():
                row = cur.fetchone()
                return row[0] if row else None
            return None
        else:
            # SQLite använder lastrowid
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
            
            # 🔴 VIKTIGT: Kontrollera om email redan finns innan vi skapar
            check_query = "SELECT id FROM users WHERE email_hash = %s AND is_active = TRUE" if self.db.database_url else "SELECT id FROM users WHERE email_hash = ? AND is_active = TRUE"
            cur.execute(check_query, (email_hash,))

            if cur.fetchone():
                raise ValueError("Det finns redan ett konto med denna emailadress.")
            
            # Använd rätt syntax för respektive databas
            if self.db.database_url:
                # PostgreSQL
                cur.execute("""
                    INSERT INTO users (name, email, email_hash, password, created_at, is_active)
                    VALUES (%s, %s, %s, %s, CURRENT_TIMESTAMP, TRUE)
                    RETURNING id
                """, (name, encrypted_email, email_hash, password_hash))
                user_id = cur.fetchone()['id']
            else:
                # SQLite
                cur.execute("""
                    INSERT INTO users (name, email, email_hash, password, created_at, is_active)
                    VALUES (?, ?, ?, ?, CURRENT_TIMESTAMP, 1)
                """, (name, encrypted_email, email_hash, password_hash))
                user_id = cur.lastrowid
            
            qr_id = None
            for attempt in range(max_attempts):
                candidate = qr_generator()
                
                try:
                    if self.db.database_url:
                        # PostgreSQL
                        cur.execute("""
                            INSERT INTO qr_codes (qr_id, user_id, is_active, is_enabled, activated_at, created_at)
                            VALUES (%s, %s, TRUE, TRUE, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
                        """, (candidate, user_id))
                    else:
                        # SQLite
                        cur.execute("""
                            INSERT INTO qr_codes (qr_id, user_id, is_active, is_enabled, activated_at, created_at)
                            VALUES (?, ?, 1, 1, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
                        """, (candidate, user_id))
                    qr_id = candidate
                    break
                except (sqlite3.IntegrityError, psycopg2.IntegrityError):
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


class PremiumService:
    LAUNCH_DATE = datetime(2026, 2, 1)
    LAUNCH_OFFER_END = datetime(2027, 3, 1)
    REGULAR_PRICE = 39.0
    
    def __init__(
        self,
        db: DatabaseConnection,
        user_repo: UserRepository,
        sub_repo: PremiumSubscriptionRepository
    ):
        self.db = db
        self.users = user_repo
        self.subs = sub_repo
    
    def is_launch_period(self) -> bool:
        return datetime.now() < self.LAUNCH_OFFER_END
    
    def can_get_free_premium(self, user_id: int) -> bool:
        if not self.is_launch_period():
            return False
        
        user = self.users.get_by_id(user_id)
        if not user:
            return False
        
        if user.created_at and user.created_at > self.LAUNCH_OFFER_END:
            return False
        
        if user.is_premium:
            return False
        
        return True
    
    def activate_premium(
        self, 
        user_id: int, 
        payment_method: str = "free",
        payment_id: Optional[str] = None,
        amount: Optional[float] = None,
        is_launch_offer: bool = False
    ) -> PremiumSubscription:
        if is_launch_offer:
            expires_at = self.LAUNCH_OFFER_END
            amount = 0.0
        else:
            expires_at = datetime.now().replace(year=datetime.now().year + 1)
            amount = amount or self.REGULAR_PRICE
        
        subscription = PremiumSubscription(
            user_id=user_id,
            status='active',
            expires_at=expires_at,
            payment_method=payment_method,
            payment_id=payment_id,
            amount_paid=amount,
            is_launch_offer=is_launch_offer
        )
        
        sub_id = self.subs.create(subscription)
        subscription.id = sub_id
        
        self.users.activate_premium(user_id, expires_at)
        
        logger.info(f"Premium aktiverat för användare {user_id}, expires: {expires_at}")
        return subscription
    
    def activate_free_launch_premium(self, user_id: int) -> Optional[PremiumSubscription]:
        if not self.can_get_free_premium(user_id):
            logger.warning(f"Användare {user_id} kan inte få gratis premium")
            return None
        
        return self.activate_premium(
            user_id=user_id,
            payment_method="free",
            is_launch_offer=True
        )
    
    def check_and_update_expired_subscriptions(self) -> int:
        """Kontrollera och uppdatera utgångna prenumerationer. Returnerar antal uppdaterade."""
        # Använd databasspecifik tidsjämförelse
        if self.db.database_url:
            query = """
                SELECT id, user_id, expires_at FROM premium_subscriptions
                WHERE status = 'active' 
                AND expires_at IS NOT NULL 
                AND expires_at < CURRENT_TIMESTAMP
            """
        else:
            query = """
                SELECT id, user_id, expires_at FROM premium_subscriptions
                WHERE status = 'active' 
                AND expires_at IS NOT NULL 
                AND expires_at < datetime('now')
            """
        
        with self.db.get_connection() as conn:
            cur = conn.cursor()
            cur.execute(query)
            rows = cur.fetchall()
            
            count = 0
            for row in rows:
                # Hantera både dict och tuple format
                if isinstance(row, dict):
                    sub_id = row.get('id')
                    user_id = row.get('user_id')
                    expires_at = row.get('expires_at')
                else:
                    sub_id = row[0]
                    user_id = row[1]
                    expires_at = row[2]
                
                # Uppdatera prenumeration till expired
                self.subs.update_status(sub_id, 'expired')
                
                # Kolla om användaren har andra aktiva prenumerationer
                active_subs = self.subs.get_by_user(user_id, active_only=True)
                
                if not active_subs:
                    # 🔴 VIKTIGT: Deaktivera även i users-tabellen!
                    self.users.deactivate_premium(user_id)
                    logger.info(f"Premium deaktiverat för användare {user_id} (prenumeration {sub_id} utgången)")
                else:
                    # Uppdatera till senaste aktiva prenumerationens expiry
                    latest = active_subs[0]
                    self.users.activate_premium(user_id, latest.expires_at)
                    logger.info(f"Premium uppdaterat för användare {user_id} till nytt expiry: {latest.expires_at}")
                
                count += 1
            
            if count > 0:
                logger.info(f"Uppdaterade {count} utgångna prenumerationer")
            
            return count
    
    def get_user_subscription_status(self, user_id: int) -> Dict:
        """Hämta fullständig prenumerationsstatus för en användare."""
        
        # 🔴 VIKTIGT: Uppdatera utgångna prenumerationer först (alltid!)
        self.check_and_update_expired_subscriptions()
        
        # Hämta färsk användardata efter potentiell uppdatering
        user = self.users.get_by_id(user_id)
        if not user:
            return {'has_premium': False, 'error': 'User not found'}
        
        # Använd databasspecifik tidsjämförelse
        if self.db.database_url:
            query = """
                SELECT * FROM premium_subscriptions 
                WHERE user_id = %s 
                AND (status = 'active' OR status = 'cancelled')
                AND (expires_at IS NULL OR expires_at > CURRENT_TIMESTAMP)
                ORDER BY created_at DESC
                LIMIT 1
            """
        else:
            query = """
                SELECT * FROM premium_subscriptions 
                WHERE user_id = ? 
                AND (status = 'active' OR status = 'cancelled')
                AND (expires_at IS NULL OR expires_at > datetime('now'))
                ORDER BY created_at DESC
                LIMIT 1
            """
        row = self.db.fetch_one(query, (user_id,))
        
        active_sub = None
        if row:
            active_sub = PremiumSubscription(
                id=row.get('id'),
                user_id=row.get('user_id', 0),
                status=row.get('status', 'active'),
                started_at=row.get('started_at'),
                expires_at=row.get('expires_at'),
                payment_method=row.get('payment_method'),
                payment_id=row.get('payment_id'),
                amount_paid=row.get('amount_paid'),
                currency=row.get('currency', 'SEK'),
                is_launch_offer=bool(row.get('is_launch_offer', 0)),
                created_at=row.get('created_at')
            )
        
        return {
            'has_premium': user.has_active_premium(),
            'is_premium': user.is_premium,
            'premium_until': user.premium_until,
            'premium_started_at': user.premium_started_at,
            'active_subscription': active_sub.to_dict() if active_sub else None,
            'is_launch_period': self.is_launch_period(),
            'can_get_free_premium': self.can_get_free_premium(user_id),
            'regular_price': self.REGULAR_PRICE
        }


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
            return_rate=return_rate,
            premium_users=self.users.get_premium_count()
        )
    
    def _get_new_users_this_week(self) -> int:
        """FIXAD för PostgreSQL - använd databasspecifik datumfunktion."""
        date_expr = self.db.dialect.now_minus_days(7)
        query = f"""
            SELECT COUNT(*) as count FROM users 
            WHERE created_at > {date_expr} AND is_active = {self.db.dialect.boolean(True)}
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
        self.dialect = db.dialect
    
    def init_tables(self) -> None:
        schema = self._get_schema()
        
        with self.db.get_connection() as conn:
            cur = conn.cursor()
            
            for table_sql in schema:
                cur.execute(table_sql)
            
            self._migrate_last_login(cur)
            self._migrate_soft_delete(cur)
            self._migrate_email_encryption(cur)
            self._migrate_premium_columns(cur)
            self._create_indexes(cur)
            self._create_unique_email_constraint(cur)
            self._migrate_orders_table(cur)
            self._migrate_qr_enabled(cur)
            
            logger.info("Database initialized")
    
    def _get_schema(self) -> List[str]:
        # Använd dialect för auto_increment
        serial = self.dialect.auto_increment()
        
        return [
            f"""
            CREATE TABLE IF NOT EXISTS users (
                id {serial} PRIMARY KEY,
                name TEXT NOT NULL,
                email TEXT NOT NULL,
                email_hash TEXT,
                password TEXT NOT NULL,
                reset_token TEXT,
                member_since TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                total_returns INTEGER DEFAULT 0,
                is_premium BOOLEAN DEFAULT FALSE,
                premium_until TIMESTAMP,
                premium_started_at TIMESTAMP,
                last_login TIMESTAMP,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                is_active BOOLEAN DEFAULT TRUE,
                deleted_at TIMESTAMP
            )
            """,
            f"""
            CREATE TABLE IF NOT EXISTS premium_subscriptions (
                id {serial} PRIMARY KEY,
                user_id INTEGER NOT NULL,
                status TEXT DEFAULT 'active',
                started_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                expires_at TIMESTAMP,
                payment_method TEXT,
                payment_id TEXT,
                amount_paid REAL,
                currency TEXT DEFAULT 'SEK',
                is_launch_offer BOOLEAN DEFAULT FALSE,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users(id)
            )
            """,
            f"""
            CREATE TABLE IF NOT EXISTS qr_codes (
                qr_id TEXT PRIMARY KEY,
                user_id INTEGER,
                is_active BOOLEAN DEFAULT FALSE,
                is_enabled BOOLEAN DEFAULT TRUE,
                activated_at TIMESTAMP,
                total_scans INTEGER DEFAULT 0,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users(id)
            )
            """,
            f"""
            CREATE TABLE IF NOT EXISTS handovers (
                id {serial} PRIMARY KEY,
                qr_id TEXT,
                finder_name TEXT,
                finder_user_id INTEGER,
                action TEXT NOT NULL,
                note TEXT,
                photo_path TEXT,
                latitude REAL,
                longitude REAL,
                confirmed BOOLEAN DEFAULT FALSE,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (qr_id) REFERENCES qr_codes(qr_id),
                FOREIGN KEY (finder_user_id) REFERENCES users(id)
            )
            """,
            f"""
            CREATE TABLE IF NOT EXISTS missing_discs (
                id {serial} PRIMARY KEY,
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
            f"""
            CREATE TABLE IF NOT EXISTS clubs (
                id {serial} PRIMARY KEY,
                name TEXT NOT NULL,
                email TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL,
                logo_url TEXT,
                member_count INTEGER DEFAULT 0,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
            """,
            f"""
            CREATE TABLE IF NOT EXISTS orders (
                id {serial} PRIMARY KEY,
                order_number TEXT UNIQUE NOT NULL,
                user_id INTEGER NOT NULL,
                qr_id TEXT,
                package_type TEXT NOT NULL,
                quantity INTEGER NOT NULL,
                total_amount REAL NOT NULL,
                currency TEXT DEFAULT 'SEK',
                status TEXT DEFAULT 'pending',
                payment_method TEXT,
                payment_id TEXT,
                shipping_name TEXT,
                shipping_address TEXT,
                shipping_postal_code TEXT,
                shipping_city TEXT,
                shipping_country TEXT DEFAULT 'SE',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                paid_at TIMESTAMP,
                shipped_at TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users(id),
                FOREIGN KEY (qr_id) REFERENCES qr_codes(qr_id)
            )
            """
        ]
    
    def _migrate_last_login(self, cursor) -> None:
        try:
            if self.db.database_url:
                cursor.execute("SELECT last_login FROM users LIMIT 1")
            else:
                cursor.execute("SELECT last_login FROM users LIMIT 1")
        except (sqlite3.OperationalError, psycopg2.Error) as e:
            if self.db.database_url:
                cursor.execute("ALTER TABLE users ADD COLUMN last_login TIMESTAMP")
            else:
                cursor.execute("ALTER TABLE users ADD COLUMN last_login TIMESTAMP")
            logger.info("La till kolumnen last_login")
    
    def _migrate_soft_delete(self, cursor) -> None:
        try:
            cursor.execute("SELECT is_active FROM users LIMIT 1")
        except (sqlite3.OperationalError, psycopg2.Error):
            if self.db.database_url:
                cursor.execute("ALTER TABLE users ADD COLUMN is_active BOOLEAN DEFAULT TRUE")
                cursor.execute("ALTER TABLE users ADD COLUMN deleted_at TIMESTAMP")
            else:
                cursor.execute("ALTER TABLE users ADD COLUMN is_active BOOLEAN DEFAULT TRUE")
                cursor.execute("ALTER TABLE users ADD COLUMN deleted_at TIMESTAMP")
            logger.info("La till soft delete kolumner")
    
    def _migrate_email_encryption(self, cursor) -> None:
        try:
            cursor.execute("SELECT email_hash FROM users LIMIT 1")
        except (sqlite3.OperationalError, psycopg2.Error):
            if self.db.database_url:
                cursor.execute("ALTER TABLE users ADD COLUMN email_hash TEXT")
            else:
                cursor.execute("ALTER TABLE users ADD COLUMN email_hash TEXT")
            logger.info("La till email_hash kolumn")
            
            # Uppdatera befintliga rader
            if self.db.database_url:
                cursor.execute("SELECT id, email FROM users WHERE email_hash IS NULL OR email_hash = ''")
            else:
                cursor.execute("SELECT id, email FROM users WHERE email_hash IS NULL OR email_hash = ''")
            rows = cursor.fetchall()
            for row in rows:
                email_hash = encryption.hash_email(row['email'])
                cursor.execute(
                    "UPDATE users SET email_hash = %s WHERE id = %s" if self.db.database_url else "UPDATE users SET email_hash = ? WHERE id = ?",
                    (email_hash, row['id'])
                )
            logger.info(f"Indexerade {len(rows)} befintliga användare")
    
    def _migrate_premium_columns(self, cursor) -> None:
        migrations = [
            ("is_premium", "BOOLEAN DEFAULT FALSE"),
            ("premium_until", "TIMESTAMP"),
            ("premium_started_at", "TIMESTAMP")
        ]
        
        for column, data_type in migrations:
            try:
                cursor.execute(f"SELECT {column} FROM users LIMIT 1")
            except (sqlite3.OperationalError, psycopg2.Error):
                cursor.execute(f"ALTER TABLE users ADD COLUMN {column} {data_type}")
                logger.info(f"La till kolumnen {column}")
        
        try:
            cursor.execute("SELECT id FROM premium_subscriptions LIMIT 1")
        except (sqlite3.OperationalError, psycopg2.Error):
            serial = self.dialect.auto_increment()
            cursor.execute(f"""
                CREATE TABLE premium_subscriptions (
                    id {serial} PRIMARY KEY,
                    user_id INTEGER NOT NULL,
                    status TEXT DEFAULT 'active',
                    started_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    expires_at TIMESTAMP,
                    payment_method TEXT,
                    payment_id TEXT,
                    amount_paid REAL,
                    currency TEXT DEFAULT 'SEK',
                    is_launch_offer BOOLEAN DEFAULT FALSE,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (user_id) REFERENCES users(id)
                )
            """)
            logger.info("Skapade premium_subscriptions tabell")
    
    def _create_indexes(self, cursor) -> None:
        indexes = [
            ("idx_qr_user", "qr_codes(user_id)"),
            ("idx_handovers_qr", "handovers(qr_id)"),
            ("idx_users_email", "users(email)"),
            ("idx_users_email_hash", "users(email_hash)"),
            ("idx_users_active", "users(is_active)"),
            ("idx_missing_user", "missing_discs(user_id)"),
            ("idx_missing_status", "missing_discs(status)"),
            ("idx_missing_location", "missing_discs(latitude, longitude)"),
            ("idx_premium_user", "premium_subscriptions(user_id)"),
            ("idx_premium_status", "premium_subscriptions(status)"),
            ("idx_premium_expires", "premium_subscriptions(expires_at)"),
            ("idx_orders_user", "orders(user_id)"),
            ("idx_orders_status", "orders(status)"),
            ("idx_orders_number", "orders(order_number)"),
            ("idx_orders_created", "orders(created_at)"),
        ]
        
        for name, columns in indexes:
            try:
                cursor.execute(f"CREATE INDEX IF NOT EXISTS {name} ON {columns}")
            except Exception as e:
                logger.warning(f"Kunde inte skapa index {name}: {e}")
    
    def _create_unique_email_constraint(self, cursor) -> None:
        """Skapa unique constraint på email_hash för att förhindra dubletter"""
        try:
            # Ta bort befintliga dubletter (behåll den äldsta)
            if self.db.database_url:
                # PostgreSQL syntax
                cursor.execute("""
                    DELETE FROM users 
                    WHERE id NOT IN (
                        SELECT MIN(id) 
                        FROM users 
                        WHERE is_active = TRUE
                        GROUP BY email_hash
                    )
                    AND is_active = TRUE
                    AND email_hash IS NOT NULL
                    AND email_hash != ''
                """)
            else:
                # SQLite syntax
                cursor.execute("""
                    DELETE FROM users 
                    WHERE id NOT IN (
                        SELECT MIN(id) 
                        FROM users 
                        WHERE is_active = TRUE
                        GROUP BY email_hash
                    )
                    AND is_active = TRUE
                    AND email_hash IS NOT NULL
                    AND email_hash != ''
                """)
            deleted = cursor.rowcount
            if deleted > 0:
                logger.warning(f"Tog bort {deleted} dubletter av användare")
            
            # Skapa unique index på email_hash
            cursor.execute("""
                CREATE UNIQUE INDEX IF NOT EXISTS idx_users_email_hash_unique 
                ON users(email_hash) 
                WHERE is_active = TRUE
            """)
            logger.info("Skapade unique index på email_hash")
            
        except (sqlite3.OperationalError, psycopg2.Error) as e:
            logger.warning(f"Kunde inte skapa unique constraint: {e}")
    
    def _migrate_orders_table(self, cursor) -> None:
        """Skapa orders-tabell om den saknas (för befintliga databaser)"""
        try:
            cursor.execute("SELECT id FROM orders LIMIT 1")
        except (sqlite3.OperationalError, psycopg2.Error):
            serial = self.dialect.auto_increment()
            cursor.execute(f"""
                CREATE TABLE orders (
                    id {serial} PRIMARY KEY,
                    order_number TEXT UNIQUE NOT NULL,
                    user_id INTEGER NOT NULL,
                    qr_id TEXT,
                    package_type TEXT NOT NULL,
                    quantity INTEGER NOT NULL,
                    total_amount REAL NOT NULL,
                    currency TEXT DEFAULT 'SEK',
                    status TEXT DEFAULT 'pending',
                    payment_method TEXT,
                    payment_id TEXT,
                    shipping_name TEXT,
                    shipping_address TEXT,
                    shipping_postal_code TEXT,
                    shipping_city TEXT,
                    shipping_country TEXT DEFAULT 'SE',
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    paid_at TIMESTAMP,
                    shipped_at TIMESTAMP,
                    FOREIGN KEY (user_id) REFERENCES users(id),
                    FOREIGN KEY (qr_id) REFERENCES qr_codes(qr_id)
                )
            """)
            logger.info("Skapade orders-tabell")
            
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_orders_user ON orders(user_id)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_orders_status ON orders(status)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_orders_number ON orders(order_number)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_orders_created ON orders(created_at)")
            logger.info("Skapade index för orders-tabell")

    def _migrate_qr_enabled(self, cursor) -> None:
        """Migrera is_enabled kolumn för befintliga QR-koder."""
        try:
            cursor.execute("SELECT is_enabled FROM qr_codes LIMIT 1")
        except (sqlite3.OperationalError, psycopg2.Error):
            if self.db.database_url:
                cursor.execute("ALTER TABLE qr_codes ADD COLUMN is_enabled BOOLEAN DEFAULT TRUE")
            else:
                cursor.execute("ALTER TABLE qr_codes ADD COLUMN is_enabled BOOLEAN DEFAULT TRUE")
            logger.info("La till is_enabled kolumn i qr_codes")


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
        self._premium_subs = PremiumSubscriptionRepository(self._db)
        self._orders = OrderRepository(self._db)
    
    def _init_services(self) -> None:
        self._user_service = UserService(self._db, self._users, self._qrs)
        self._premium_service = PremiumService(self._db, self._users, self._premium_subs)
        self._matching = MatchingService(self._missing)
        self._admin = AdminService(
            self._db, self._users, self._qrs, self._handovers, self._missing
        )
        self._manager = DatabaseManager(self._db)
    
    def init_tables(self) -> None:
        self._manager.init_tables()
    
    def reset_database(self, confirm: bool = False) -> bool:
        return self._admin.reset_database(confirm)
    
    # User methods
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
    
    # Premium methods
    def activate_premium(self, user_id: int, payment_method: str = "free", 
                       payment_id: Optional[str] = None, 
                       amount: Optional[float] = None) -> Dict:
        sub = self._premium_service.activate_premium(
            user_id, payment_method, payment_id, amount, 
            is_launch_offer=False
        )
        return sub.to_dict() if sub else {}
    
    def activate_free_launch_premium(self, user_id: int) -> Optional[Dict]:
        sub = self._premium_service.activate_free_launch_premium(user_id)
        return sub.to_dict() if sub else None
    
    def get_user_subscription_status(self, user_id: int) -> Dict:
        """Hämta fullständig prenumerationsstatus för en användare."""
        # 🔴 VIKTIGT: Kolla utgångna prenumerationer först
        self.check_expired_subscriptions()
        
        return self._premium_service.get_user_subscription_status(user_id)
    
    def check_expired_subscriptions(self) -> int:
        return self._premium_service.check_and_update_expired_subscriptions()
    
    def is_launch_period(self) -> bool:
        return self._premium_service.is_launch_period()
    
    def can_get_free_premium(self, user_id: int) -> bool:
        return self._premium_service.can_get_free_premium(user_id)
    
    # QR methods
    def create_qr(self, qr_id: str) -> bool:
        return self._qrs.create(qr_id)
    
    def get_qr(self, qr_id: str) -> Optional[Dict]:
        qr = self._qrs.get_by_id(qr_id)
        return qr.to_dict() if qr else None
    
    def activate_qr(self, qr_id: str, user_id: int) -> None:
        self._qrs.activate(qr_id, user_id)
    
    def get_user_qr(self, user_id: int) -> Optional[Dict]:
        qrs = self._qrs.get_by_user(user_id)
        return qrs[0].to_dict() if qrs else None
    
    def get_user_qr_codes(self, user_id: int) -> List[Dict]:
        qrs = self._qrs.get_by_user(user_id)
        return [qr.to_dict() for qr in qrs]
    
    def assign_qr_to_user(self, qr_id: str, user_id: int) -> bool:
        return self._qrs.assign_to_user(qr_id, user_id)
    
    def toggle_qr_enabled(self, qr_id: str, user_id: int, enabled: bool) -> bool:
        return self._qrs.toggle_enabled(qr_id, user_id, enabled)
    
    def increment_qr_scans(self, qr_id: str) -> None:
        self._qrs.increment_scans(qr_id)
    
    # Handover methods
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
    
    # Missing disc methods
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
        
    def get_missing_disc_by_id(self, disc_id: int) -> Optional[Dict]:
        """Hämta en specifik missing disc med ID."""
        disc = self._missing.get_by_id(disc_id)
        return disc.to_dict() if disc else None        
    
    def delete_missing_disc(self, disc_id: int, user_id: int) -> bool:
        return self._missing.delete(disc_id, user_id)
    
    # Stats methods
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
            'missing_discs': admin_stats.missing_discs,
            'premium_users': admin_stats.premium_users
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
            'return_rate': stats.return_rate,
            'premium_users': stats.premium_users
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

    # Order methods
    def create_order(self, order_data: Dict) -> Dict:
        order = Order(
            order_number=self._orders.generate_order_number(),
            user_id=order_data['user_id'],
            qr_id=order_data.get('qr_id'),
            package_type=order_data['package_type'],
            quantity=order_data['quantity'],
            total_amount=order_data['total_amount'],
            currency=order_data.get('currency', 'SEK'),
            status=order_data.get('status', 'pending'),
            payment_method=order_data.get('payment_method', ''),
            payment_id=order_data.get('payment_id'),
            shipping_name=order_data.get('shipping_name', ''),
            shipping_address=order_data.get('shipping_address', ''),
            shipping_postal_code=order_data.get('shipping_postal_code', ''),
            shipping_city=order_data.get('shipping_city', ''),
            shipping_country=order_data.get('shipping_country', 'SE')
        )
        
        order_id = self._orders.create(order)
        order.id = order_id
        
        return order.to_dict()
    
    def get_all_orders_with_user_info(self, status: str = None) -> List[Dict]:
        return self._orders.get_all_with_user_info(status)
    
    def get_order_by_id(self, order_id: int) -> Optional[Dict]:
        order = self._orders.get_by_id(order_id)
        return order.to_dict() if order else None
    
    def get_order_by_number(self, order_number: str) -> Optional[Dict]:
        order = self._orders.get_by_order_number(order_number)
        return order.to_dict() if order else None
    
    def get_order_stats(self) -> Dict:
        return self._orders.get_order_stats()
    
    def update_order_status(self, order_id: int, status: str) -> bool:
        return self._orders.update_status(order_id, status)
    
    def mark_order_as_paid(self, order_id: int, payment_id: str = None) -> bool:
        return self._orders.mark_as_paid(order_id, payment_id)
    
    def mark_order_as_shipped(self, order_id: int) -> bool:
        return self._orders.mark_as_shipped(order_id)

    # Admin methods for QR management
    def update_qr_id(self, old_qr_id: str, new_qr_id: str) -> bool:
        import os
        from utils import create_qr_code
        
        if not new_qr_id or len(new_qr_id) < 3:
            raise ValueError("QR-ID måste vara minst 3 tecken")
        
        if not new_qr_id.isalnum():
            raise ValueError("QR-ID får endast innehålla bokstäver och siffror")
        
        new_qr_id = new_qr_id.upper()
        
        existing = self.get_qr(new_qr_id)
        if existing:
            raise ValueError(f"QR-ID {new_qr_id} finns redan")
        
        old_qr = self.get_qr(old_qr_id)
        if not old_qr:
            raise ValueError(f"QR-ID {old_qr_id} hittades inte")
        
        user_id = old_qr.get('user_id')
        
        with self._db.get_connection() as conn:
            cur = conn.cursor()
            
            cur.execute(f"""
                UPDATE qr_codes 
                SET qr_id = {self._db.dialect.placeholder()} 
                WHERE qr_id = {self._db.dialect.placeholder()}
            """, (new_qr_id, old_qr_id))
            
            cur.execute(f"""
                UPDATE handovers 
                SET qr_id = {self._db.dialect.placeholder()} 
                WHERE qr_id = {self._db.dialect.placeholder()}
            """, (new_qr_id, old_qr_id))
        
        try:
            create_qr_code(new_qr_id, user_id)
        except Exception as e:
            logger.error(f"Kunde inte skapa ny QR-bild: {e}")
        
        qr_folder = os.environ.get('QR_FOLDER', 'static/qr')
        old_filepath = os.path.join(qr_folder, f"qr_{old_qr_id}.png")
        if os.path.exists(old_filepath):
            try:
                os.remove(old_filepath)
            except Exception as e:
                logger.warning(f"Kunde inte ta bort gammal QR-bild: {e}")
        
        logger.info(f"QR-ID ändrat från {old_qr_id} till {new_qr_id}")
        return True
    
    def toggle_user_premium(self, user_id: int, is_premium: bool) -> bool:
        query = f"""
            UPDATE users 
            SET is_premium = {self._db.dialect.boolean(is_premium)} 
            WHERE id = {self._db.dialect.placeholder()} AND is_active = {self._db.dialect.boolean(True)}
        """
        self._db.execute(query, (user_id,))
        logger.info(f"Användare {user_id} premium satt till {is_premium}")
        return True
    
    def get_user_payment_info(self, user_id: int) -> Optional[Dict]:
        # Använd databasspecifik datumformatering
        if self._db.database_url:
            query = """
                SELECT 
                    u.id, u.name, u.email, u.is_premium, u.created_at,
                    'ORD-' || TO_CHAR(u.created_at, 'YYYY-MM-DD') || '-' || u.id as order_id
                FROM users u
                WHERE u.id = %s AND u.is_active = TRUE
            """
        else:
            query = """
                SELECT 
                    u.id, u.name, u.email, u.is_premium, u.created_at,
                    'ORD-' || strftime('%Y-%m-%d', u.created_at) || '-' || u.id as order_id
                FROM users u
                WHERE u.id = ? AND u.is_active = TRUE
            """
        row = self._db.fetch_one(query, (user_id,))
        return row
    
    def register_user_on_qr(self, qr_id: str, name: str, email: str, password: str) -> int:
        from werkzeug.security import generate_password_hash
        
        qr = self.get_qr(qr_id)
        if not qr:
            raise ValueError(f"QR-kod {qr_id} hittades inte")
        
        if qr.get('user_id'):
            raise ValueError(f"QR-kod {qr_id} är redan tilldelad användare {qr['user_id']}")
        
        existing = self.get_user_by_email(email.lower().strip())
        if existing:
            raise ValueError("Det finns redan ett konto med denna emailadress.")
        
        password_hash = generate_password_hash(password)
        
        with self._db.get_connection() as conn:
            cur = conn.cursor()
            
            encrypted_email = encryption.encrypt(email)
            email_hash = encryption.hash_email(email)
            
            if self._db.database_url:
                # PostgreSQL
                cur.execute("""
                    INSERT INTO users (name, email, email_hash, password, created_at, is_active)
                    VALUES (%s, %s, %s, %s, CURRENT_TIMESTAMP, TRUE)
                    RETURNING id
                """, (name, encrypted_email, email_hash, password_hash))
                row = cur.fetchone()
                user_id = row['id'] if row else None
            else:
                # SQLite
                cur.execute("""
                    INSERT INTO users (name, email, email_hash, password, created_at, is_active)
                    VALUES (?, ?, ?, ?, CURRENT_TIMESTAMP, 1)
                """, (name, encrypted_email, email_hash, password_hash))
                user_id = cur.lastrowid
            
            cur.execute(f"""
                UPDATE qr_codes 
                SET user_id = {self._db.dialect.placeholder()}, 
                    is_active = {self._db.dialect.boolean(True)}, 
                    is_enabled = {self._db.dialect.boolean(True)}, 
                    activated_at = {self._db.dialect.current_timestamp()}
                WHERE qr_id = {self._db.dialect.placeholder()}
            """, (user_id, qr_id))
            
            conn.commit()
        
        logger.info(f"Ny användare {user_id} registrerad på QR {qr_id}")
        return user_id
    
    def get_qr_with_payment_info(self, qr_id: str) -> Optional[Dict]:
        # Använd databasspecifik datumformatering
        if self._db.database_url:
            query = """
                SELECT 
                    q.qr_id, q.is_active, q.is_enabled, q.activated_at, q.total_scans, q.created_at,
                    u.id as user_id, u.name, u.email, u.is_premium, u.created_at as user_created_at,
                    'ORD-' || TO_CHAR(u.created_at, 'YYYY-MM-DD') || '-' || u.id as order_id
                FROM qr_codes q
                LEFT JOIN users u ON q.user_id = u.id
                WHERE q.qr_id = %s
            """
        else:
            query = """
                SELECT 
                    q.qr_id, q.is_active, q.is_enabled, q.activated_at, q.total_scans, q.created_at,
                    u.id as user_id, u.name, u.email, u.is_premium, u.created_at as user_created_at,
                    'ORD-' || strftime('%Y-%m-%d', u.created_at) || '-' || u.id as order_id
                FROM qr_codes q
                LEFT JOIN users u ON q.user_id = u.id
                WHERE q.qr_id = ?
            """
        row = self._db.fetch_one(query, (qr_id,))
        
        if row:
            email = row.get('email')
            if email and email.startswith('gAAAA'):
                row['email'] = encryption.decrypt(email)
        
        return row
        
    def update_user(self, user_id: int, name: str = None, email: str = None) -> bool:
        try:
            if name:
                query = f"UPDATE users SET name = {self._db.dialect.placeholder()} WHERE id = {self._db.dialect.placeholder()}"
                self._db.execute(query, (name, user_id))
            
            if email:
                encrypted_email = encryption.encrypt(email)
                email_hash = encryption.hash_email(email)
                query = f"""
                    UPDATE users 
                    SET email = {self._db.dialect.placeholder()}, 
                        email_hash = {self._db.dialect.placeholder()} 
                    WHERE id = {self._db.dialect.placeholder()}
                """
                self._db.execute(query, (encrypted_email, email_hash, user_id))
            
            logger.info(f"Användare {user_id} uppdaterad")
            return True
            
        except Exception as e:
            logger.error(f"Fel vid uppdatering av användare: {e}")
            raise


# Skapa global databasinstans
db = Database(DB_PATH)