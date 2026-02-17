BEGIN TRANSACTION;
CREATE TABLE clubs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                email TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL,
                logo_url TEXT,
                member_count INTEGER DEFAULT 0,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
CREATE TABLE handovers (
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
            );
INSERT INTO "handovers" VALUES(1,'26JVE',NULL,NULL,'gömde','Under skärmen','17713551072928387346168216718720_20260217_200540.jpg',55.976933,12.8488385,0,'2026-02-17 19:05:40');
INSERT INTO "handovers" VALUES(2,'26JVE',NULL,NULL,'gömde','Under skärmen x2','uploads/26JVE/17713555890823816339287240352834_20260217_201332.jpg',55.9769955,12.8489247,0,'2026-02-17 19:13:32');
INSERT INTO "handovers" VALUES(3,'26JVE',NULL,NULL,'gömde','Där','uploads/26JVE/17713561473945028821013437108473_20260217_202250.jpg',55.9769961,12.8489265,0,'2026-02-17 19:22:50');
INSERT INTO "handovers" VALUES(4,'26JVE',NULL,NULL,'gömde','Hu','uploads/17713566128822737761141632540528_20260217_203031.jpg',55.9769852,12.8489124,0,'2026-02-17 19:30:31');
INSERT INTO "handovers" VALUES(5,'26JVE',NULL,NULL,'gömde','Hu','uploads/17713572615498253731775766227483_20260217_204127.jpg',55.9769836,12.8489077,0,'2026-02-17 19:41:27');
INSERT INTO "handovers" VALUES(6,'26JVE',NULL,NULL,'gömde','Huuuuu','uploads/17713578326772577758240842455258_20260217_205051.jpg',55.9769973,12.8489232,0,'2026-02-17 19:50:51');
CREATE TABLE missing_discs (
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
            );
CREATE TABLE orders (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
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
            );
INSERT INTO "orders" VALUES(1,'RET-20260217-001',1,'26JVE','standard',24,99.0,'SEK','paid','stripe','pi_3T1uUSETfQUcG8ra0dQbgice','Robert Winterqvist','Fastmårupsvägen 262','253 42','Vallåkra','SE','2026-02-17 20:03:28',NULL,NULL);
INSERT INTO "orders" VALUES(2,'RET-20260217-002',1,'26JVE','standard',24,99.0,'SEK','paid','stripe','pi_3T1uUSETfQUcG8ra0dQbgice','Stripe Test','','','','SE','2026-02-17 20:07:41',NULL,NULL);
CREATE TABLE premium_subscriptions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                status TEXT DEFAULT 'active',
                started_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                expires_at TIMESTAMP,
                payment_method TEXT,
                payment_id TEXT,
                amount_paid REAL,
                currency TEXT DEFAULT 'SEK',
                is_launch_offer BOOLEAN DEFAULT 0,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users(id)
            );
INSERT INTO "premium_subscriptions" VALUES(1,1,'active','2026-02-17 20:08:38','2027-03-01T00:00:00','free',NULL,0.0,'SEK',1,'2026-02-17 20:08:38');
CREATE TABLE qr_codes (
                qr_id TEXT PRIMARY KEY,
                user_id INTEGER,
                is_active BOOLEAN DEFAULT 0,
                is_enabled BOOLEAN DEFAULT 1,
                activated_at TIMESTAMP,
                total_scans INTEGER DEFAULT 0,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users(id)
            );
INSERT INTO "qr_codes" VALUES('26JVE',1,1,1,'2026-02-17 19:04:33',20,'2026-02-17 19:04:33');
CREATE TABLE users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                email TEXT NOT NULL,
                email_hash TEXT,
                password TEXT NOT NULL,
                reset_token TEXT,
                member_since TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                total_returns INTEGER DEFAULT 0,
                is_premium BOOLEAN DEFAULT 0,
                premium_until TIMESTAMP,
                premium_started_at TIMESTAMP,
                last_login TIMESTAMP,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                is_active BOOLEAN DEFAULT 1,
                deleted_at TIMESTAMP
            );
INSERT INTO "users" VALUES(1,'Robert Winterqvist','gAAAAABplLvBa68JxxB1g7iBEDcoWt53iB6BcoHYCPc7gIrhWr2aGZ2Mj98bi-FosGwptDupmzw_DuOQ0AwlCkqqSbHDXfw0kVMxBc3SpvDifPb_i8DY0qs=','3031ab05bea2875388866078051c96532f4fdf6ac5bcfcd79ca1c01b29dc64c4','scrypt:32768:8:1$4D1cuQ38R5brrK6e$8ba2f77c2cd87f8358aa2c4a5b683f2de5e1c13c7f3070e38a8ca6c31b897bb7abf5dafb677e83649a6d20f7821c0cf7c07cb292b5a4e41fac57700225b269c8',NULL,'2026-02-17 19:04:33',0,1,'2027-03-01T00:00:00','2026-02-17 20:08:38',NULL,'2026-02-17 19:04:33',1,NULL);
CREATE INDEX idx_qr_user ON qr_codes(user_id);
CREATE INDEX idx_handovers_qr ON handovers(qr_id);
CREATE INDEX idx_users_email ON users(email);
CREATE INDEX idx_users_email_hash ON users(email_hash);
CREATE INDEX idx_users_active ON users(is_active);
CREATE INDEX idx_missing_user ON missing_discs(user_id);
CREATE INDEX idx_missing_status ON missing_discs(status);
CREATE INDEX idx_missing_location ON missing_discs(latitude, longitude);
CREATE INDEX idx_premium_user ON premium_subscriptions(user_id);
CREATE INDEX idx_premium_status ON premium_subscriptions(status);
CREATE INDEX idx_premium_expires ON premium_subscriptions(expires_at);
CREATE INDEX idx_orders_user ON orders(user_id);
CREATE INDEX idx_orders_status ON orders(status);
CREATE INDEX idx_orders_number ON orders(order_number);
CREATE INDEX idx_orders_created ON orders(created_at);
CREATE UNIQUE INDEX idx_users_email_hash_unique 
                ON users(email_hash) 
                WHERE is_active = 1
            ;
DELETE FROM "sqlite_sequence";
INSERT INTO "sqlite_sequence" VALUES('users',1);
INSERT INTO "sqlite_sequence" VALUES('handovers',6);
INSERT INTO "sqlite_sequence" VALUES('orders',2);
INSERT INTO "sqlite_sequence" VALUES('premium_subscriptions',1);
COMMIT;
