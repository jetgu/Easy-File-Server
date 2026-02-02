# database.py
import sqlite3
import bcrypt
import time
from config import DB_PATH

def init_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    
    # Users Table (Original)
    c.execute('''CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        email TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        is_admin INTEGER DEFAULT 0,
        created_at REAL,
        is_active INTEGER DEFAULT 1,
        info TEXT,
        quota INTEGER DEFAULT 5120  -- New: Quota in MB (Default 5GB)
    )''')
    
    # ... (Other tables: settings, shares) ...
    c.execute('''CREATE TABLE IF NOT EXISTS settings (key TEXT UNIQUE, value TEXT)''')
    c.execute('''CREATE TABLE IF NOT EXISTS shares (token TEXT PRIMARY KEY, user_id INTEGER, file_path TEXT, created_at REAL, expires_at REAL)''')
    
    # --- MIGRATIONS ---
    # Add is_active if missing
    try:
        c.execute("ALTER TABLE users ADD COLUMN is_active INTEGER DEFAULT 1")
    except sqlite3.OperationalError: pass
    
    # NEW: Add info column if missing
    try:
        c.execute("ALTER TABLE users ADD COLUMN info TEXT")
    except sqlite3.OperationalError: pass
    # ------------------
    try:
        # Default 5120 MB = 5 GB
        c.execute("ALTER TABLE users ADD COLUMN quota INTEGER DEFAULT 5120")
    except sqlite3.OperationalError:
        pass
        
    # Default Settings & Admin
    c.execute("INSERT OR IGNORE INTO settings (key, value) VALUES ('max_upload_size', '50')")
    c.execute("INSERT OR IGNORE INTO settings (key, value) VALUES ('download_speed_limit', '0')")
    
    # Default Admin
    hashed = bcrypt.hashpw(b"admin123", bcrypt.gensalt()).decode('utf-8')
    try:
        # Note: Added default quota 10240 (10GB) for admin
        c.execute("INSERT INTO users (email, password, is_admin, created_at, is_active, info, quota) VALUES (?, ?, ?, ?, ?, ?, ?)",
                  ("admin@example.com", hashed, 1, time.time(), 1, "System Admin", 10240))
    except sqlite3.IntegrityError:
        pass
        
    conn.commit()
    conn.close()

def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn