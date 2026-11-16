import sqlite3
from werkzeug.security import generate_password_hash
from crypto_utils import Dissanayake

DB_NAME = "securevault.db"

def get_db():
    conn = sqlite3.connect(DB_NAME)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            pub_n TEXT NOT NULL,
            pub_e TEXT NOT NULL,
            priv_d TEXT NOT NULL
        )
    """)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS messages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            sender_id INTEGER NOT NULL,
            receiver_id INTEGER NOT NULL,
            ciphertext TEXT NOT NULL,
            salt TEXT NOT NULL,
            iv TEXT NOT NULL,
            signature TEXT NOT NULL,
            r_val TEXT NOT NULL,
            timestamp TEXT NOT NULL,
            FOREIGN KEY(sender_id) REFERENCES users(id),
            FOREIGN KEY(receiver_id) REFERENCES users(id)
        )
    """)
    
    for uname in ["cece", "kaka"]:
        cursor.execute("SELECT * FROM users WHERE username = ?", (uname,))
        if not cursor.fetchone():
            n, e, d = Dissanayake.keygen(256)
            cursor.execute("INSERT INTO users (username, password_hash, pub_n, pub_e, priv_d) VALUES (?, ?, ?, ?, ?)",
                           (uname, generate_password_hash("123456"), n, e, d))
    conn.commit()
    conn.close()
