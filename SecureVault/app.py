import os
from datetime import datetime
from functools import wraps
from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify
from werkzeug.security import check_password_hash, generate_password_hash
from database import get_db, init_db
from crypto_utils import Dissanayake, encrypt_aes_gcm, decrypt_aes_gcm

app = Flask(__name__)
app.secret_key = os.urandom(24)

init_db()

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session: 
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username', '').strip().lower()
        password = request.form.get('password', '')
        conn = get_db()
        user = conn.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
        conn.close()
        
        if user and check_password_hash(user['password_hash'], password):
            session['user_id'] = user['id']
            session['username'] = user['username']
            flash(f"Selamat datang kembali, {user['username']}!", "success")
            return redirect(url_for('dashboard'))
        flash("Username atau password salah.", "danger")
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username', '').strip().lower()
        password = request.form.get('password', '')
        if not username or not password:
            flash("Username dan password wajib diisi.", "danger")
            return redirect(url_for('register'))
            
        conn = get_db()
        if conn.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone():
            conn.close()
            flash("Username sudah terdaftar.", "danger")
            return redirect(url_for('register'))
            
        n, e, d = Dissanayake.keygen(256)
        conn.execute("INSERT INTO users (username, password_hash, pub_n, pub_e, priv_d) VALUES (?, ?, ?, ?, ?)",
                     (username, generate_password_hash(password), n, e, d))
        conn.commit()
        conn.close()
        flash("Akun berhasil terdaftar! Silakan login.", "success")
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/logout')
def logout():
    session.clear()
    flash("Anda telah keluar dari akun.", "info")
    return redirect(url_for('login'))

@app.route('/')
@login_required
def dashboard():
    conn = get_db()
    current_user_id = session['user_id']
    user = conn.execute("SELECT * FROM users WHERE id = ?", (current_user_id,)).fetchone()
    users = conn.execute("SELECT id, username FROM users WHERE id != ?", (current_user_id,)).fetchall()
    
    inbox = conn.execute("""
        SELECT m.*, u.username as sender_name, u.pub_n as sender_n, u.pub_e as sender_e
        FROM messages m JOIN users u ON m.sender_id = u.id 
        WHERE m.receiver_id = ? ORDER BY m.id DESC
    """, (current_user_id,)).fetchall()
    
    outbox = conn.execute("""
        SELECT m.*, u.username as receiver_name 
        FROM messages m JOIN users u ON m.receiver_id = u.id 
        WHERE m.sender_id = ? ORDER BY m.id DESC
    """, (current_user_id,)).fetchall()
    
    conn.close()
    return render_template('dashboard.html', user=user, users=users, inbox=inbox, outbox=outbox)

@app.route('/send', methods=['POST'])
@login_required
def send_message():
    receiver_id = request.form.get('receiver_id')
    message = request.form.get('message')
    password = request.form.get('password')
    
    if not receiver_id or not message or not password:
        flash("Semua kolom pesan dan password wajib diisi.", "danger")
        return redirect(url_for('dashboard'))
        
    conn = get_db()
    sender = conn.execute("SELECT * FROM users WHERE id = ?", (session['user_id'],)).fetchone()
    
    signature, r_val = Dissanayake.sign(message, sender['priv_d'], sender['pub_n'])
    salt, iv, ciphertext = encrypt_aes_gcm(message, password)
    
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    conn.execute("""
        INSERT INTO messages (sender_id, receiver_id, ciphertext, salt, iv, signature, r_val, timestamp)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    """, (sender['id'], receiver_id, ciphertext, salt, iv, signature, r_val, timestamp))
    conn.commit()
    conn.close()
    
    flash("Pesan berhasil dienkripsi & dikirim!", "success")
    return redirect(url_for('dashboard'))

@app.route('/decrypt', methods=['POST'])
@login_required
def decrypt_message():
    data = request.get_json() or {}
    msg_id = data.get('msg_id')
    password = data.get('password')
    
    conn = get_db()
    msg = conn.execute("""
        SELECT m.*, u.username as sender_name, u.pub_n as sender_n, u.pub_e as sender_e
        FROM messages m JOIN users u ON m.sender_id = u.id 
        WHERE m.id = ? AND m.receiver_id = ?
    """, (msg_id, session['user_id'])).fetchone()
    conn.close()
    
    if not msg:
        return jsonify({"success": False, "error": "Pesan tidak ditemukan."})
        
    try:
        plaintext = decrypt_aes_gcm(msg['ciphertext'], password, msg['salt'], msg['iv'])
        is_valid_sig = Dissanayake.verify(plaintext, msg['signature'], msg['r_val'], msg['sender_n'], msg['sender_e'])
        return jsonify({
            "success": True,
            "plaintext": plaintext,
            "valid_gcm": True,
            "valid_sig": is_valid_sig,
            "sender": msg['sender_name'],
            "timestamp": msg['timestamp']
        })
    except Exception:
        return jsonify({
            "success": False,
            "error": "Dekripsi gagal! Password salah atau ciphertext rusak."
        })

if __name__ == '__main__':
    app.run(debug=True, port=5000)
