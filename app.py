from flask import Flask, render_template, request, redirect, url_for, session
import sqlite3
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)

# 🔑 SECRET KEY (Crucial for Sessions)
# This acts like a digital signature to keep the session secure.
app.secret_key = "super_secret_key_123" 

# --- DATABASE SETUP ---
def init_db():
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS users 
                 (id INTEGER PRIMARY KEY, username TEXT, password TEXT)''')
    conn.commit()
    conn.close()

init_db()

# --- ROUTES ---

@app.route('/')
def home():
    # If already logged in, send them to dashboard
    if 'username' in session:
        return redirect(url_for('dashboard'))
    return "<h1>Welcome! <a href='/login'>Login</a> or <a href='/register'>Register</a></h1>"

# --- 3. SECURE REGISTRATION ROUTE (Updated for Styling) ---
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        # Security Check
        if len(password) < 8:
            return render_template('success.html', msg="❌ Error: Password must be at least 8 characters.")

        hashed_password = generate_password_hash(password)
        
        conn = sqlite3.connect('users.db')
        c = conn.cursor()
        try:
            c.execute("INSERT INTO users (username, password) VALUES (?, ?)", (username, hashed_password))
            conn.commit()
            # ✅ SEND SUCCESS MESSAGE TO THE NEW HTML PAGE
            return render_template('success.html', msg="Registration Successful! You can now Login.")
        except:
            # ❌ SEND ERROR MESSAGE TO THE NEW HTML PAGE
            return render_template('success.html', msg="Error: User might already exist.")
        finally:
            conn.close()

    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        conn = sqlite3.connect('users.db')
        c = conn.cursor()
        c.execute("SELECT * FROM users WHERE username = ?", (username,))
        user = c.fetchone()
        conn.close()
        
        if user and check_password_hash(user[2], password):
            # ✅ CREATE SESSION (Give them the digital ID card)
            session['username'] = username
            return redirect(url_for('dashboard'))
        else:
            return "<h1>Login Failed! ❌</h1> <a href='/login'>Try Again</a>"

    return render_template('login.html')

# --- 🔒 PROTECTED ROUTE (Dashboard) ---
@app.route('/dashboard')
def dashboard():
    # Check if user has a session ID
    if 'username' in session:
        return render_template('dashboard.html', username=session['username'])
    else:
        return redirect(url_for('login')) # Kick them out if not logged in

# --- 🚪 LOGOUT ROUTE ---
@app.route('/logout')
def logout():
    session.pop('username', None) # Destroy the session ID
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(debug=True)