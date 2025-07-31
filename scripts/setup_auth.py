import sqlite3
from flask_bcrypt import Bcrypt
from flask import Flask


app = Flask(__name__)
bcrypt = Bcrypt(app)

def setup_auth():
    conn = sqlite3.connect('logs.db')
    cursor = conn.cursor()
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS admins(
       username TEXT PRIMARY KEY,
       password_hash TEXT
    )
    ''')

    username = 'admin'
    password = 'admin123'
    password_hash = bcrypt.generate_password_hash(password).decode('utf-8')
    cursor.execute('INSERT OR IGNORE INTO admins (username, password_hash) VALUES (?, ?)', (username, password_hash))
    conn.commit()
    conn.close()
    print("Authentification configuree avec succes.")

if __name__ == "__main__":
    setup_auth()
