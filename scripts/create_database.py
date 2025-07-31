import sqlite3
from flask_bcrypt import Bcrypt
from flask import Flask

app = Flask(__name__)
bcrypt = Bcrypt(app)

def create_database():
    try:
       conn = sqlite3.connect('logs.db')
       cursor = conn.cursor()

       # Table des utilisateurs
       cursor.execute('''
       CREATE TABLE IF NOT EXISTS users(
          user_id TEXT PRIMARY KEY,
          first_name TEXT,
          last_name TEXT,
          birth_date TEXT
       )
       ''')

       # Table des logs
       cursor.execute('''
       CREATE TABLE IF NOT EXISTS logs(
          timestamp TEXT,
          platform TEXT,
          user_id TEXT,
          first_name TEXT,
          last_name TEXT,
          birth_date TEXT,
          action TEXT,
          ip_address TEXT,
          status TEXT,
          FOREIGN KEY (user_id) REFERENCES users(user_id)
       )
       ''')

       # Table des utilisateurs bloqués
       cursor.execute('''
       CREATE TABLE IF NOT EXISTS blocked_users(
          user_id TEXT,
          platform TEXT,
          block_timestamp TEXT,
          block_duration INTEGER,
          FOREIGN KEY (user_id) REFERENCES users(user_id)
       )
       ''')

       # Table pour l'audit
       cursor.execute('''
       CREATE TABLE IF NOT EXISTS audit_log(
          timestamp TEXT,
          admin_id TEXT,
          action TEXT,
          details TEXT
       )
       ''')

       # Table des administrateurs
       cursor.execute('''
       CREATE TABLE IF NOT EXISTS admins(
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          username TEXT UNIQUE NOT NULL,
          password_hash TEXT NOT NULL
       )
       ''')

       # Insert a default admin
       username = 'admin'
       password = 'admin123'
       password_hash = bcrypt.generate_password_hash(password).decode('utf-8')
       cursor.execute('INSERT OR IGNORE INTO admins (username, password_hash) VALUES (?, ?)', (username, password_hash))

       conn.commit()
       conn.close()
       print("Base de données créée avec succès.")
    except Exception as e:
       print(f"Erreur lors de la création de la base de données : {e}")

if __name__ == "__main__":
    create_database()
