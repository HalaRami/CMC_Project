import sqlite3
from flask_bcrypt import Bcrypt
from flask import Flask

app = Flask(__name__)
bcrypt = Bcrypt(app)

def verify_credentials(username, password):
    conn = sqlite3.connect('logs.db')
    cursor = conn.cursor()
    cursor.execute('SELECT password_hash FROM admins WHERE username= ?', (username,))
    result = cursor.fetchone()
    conn.close()

    if result and bcrypt.check_password_hash(result[0], password):
       return True
    return False
