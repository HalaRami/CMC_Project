import pandas as pd
import random
from datetime import datetime, timedelta
import sqlite3
from faker import Faker
from cryptography.fernet import Fernet
import os
import argparse
import time

# Gestion des arguments
parser = argparse.ArgumentParser(description='Générer des logs simulés.')
parser.add_argument('--append', action='store_true', help='Ajouter des logs sans réinitialiser.')
parser.add_argument('--continuous', action='store_true', help='Exécuter en continu avec intervalle.')
args = parser.parse_args()

# Charger la clé de chiffrement
key_path = os.path.join(os.path.dirname(__file__), 'encryption_key.key')
if not os.path.exists(key_path):
    key = Fernet.generate_key()
    with open(key_path, 'wb') as key_file:
        key_file.write(key)
else:
    with open(key_path, 'rb') as key_file:
        key = key_file.read()  # Stocker la clé lue
cipher = Fernet(key)

def encrypt_data(data):
    return cipher.encrypt(data.encode()).decode()

# Initialiser Faker
fake = Faker('fr_FR')

# Paramètres
platforms = ['OFPPT Academy', 'OFPPT Langues', 'ScholarVox', 'Electude']
actions = ['login', 'logout', 'access_resource']
statuses = ['success', 'failure']
ips = [f'192.168.1.{i}' for i in range(1, 255)] + ['203.0.113.1', '10.0.0.15']
num_users = 100 if not args.append else 0
num_logs = 50

# Connexion à la base
db_path = os.path.join(os.path.dirname(__file__), 'logs.db')
conn = sqlite3.connect(db_path)
cursor = conn.cursor()

# Générer des utilisateurs
if not args.append:
    users = []
    for i in range(num_users):
        user_id = f'user{i+1}'
        first_name = encrypt_data(fake.first_name())
        last_name = encrypt_data(fake.last_name())
        birth_date = encrypt_data(fake.date_of_birth(minimum_age=18, maximum_age=60).strftime('%Y-%m-%d'))
        users.append([user_id, first_name, last_name, birth_date])
    try:
        cursor.executemany('INSERT OR REPLACE INTO users VALUES (?, ?, ?, ?)', users)
        conn.commit()
    except Exception as e:
        print(f"Erreur lors de l'enregistrement des utilisateurs : {e}")
        conn.close()
        exit(1)

# Génération des logs
def generate_new_logs():
    logs = []
    cursor.execute('SELECT user_id, first_name, last_name, birth_date FROM users')
    users = cursor.fetchall()

    for _ in range(num_logs):
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        platform = random.choice(platforms)
        user = random.choice(users)
        user_id, first_name, last_name, birth_date = user
        action = random.choice(actions)
        ip_address = random.choice(ips)  # Utiliser ip_address pour cohérence
        status = 'failure' if random.random() < 0.3 else 'success'

        if random.random() < 0.1:
            if random.random() < 0.3:
                timestamp = (datetime.now() - timedelta(hours=random.randint(0, 5))).strftime('%Y-%m-%d %H:%M:%S')
            elif random.random() < 0.3:
                ip_address = random.choice([f'10.0.0.{random.randint(1, 100)}', '203.0.113.1'])
            elif random.random() < 0.3:
                status = 'failure'
        logs.append([timestamp, platform, user_id, first_name, last_name, birth_date, action, ip_address, status])
    return logs

# Boucle continue
if args.continuous:
    while True:
        logs = generate_new_logs()
        try:
            df_logs = pd.DataFrame(logs, columns=['timestamp', 'platform', 'user_id', 'first_name', 'last_name', 'birth_date', 'action', 'ip_address', 'status'])
            csv_path = os.path.join(os.path.dirname(__file__), 'simulated_logs.csv')
            if args.append and os.path.exists(csv_path):
                df_logs.to_csv(csv_path, mode='a', header=False, index=False)
            else:
                df_logs.to_csv(csv_path, index=False)
            df_logs.to_sql('logs', conn, if_exists='append', index=False)
            print(f"{len(logs)} nouveaux logs ajoutés à {csv_path} et logs.db.")
        except Exception as e:
            print(f"Erreur lors de l'enregistrement des logs : {e}")
        time.sleep(30)
else:
    logs = generate_new_logs()
    try:
        df_logs = pd.DataFrame(logs, columns=['timestamp', 'platform', 'user_id', 'first_name', 'last_name', 'birth_date', 'action', 'ip_address', 'status'])
        csv_path = os.path.join(os.path.dirname(__file__), 'simulated_logs.csv')
        if args.append and os.path.exists(csv_path):
            df_logs.to_csv(csv_path, mode='a', header=False, index=False)
        else:
            df_logs.to_csv(csv_path, index=False)
        df_logs.to_sql('logs', conn, if_exists='append', index=False)
        print(f"{len(logs)} nouveaux logs ajoutés à {csv_path} et logs.db.")
    except Exception as e:
        print(f"Erreur lors de l'enregistrement des logs : {e}")

conn.close()
