import pandas as pd
import sqlite3
from datetime import datetime, timedelta
import os
from cryptography.fernet import Fernet

# Charger la clé de chiffrement
key_path = os.path.join(os.path.dirname(__file__), 'encryption_key.key')
try:
    with open(key_path, 'rb') as key_file:
        key = key_file.read()
    cipher = Fernet(key)
except Exception as e:
    print(f"Erreur lors du chargement de la clé de chiffrement : {e}")
    exit(1)

def decrypt_data(data):
    try:
        return cipher.decrypt(data.encode()).decode()
    except Exception as e:
        print(f"Échec du déchiffrement pour {data}. Retour des données brutes : {e}")
        return data  # Retourner les données brutes en cas d'erreur

def block_user(user_id, platform, duration=3600):
    try:
        db_path = os.path.join(os.path.dirname(__file__), 'logs.db')
        with sqlite3.connect(db_path) as conn:
            cursor = conn.cursor()
            block_timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            cursor.execute('''
                INSERT OR REPLACE INTO blocked_users (user_id, platform, block_timestamp, block_duration) 
                VALUES (?, ?, ?, ?)
            ''', (user_id, platform, block_timestamp, duration))
            cursor.execute('''
                INSERT INTO audit_log (timestamp, admin_id, action, details) 
                VALUES (?, ?, ?, ?)
            ''', (block_timestamp, 'system', 'block_user', f"Utilisateur {user_id} bloqué sur {platform}"))
            conn.commit()
        return f"Utilisateur {user_id} bloqué temporairement sur {platform}"
    except Exception as e:
        print(f"Erreur lors du blocage de l'utilisateur : {e}")
        return None

def detect_anomalies(platform=None):
    try:
        db_path = os.path.join(os.path.dirname(__file__), 'logs.db')
        with sqlite3.connect(db_path) as conn:
            cursor = conn.cursor()

            # Vérifier la structure de la table logs
            cursor.execute("PRAGMA table_info(logs)")
            columns = [col[1] for col in cursor.fetchall()]
            print(f"Colonnes dans la table logs : {columns}")
            required_columns = ['ip_address', 'platform', 'action', 'status', 'user_id', 'timestamp']
            for col in required_columns:
                if col not in columns:
                    print(f"Erreur : La colonne '{col}' est absente dans la table logs.")
                    return []

            # Charger les logs (dernière heure)
            time_threshold = (datetime.now() - timedelta(hours=1)).strftime('%Y-%m-%d %H:%M:%S')
            query = 'SELECT * FROM logs WHERE timestamp >= ?'
            params = [time_threshold]
            if platform:
                query += ' AND platform = ?'
                params.append(platform)

            df = pd.read_sql_query(query, conn, params=params)
            print(f"Nombre de logs chargés (dernière heure) : {len(df)}")
            if df.empty:
                print("Aucun log trouvé dans la dernière heure.")
                return []

            # Déchiffrer les colonnes
            for col in ['first_name', 'last_name', 'birth_date']:
                if col in df.columns:
                    df[col] = df[col].apply(decrypt_data)
                else:
                    print(f"Colonne {col} manquante dans les logs.")

            anomalies = []

            # 1. Échecs de connexion multiples (seuil à 2)
            login_failures = df[(df['action'] == 'login') & (df['status'] == 'failure')]
            print(f"Échecs de connexion trouvés : {len(login_failures)}")
            for (user_id, platform), group in login_failures.groupby(['user_id', 'platform']):
                if len(group) >= 2:
                    timestamps = pd.to_datetime(group['timestamp'])
                    if (timestamps.max() - timestamps.min()).total_seconds() <= 600:
                        user_info = group.iloc[0]
                        details = f"{len(group)} échecs de connexion pour {user_info['first_name']} {user_info['last_name']} ({user_id}) sur {platform}"
                        action = block_user(user_id, platform)
                        anomalies.append({
                            'platform': platform,
                            'user_id': user_id,
                            'anomaly_type': 'multiple_login_failures',
                            'timestamp': group['timestamp'].iloc[0],
                            'details': details,
                            'solution': 'Bloquer temporairement le compte pour 1 heure',
                            'action_taken': action
                        })

            # 2. Heures inhabituelles (0h-6h)
            df['timestamp'] = pd.to_datetime(df['timestamp'])
            unusual_hours = df[df['timestamp'].dt.hour.between(0, 6)]
            print(f"Connexions à heures inhabituelles : {len(unusual_hours)}")
            for _, row in unusual_hours.iterrows():
                details = f"Connexion à une heure inhabituelle pour {row['first_name']} {row['last_name']} ({row['user_id']}) sur {row['platform']}"
                anomalies.append({
                    'platform': row['platform'],
                    'user_id': row['user_id'],
                    'anomaly_type': 'unusual_hour',
                    'timestamp': row['timestamp'].strftime('%Y-%m-%d %H:%M:%S'),
                    'details': details,
                    'solution': 'Demander une authentification supplémentaire',
                    'action_taken': 'Alerte envoyée à l\'utilisateur'
                })

            # 3. Multiples adresses IP
            for (user_id, platform), group in df.groupby(['user_id', 'platform']):
                unique_ips = group['ip_address'].unique()
                if len(unique_ips) > 1:
                    timestamps = pd.to_datetime(group['timestamp'])
                    if (timestamps.max() - timestamps.min()).total_seconds() <= 600:
                        user_info = group.iloc[0]
                        details = f"Connexions depuis multiples IPs ({', '.join(unique_ips)}) pour {user_info['first_name']} {user_info['last_name']} ({user_id}) sur {platform}"
                        anomalies.append({
                            'platform': platform,
                            'user_id': user_id,
                            'anomaly_type': 'multiple_ips',
                            'timestamp': group['timestamp'].iloc[0],
                            'details': details,
                            'solution': 'Demander une réauthentification',
                            'action_taken': 'Alerte envoyée à l\'utilisateur'
                        })

            
            # 4. Accès non autorisés
            unauthorized = df[(df['action'] == 'access_resource') & (df['status'] == 'failure')]
            print(f"Tentatives d'accès non autorisées : {len(unauthorized)}")
            for _, row in unauthorized.iterrows():
                details = f"Tentative d'accès non autorisée pour {row['first_name']} {row['last_name']} ({row['user_id']}) sur {row['platform']}"
                action = block_user(row['user_id'], row['platform'])
                anomalies.append({
                    'platform': row['platform'],
                    'user_id': row['user_id'],
                    'anomaly_type': 'unauthorized_access',
                    'timestamp': row['timestamp'].strftime('%Y-%m-%d %H:%M:%S'),
                    'details': details,
                    'solution': 'Bloquer temporairement le compte',
                    'action_taken': action
                })

            # 5. IPs suspectes
            suspicious_ips = ['203.0.113.1']
            suspicious = df[df['ip_address'].isin(suspicious_ips)]
            print(f"Connexions depuis IPs suspectes : {len(suspicious)}")
            for _, row in suspicious.iterrows():
                details = f"Connexion depuis une IP suspecte ({row['ip_address']}) pour {row['first_name']} {row['last_name']} ({row['user_id']}) sur {row['platform']}"
                action = block_user(row['user_id'], row['platform'])
                anomalies.append({
                    'platform': row['platform'],
                    'user_id': row['user_id'],
                    'anomaly_type': 'suspicious_ip',
                    'timestamp': row['timestamp'].strftime('%Y-%m-%d %H:%M:%S'),
                    'details': details,
                    'solution': 'Blacklister l\'IP et demander une authentification',
                    'action_taken': action
                })

            # Enregistrer les anomalies
            if anomalies:
                df_anomalies = pd.DataFrame(anomalies)
                csv_path = os.path.join(os.path.dirname(__file__), 'anomalies_detected.csv')
                os.makedirs(os.path.dirname(csv_path), exist_ok=True)
                if os.path.exists(csv_path):
                    df_anomalies.to_csv(csv_path, mode='a', header=False, index=False)
                else:
                    df_anomalies.to_csv(csv_path, index=False)
                print(f"{len(anomalies)} anomalies détectées et enregistrées dans {csv_path}")
            else:
                print("Aucune anomalie détectée.")

            return anomalies

    except Exception as e:
        print(f"Erreur lors de la détection des anomalies : {e}")
        return []

if __name__ == "__main__":
    anomalies = detect_anomalies()
    print(f"Résultat final : {len(anomalies)} anomalies trouvées.")
