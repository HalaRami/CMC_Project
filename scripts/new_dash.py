import dash
from dash import dcc, html, dash_table, Input, Output
import dash_bootstrap_components as dbc
from flask import Flask, request, redirect, session, url_for, render_template_string
from flask_bcrypt import Bcrypt
import sqlite3
import pandas as pd
import matplotlib.pyplot as plt
import io
import base64
import os
from datetime import datetime, timedelta
from cryptography.fernet import Fernet
import matplotlib
matplotlib.use('Agg')

# Flask Configuration
server = Flask(__name__)
server.secret_key = os.urandom(24)
bcrypt = Bcrypt(server)

# Dash Configuration with Tailwind CSS
app = dash.Dash(__name__, server=server, external_stylesheets=[
    'https://cdn.jsdelivr.net/npm/tailwindcss@2.2.19/dist/tailwind.min.css'
], suppress_callback_exceptions=True)
app.title = "CMC Dashboard"

# File Paths
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, 'logs.db')
ANOMALIES_CSV = os.path.join(BASE_DIR, 'anomalies_detected.csv')
KEY_PATH = os.path.join(BASE_DIR, 'encryption_key.key')

# Verify file paths
print(f"BASE_DIR: {BASE_DIR}")
print(f"DB_PATH: {DB_PATH}, Exists: {os.path.exists(DB_PATH)}")
print(f"ANOMALIES_CSV: {ANOMALIES_CSV}, Exists: {os.path.exists(ANOMALIES_CSV)}")
print(f"KEY_PATH: {KEY_PATH}, Exists: {os.path.exists(KEY_PATH)}")

# Load encryption key
try:
    with open(KEY_PATH, 'rb') as key_file:
        key = key_file.read()
    cipher = Fernet(key)
except Exception as e:
    print(f"Error loading encryption key: {e}")
    exit(1)

# Decryption function
def decrypt_data(data):
    try:
        return cipher.decrypt(data.encode()).decode()
    except Exception as e:
        print(f"Decryption failed for {data}: {e}")
        return data

# Verify credentials
def verify_credentials(username, password):
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute('SELECT password_hash FROM admins WHERE username = ?', (username,))
        result = cursor.fetchone()
        conn.close()
        if result and bcrypt.check_password_hash(result[0], password):
            return True
        return False
    except Exception as e:
        print(f"Error verifying credentials: {e}")
        return False

# Login page
def is_logged_in():
    return session.get('logged_in', False)

@server.route('/')
def root():
    if not is_logged_in():
        return redirect('/login')
    return redirect('/dashboard')

@server.route('/login', methods=['GET', 'POST'])
def login():
    print("Accessing / or /login route")
    error = None
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        if verify_credentials(username, password):
            session['logged_in'] = True
            session['username'] = username
            print(f"User {username} logged in successfully")
            return redirect('/dashboard')
        else:
            error = "Identifiants incorrects."
    
    return render_template_string("""
        <!DOCTYPE html>
        <html lang="fr">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>Connexion Administrateur</title>
            <meta http-equiv="Content-Security-Policy" content="default-src 'self'; script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net;">
            <link href="https://cdn.jsdelivr.net/npm/tailwindcss@2.2.19/dist/tailwind.min.css" rel="stylesheet">
            <script src="https://cdn.jsdelivr.net/npm/particles.js@2.0.0/particles.min.js"></script>
            <style>
                body {
                    background: linear-gradient(135deg, #6b7280, #1e3a8a);
                }
                .auth-card {
                    animation: fadeIn 1s ease-in-out;
                    background: rgba(255, 255, 255, 0.95);
                    backdrop-filter: blur(10px);
                }
                .toggle-password {
                    position: absolute;
                    right: 12px;
                    top: 60%; /* Adjusted to lower the position */
                    transform: translateY(-40%); /* Adjusted to compensate for the new top value */
                    cursor: pointer;
                    color: #8b5cf6;
                    font-size: 0.875rem;
                }
                .password-container {
                    position: relative;
                }
                @keyframes fadeIn {
                    from { opacity: 0; transform: translateY(20px); }
                    to { opacity: 1; transform: translateY(0); }
                }
                #particles-js {
                    position: fixed;
                    width: 100%;
                    height: 100%;
                    z-index: -1;
                    background: transparent;
                }
                button, a {
                    transition: all 0.3s ease;
                }
                button:hover {
                    transform: translateY(-2px);
                }
                .font-control {
                    border-radius: 5px;
                    border: 1px solid #ced4da;
                    padding: 10px;
                    background-color: #e6f0fa;
                    transition: border-color 0.3s ease;
                }
                .font-control:focus {
                    border-color: #3498db;
                    box-shadow: 0 0 5px rgba(52, 152, 219, 0.3);
                    background-color: #e6f0fa;
                }
            </style>
            <script>
                function togglePassword(fieldId) {
                    const field = document.getElementById(fieldId);
                    const toggle = document.getElementById(fieldId + '-toggle');
                    field.type = field.type === 'password' ? 'text' : 'password';
                    toggle.textContent = field.type === 'password' ? 'Afficher' : 'Masquer';
                }
                document.addEventListener('DOMContentLoaded', function() {
                    particlesJS('particles-js', {
                        particles: {
                            number: { value: 80, density: { enable: true, value_area: 800 } },
                            color: { value: '#8b5cf6' },
                            shape: { type: 'circle' },
                            opacity: { value: 0.5, random: true },
                            size: { value: 3, random: true },
                            line_linked: { enable: true, distance: 150, color: '#8b5cf6', opacity: 0.4, width: 1 },
                            move: { enable: true, speed: 3, direction: 'none', random: false }
                        },
                        interactivity: {
                            detect_on: 'canvas',
                            events: { onhover: { enable: true, mode: 'repulse' }, onclick: { enable: true, mode: 'push' } },
                            modes: { repulse: { distance: 100 }, push: { particles_nb: 4 } }
                        },
                        retina_detect: true
                    });
                });
            </script>
        </head>
        <body class="flex items-center justify-center min-h-screen">
            <div id="particles-js"></div>
            <div class="auth-card p-8 rounded-2xl shadow-2xl w-full max-w-md">
                <h2 class="text-3xl font-bold text-center text-gray-800 mb-6">Connexion CMC</h2>
                {% if error %}
                <div class="bg-red-100 text-red-700 p-3 rounded-lg mb-4">{{ error }}</div>
                {% endif %}
                <form method="post">
                    <div class="mb-4">
                        <label class="block text-gray-700 font-medium mb-2">Nom d'utilisateur</label>
                        <input type="text" name="username" class="w-full p-3 border rounded-lg focus:ring-2 focus:ring-purple-500 focus:border-purple-500 font-control" required>
                    </div>
                    <div class="mb-6 password-container">
                        <label class="block text-gray-700 font-medium mb-2">Mot de passe</label>
                        <input type="password" name="password" id="password" class="w-full p-3 border rounded-lg focus:ring-2 focus:ring-purple-500 focus:border-purple-500 font-control" required>
                        <span class="toggle-password" id="password-toggle" onclick="togglePassword('password')">Afficher</span>
                    </div>
                    <button type="submit" class="w-full bg-gradient-to-r from-purple-600 to-blue-600 text-white p-3 rounded-lg hover:from-purple-700 hover:to-blue-700">Se connecter</button>
                    <a href="/signup" class="block text-center mt-4 text-purple-600 hover:underline">S'inscrire</a>
                </form>
            </div>
        </body>
        </html>
    """, error=error)

@server.route('/signup', methods=['GET', 'POST'])
def signup():
    error = None
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        confirm_password = request.form['confirm_password']
        
        if not username or not password or not confirm_password:
            error = "Veuillez remplir tous les champs obligatoires."
        elif password != confirm_password:
            error = "Les mots de passe ne correspondent pas. Veuillez vérifier."
        else:
            try:
                conn = sqlite3.connect(DB_PATH)
                cursor = conn.cursor()
                cursor.execute('SELECT username FROM admins WHERE username = ?', (username,))
                if cursor.fetchone():
                    error = "Ce nom d'utilisateur est déjà pris. Choisissez un autre."
                else:
                    password_hash = bcrypt.generate_password_hash(password).decode('utf-8')
                    cursor.execute('INSERT INTO admins (username, password_hash) VALUES (?, ?)', (username, password_hash))
                    conn.commit()
                    conn.close()
                    return redirect('/login')
            except Exception as e:
                print(f"Signup error: {e}")
                error = "Erreur lors de l'inscription. Veuillez réessayer."
            finally:
                if 'conn' in locals():
                    conn.close()

    return render_template_string("""
        <!DOCTYPE html>
        <html lang="fr">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>Inscription Administrateur</title>
            <meta http-equiv="Content-Security-Policy" content="default-src 'self'; script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net;">
            <link href="https://cdn.jsdelivr.net/npm/tailwindcss@2.2.19/dist/tailwind.min.css" rel="stylesheet">
            <script src="https://cdn.jsdelivr.net/npm/particles.js@2.0.0/particles.min.js"></script>
            <style>
                body {
                    background: linear-gradient(135deg, #6b7280, #1e3a8a);
                }
                .auth-card {
                    animation: fadeIn 1s ease-in-out;
                    background: rgba(255, 255, 255, 0.95);
                    backdrop-filter: blur(10px);
                }
                .toggle-password {
                    position: absolute;
                    right: 12px;
                    top: 60%; /* Adjusted to lower the position */
                    transform: translateY(-40%); /* Adjusted to compensate for the new top value */
                    cursor: pointer;
                    color: #8b5cf6;
                    font-size: 0.875rem;
                }
                .password-container {
                    position: relative;
                }
                @keyframes fadeIn {
                    from { opacity: 0; transform: translateY(20px); }
                    to { opacity: 1; transform: translateY(0); }
                }
                #particles-js {
                    position: fixed;
                    width: 100%;
                    height: 100%;
                    z-index: -1;
                    background: transparent;
                }
                button, a {
                    transition: all 0.3s ease;
                }
                button:hover {
                    transform: translateY(-2px);
                }
                .font-control {
                    border-radius: 5px;
                    border: 1px solid #ced4da;
                    padding: 10px;
                    background-color: #e6f0fa;
                    transition: border-color 0.3s ease;
                }
                .font-control:focus {
                    border-color: #3498db;
                    box-shadow: 0 0 5px rgba(52, 152, 219, 0.3);
                    background-color: #e6f0fa;
                }
            </style>
            <script>
                function togglePassword(fieldId) {
                    const field = document.getElementById(fieldId);
                    const toggle = document.getElementById(fieldId + '-toggle');
                    field.type = field.type === 'password' ? 'text' : 'password';
                    toggle.textContent = field.type === 'password' ? 'Afficher' : 'Masquer';
                }
                document.addEventListener('DOMContentLoaded', function() {
                    particlesJS('particles-js', {
                        particles: {
                            number: { value: 80, density: { enable: true, value_area: 800 } },
                            color: { value: '#8b5cf6' },
                            shape: { type: 'circle' },
                            opacity: { value: 0.5, random: true },
                            size: { value: 3, random: true },
                            line_linked: { enable: true, distance: 150, color: '#8b5cf6', opacity: 0.4, width: 1 },
                            move: { enable: true, speed: 3, direction: 'none', random: false }
                        },
                        interactivity: {
                            detect_on: 'canvas',
                            events: { onhover: { enable: true, mode: 'repulse' }, onclick: { enable: true, mode: 'push' } },
                            modes: { repulse: { distance: 100 }, push: { particles_nb: 4 } }
                        },
                        retina_detect: true
                    });
                });
            </script>
        </head>
        <body class="flex items-center justify-center min-h-screen">
            <div id="particles-js"></div>
            <div class="auth-card p-8 rounded-2xl shadow-2xl w-full max-w-md">
                <h2 class="text-3xl font-bold text-center text-gray-800 mb-6">Inscription CMC</h2>
                {% if error %}
                <div class="bg-red-100 text-red-700 p-3 rounded-lg mb-4">{{ error }}</div>
                {% endif %}
                <form method="post">
                    <div class="mb-4">
                        <label class="block text-gray-700 font-medium mb-2">Nom d'utilisateur</label>
                        <input type="text" name="username" class="w-full p-3 border rounded-lg focus:ring-2 focus:ring-purple-500 focus:border-purple-500 font-control" value="admin" required>
                    </div>
                    <div class="mb-4 password-container">
                        <label class="block text-gray-700 font-medium mb-2">Mot de passe</label>
                        <input type="password" name="password" id="password" class="w-full p-3 border rounded-lg focus:ring-2 focus:ring-purple-500 focus:border-purple-500 font-control" required>
                        <span class="toggle-password" id="password-toggle" onclick="togglePassword('password')">Afficher</span>
                    </div>
                    <div class="mb-6 password-container">
                        <label class="block text-gray-700 font-medium mb-2">Confirmer le mot de passe</label>
                        <input type="password" name="confirm_password" id="confirm_password" class="w-full p-3 border rounded-lg focus:ring-2 focus:ring-purple-500 focus:border-purple-500 font-control" required>
                        <span class="toggle-password" id="confirm_password-toggle" onclick="togglePassword('confirm_password')">Afficher</span>
                    </div>
                    <button type="submit" class="w-full bg-gradient-to-r from-purple-600 to-blue-600 text-white p-3 rounded-lg hover:from-purple-700 hover:to-blue-700">S'inscrire</button>
                    <a href="/login" class="block text-center mt-4 text-purple-600 hover:underline">Retour à la connexion</a>
                </form>
            </div>
        </body>
        </html>
    """, error=error)

@server.route('/logout')
def logout():
    session.pop('logged_in', None)
    session.pop('username', None)
    return redirect('/login')

@server.route('/dashboard')
def dashboard():
    if not session.get('logged_in'):
        return redirect('/login')
    return app.index()

def create_layout():
    return html.Div([
        dcc.Location(id='url', refresh=False),
        html.Div(id='page-content')
    ])

app.layout = create_layout()

def main_page():
    platforms = ['OFPPT Academy', 'OFPPT Langues', 'ScholarVox', 'Electude']
    platform_cards = [
        html.Div([
            html.Div(className="flex items-center mb-3", children=[
                html.Span("📚", className="text-3xl mr-2 text-purple-600"),  # Modern icon
                html.H5(platform, className="text-xl font-bold text-purple-600"),
            ]),
            html.P("Explorez les logs et anomalies.", className="text-gray-700 text-base mb-4"),
            dcc.Link("Voir détails", href=f"/platform/{platform.replace(' ', '_')}", 
                     className="mt-4 inline-block bg-gradient-to-r from-purple-600 to-blue-600 text-white px-5 py-2.5 rounded-full font-medium hover:from-purple-700 hover:to-blue-700 transition-all duration-300 transform hover:scale-105 hover:shadow-lg text-base")
        ], className="bg-gradient-to-br from-white to-gray-50 p-8 rounded-xl shadow-lg hover:shadow-2xl transition-all duration-300 transform hover:scale-105 border border-purple-200/50 w-80 animate-slide-in", style={'animation-delay': f'{i * 0.1}s'}) for i, platform in enumerate(platforms)
    ]

    return html.Div([
        # Header
        html.Div(className="fixed top-0 left-0 w-full bg-white/30 backdrop-blur-md shadow-lg z-10", style={
            'background': 'linear-gradient(to right, rgba(255, 255, 255, 0.3), rgba(255, 255, 255, 0.2))',
        }, children=[
            html.Div(className="container mx-auto px-4 py-4 flex justify-between items-center", children=[
                html.H1(
                    "Tableau de bord CMC",
                    className="text-4xl font-extrabold",
                    style={
                        'background': 'linear-gradient(to right, #7c3aed, #2563eb)',
                        '-webkit-background-clip': 'text',
                        'background-clip': 'text',
                        'color': 'transparent',
                        'text-shadow': '0 0 8px rgba(124, 58, 237, 0.5)',
                        'font-family': "'Inter', 'Arial', sans-serif",
                        'animation': 'fade-in 1s ease-out'
                    }
                ),
                html.A("Déconnexion", href="/logout", className="text-white bg-red-600 px-4 py-2 rounded-lg hover:bg-red-700 transition transform hover:-translate-y-1")
            ])
        ]),
        # Main Content
        html.Div(className="container mx-auto px-4 pt-24 pb-8 flex justify-center items-center min-h-screen", children=[
            html.Div([
                html.Div(platform_cards, className="grid grid-cols-2 gap-8 max-w-4xl"),
            ], className="bg-white/20 backdrop-blur-lg rounded-2xl shadow-2xl p-10 border border-purple-200/30 animate-fade-in")
        ])
    ], className="min-h-screen", style={
        'background': 'linear-gradient(to bottom, #f3f4f6, #e5e7eb)'
    })
def fig_to_base64(fig):
    buf = io.BytesIO()
    fig.savefig(buf, format='png', bbox_inches='tight')
    buf.seek(0)
    img_base64 = base64.b64encode(buf.getvalue()).decode('utf-8')
    buf.close()
    return f"data:image/png;base64,{img_base64}"

def platform_page(platform):
    try:
        with sqlite3.connect(DB_PATH) as conn:
            time_threshold = (datetime.now() - timedelta(hours=1)).strftime('%Y-%m-%d %H:%M:%S')
            query = 'SELECT * FROM logs WHERE platform = ? AND timestamp >= ?'
            df_logs = pd.read_sql_query(query, conn, params=(platform, time_threshold))
            for col in ['first_name', 'last_name', 'birth_date']:
                if col in df_logs.columns:
                    df_logs[col] = df_logs[col].apply(decrypt_data)
    except Exception as e:
        print(f"Error loading logs: {e}")
        df_logs = pd.DataFrame()

    try:
        df_anomalies = pd.read_csv(ANOMALIES_CSV)
        df_anomalies = df_anomalies[df_anomalies['platform'] == platform]
        df_anomalies['details'] = df_anomalies['details'].apply(
            lambda x: ' '.join([decrypt_data(word) if word.startswith('g=') else word for word in x.split()])
        )
    except Exception as e:
        print(f"Error loading anomalies: {e}")
        df_anomalies = pd.DataFrame()

    try:
        with sqlite3.connect(DB_PATH) as conn:
            query = 'SELECT * FROM audit_log WHERE details LIKE ?'
            df_actions = pd.read_sql_query(query, conn, params=(f'%{platform}%',))
    except Exception as e:
        print(f"Error loading actions: {e}")
        df_actions = pd.DataFrame()

    histogram_img, timeline_img = None, None
    if not df_anomalies.empty:
        plt.figure(figsize=(6, 3))
        df_anomalies['anomaly_type'].value_counts().plot(kind='bar', color='#8b5cf6')
        plt.title("Répartition des types d'anomalies")
        plt.xlabel("Type d'anomalie")
        plt.ylabel("Nombre")
        plt.tight_layout()
        histogram_img = fig_to_base64(plt.gcf())
        plt.close()

        df_anomalies['timestamp'] = pd.to_datetime(df_anomalies['timestamp'])
        df_time = df_anomalies.groupby(df_anomalies['timestamp'].dt.floor('h')).size().reset_index(name='count')
        plt.figure(figsize=(6, 3))
        plt.plot(df_time['timestamp'], df_time['count'], marker='o', color='#3b82f6')
        plt.title("Évolution des anomalies par heure")
        plt.xlabel("Heure")
        plt.ylabel("Nombre d'anomalies")
        plt.xticks(rotation=45)
        plt.tight_layout()
        timeline_img = fig_to_base64(plt.gcf())
        plt.close()

    return html.Div([
        html.Div(className="container mx-auto px-4 py-8", children=[
            html.H2(f"📊 Plateforme : {platform}", className="text-3xl font-bold text-center text-gray-800 mb-2"),
            html.P("Analyse des activités, anomalies et journaux récents", className="text-center text-gray-600 mb-6"),
            html.Div(className="flex justify-between mb-6", children=[
                dcc.Link("← Retour au tableau de bord", href="/dashboard", className="text-purple-600 hover:underline font-medium"),
                html.A("Déconnexion", href="/logout", className="text-white bg-red-600 px-4 py-2 rounded-lg hover:bg-red-700 transition transform hover:-translate-y-1")
            ]),
            html.Div([
                html.H4("🕒 Logs récents (dernière heure)", className="text-lg font-semibold text-gray-800 mb-3"),
                dash_table.DataTable(
                    data=df_logs.to_dict('records'),
                    columns=[{'name': col, 'id': col} for col in df_logs.columns],
                    page_size=10,
                    style_table={'overflowX': 'auto', 'borderRadius': '8px', 'boxShadow': '0 4px 20px rgba(0,0,0,0.1)'},
                    style_cell={'textAlign': 'left', 'padding': '8px', 'fontFamily': 'Arial'},
                    style_header={'background': 'linear-gradient(to right, #8b5cf6, #3b82f6)', 'color': 'white', 'fontWeight': 'bold'},
                    style_data_conditional=[{'if': {'row_index': 'odd'}, 'backgroundColor': '#f9fafb'}]
                )
            ], className="mb-8"),
            html.Div([
                html.H4("🚨 Anomalies détectées", className="text-lg font-semibold text-gray-800 mb-3"),
                dash_table.DataTable(
                    data=df_anomalies.to_dict('records'),
                    columns=[{'name': col, 'id': col} for col in df_anomalies.columns],
                    page_size=10,
                    style_table={'overflowX': 'auto', 'borderRadius': '8px', 'boxShadow': '0 4px 20px rgba(0,0,0,0.1)'},
                    style_cell={'textAlign': 'left', 'padding': '8px', 'fontFamily': 'Arial'},
                    style_header={'background': 'linear-gradient(to right, #8b5cf6, #3b82f6)', 'color': 'white', 'fontWeight': 'bold'},
                    style_data_conditional=[{'if': {'row_index': 'odd'}, 'backgroundColor': '#f9fafb'}]
                )
            ], className="mb-8"),
            html.Div([
                html.H4("📝 Historique des actions", className="text-lg font-semibold text-gray-800 mb-3"),
                dash_table.DataTable(
                    data=df_actions.to_dict('records'),
                    columns=[{'name': col, 'id': col} for col in df_actions.columns],
                    page_size=10,
                    style_table={'overflowX': 'auto', 'borderRadius': '8px', 'boxShadow': '0 4px 20px rgba(0,0,0,0.1)'},
                    style_cell={'textAlign': 'left', 'padding': '8px', 'fontFamily': 'Arial'},
                    style_header={'background': 'linear-gradient(to right, #8b5cf4, #3b82f6)', 'color': 'white', 'fontWeight': 'bold'},
                    style_data_conditional=[{'if': {'row_index': 'odd'}, 'backgroundColor': '#f9fafb'}]
                )
            ], className="mb-8"),
            html.Div(className="grid grid-cols-1 lg:grid-cols-2 gap-6", children=[
                html.Div([
                    html.H4("📈 Visualisation des anomalies", className="text-lg font-semibold text-gray-800 mb-3"),
                    html.Img(src=histogram_img, className="w-full rounded-lg shadow-md transform hover:scale-105 transition duration-300", style={'height': '250px'}) if histogram_img else html.P("Aucune donnée pour l'histogramme", className="text-gray-600")
                ]),
                html.Div([
                    html.H4("📊 Évolution temporelle", className="text-lg font-semibold text-gray-800 mb-3"),
                    html.Img(src=timeline_img, className="w-full rounded-lg shadow-md transform hover:scale-105 transition duration-300", style={'height': '250px'}) if timeline_img else html.P("Aucune donnée pour la courbe temporelle", className="text-gray-600")
                ])
            ])
        ])
    ], className="bg-gradient-to-b from-gray-100 to-gray-200 min-h-screen")

@app.callback(
    Output('page-content', 'children'),
    [Input('url', 'pathname')]
)
def display_page(pathname):
    if pathname == '/dashboard':
        return main_page()
    elif pathname.startswith('/platform/'):
        platform = pathname.split('/platform/')[1].replace('_', ' ')
        return platform_page(platform)
    else:
        return dcc.Location(pathname='/login', id='redirect')

if __name__ == "__main__":
    server.run(host='0.0.0.0', port=8050, debug=True)