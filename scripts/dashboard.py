
import dash 
from dash import dcc, html, dash_table, Input, Output, State
import dash_bootstrap_components as dbc
from flask import Flask, request, redirect, session, url_for, send_from_directory, render_template_string
from flask_bcrypt import  Bcrypt
import sqlite3
import pandas as pd
import matplotlib.pyplot as plt
import io
import base64
import os
from datetime import datetime, timedelta
from cryptography.fernet import Fernet

#Configuration de Flask
server = Flask(__name__)
server.secret_key = os.urandom(24)
bcrypt = Bcrypt(server)

#Configuration de Dash avec Bootstrap
app = dash.Dash(__name__, server=server, external_stylesheets=[dbc.themes.BOOTSTRAP], suppress_callback_exceptions=True)
app.title = "CMC Dashboard"

#Chemins
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DB_PATH = os.path.join(BASE_DIR, 'logs.db')
ANOMALIES_CSV = os.path.join(BASE_DIR, 'anomalies_detected.csv')
KEY_PATH = os.path.join(BASE_DIR, 'encryption_key.key')

#verify file paths
print(f"BASE_DIR: {BASE_dir}")
print(f"DB_PATH: {DB_PATH}, Exists: {os.path.exists(DB_PATH)}")
print(f"ANOMALIES_CSV: {ANOMALIES_CSV}, Exists: {os.path.exists(ANOMALIES_CSV)}")
print(f"KEY_PATH: {KEY_PATH}, Exists: {os.path.exists(KEY_PATH)}")

#Charger la cle de chiffrement
try:
   with open(KEY_PATH, 'rb') as key_file:
      key = key_file.read() 
   cipher = Fernet(key)
except exception as e:
   print(f"Erreur lors du chargement de la cle de chiffrement : {e}")
   exit(1)

#Fonction de dechiffrement 
def decrypt_data(data):
    try:
       return cipher.decrypt(data.encode()).decode()
    except Exception:
       print(f"Echec du dechiffrement pour {data}. Retour des donnees brutes.")
       return data

#Verification des identifiants
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
       print(f"Erreur lors de la verification des identifiants : {e}")
       return False

#page d'inscription Flask
@server.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
       username = request.form['username']
       password = request.form['password']
       if not username or not password:
          return render_template_string("""
              <!DOCTYPE html>
              <html>
              <head>
                  <title> Inscription</title>
                  <meta http-equiv="Content-Security-Policy" content="default-src 'self'; script-src 'self' https.//cdn.jsdelivr.net; style-src 'self' https://cdn.jsdelivr.net; connect-src 'self';">
                  <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dict/css/bootstrap.min.css" rel="stylesheet">
                  <link href="/assets/style.css" rel="stylesheet">
              </head>
              <body>
              <div class="container mt-5">
                 <h2>Inscription Administrateur</h2>
                 <div class="alert alert-danger">Veuillez remplir tous les champs.</div>
                 <form method="post">
                     <div class="mb-3">
                        <label class="form-label">Nom d'utilisateur</label>
                        <input type="text" name="username" class="form-control" required>
                     </div>
                     <div class="mb-3">
                        <label class="form-label">Mot de passe</label> 
                        <input type="password" name="password" class="form-control" required> 
                     </div>
                     <button type="submit" class="btn btn-primary">S'incrire</button>
                     <a href="/login" class="btn btn-secondary ms-2">Retour a la connexion</a>
                 </form>
              </div>
              </body>
              </html>
         """)
       try:
           conn = sqlite3.connect(DB_PATH)
           cursor = conn.cursor()
           cursor.execute('SELECT username FROM admins WHERE username = ?', (username,))
           if cursor.fetchone():
              conn.closer()
              return render_template_string("""
                  <!DOCTYPE html>
                  <html>
                  <head>
                      <title> Inscription</title>
                      <meta http-equiv="Content-Security-Policy" content="default-src 'self'; script-src 'self' https.//cdn.jsdelivr.net; style-src 'self' https://cdn.jsdelivr.net; connect-src 'self';">
                      <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dict/css/bootstrap.min.css" rel="stylesheet">
                      <link href="/assets/style.css" rel="stylesheet">
                  </head>
                  <body>
                  <div class="container mt-5">
                     <h2>Inscription Administrateur</h2>
                     <div class="alert alert-danger">Ce nom d'utilisateur existe deja.</div> 
                     <form method="post"> 
                         <div class="mb-3"> 
                            <label class="form-label">Nom d'utilisateur</label> 
                            <input type="text" name="username" class="form-control" required> 
                         </div> 
                         <div class="mb-3"> 
                            <label class="form-label">Mot de passe</label> 
                            <input type="password" name="password" class="form-control" required> 
                         </div>
                         <button type="submit" class="btn btn-primary">S'incrire</button>
                         <a href="/login" class="btn btn-secondary ms-2">Retour a la connexion</a>
                     </form>
                  </div>
                  </body>
                  </html>
               """)

              password_hash = bcrypt.generate_password_hash(password).decode('utf-8')
              cursor.execute('INSERT INTO admins (username, password_hash) VALUES (?, ?)', (username, password_hash))
              conn.commit()
              conn.close()
        return render_template_string("""
            <!DOCTYPE html>
            <html>
            <head>
                <title> Inscription</title>
                <meta http-equiv="Content-Security-Policy" content="default-src 'self'; script-src 'self' https.//cdn.jsdelivr.net; style-src 'self' https://cdn.jsdelivr.net; connect-src 'self';">
                <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dict/css/bootstrap.min.css" rel="stylesheet">
                <link href="/assets/style.css" rel="stylesheet">
            </head>
            <body>
            <div class="container mt-5">
                 <h2>Inscription Administrateur</h2>
                 <div class="alert alert-danger">Inscription reussie ! Veuillez vous connecter.</div> 
                 <a href="/login" class="btn btn-primary">Allez a la connexion</a>
            </div>
            </body>
            </html>
         """)
        except Exception as e:
           print(f"Erreur lors de l'inscription : {e}")
           return render_template_string("""
             <!DOCTYPE html>
              <html>
              <head>
                  <title> Inscription</title>
                  <meta http-equiv="Content-Security-Policy" content="default-src 'self'; script-src 'self' https.//cdn.jsdelivr.net; sryle-src 'self' https://cdn.jsdelivr.net; connect-src 'self';">
                  <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dict/css/bootstrap.min.css" rel="stylesheet">
                  <link href="/assets/style.css" rel="stylesheet">
              </head>
              <body>
              <div class="container mt-5">
                 <h2>Inscription Administrateur</h2>
                 <div class="alert alert-danger">Erreur lors de l'inscription. Veuillez reessayer.</div>
                 <form method="post">
                     <div class="mb-3">
                        <label class="form-label">Nom d'utilisateur</label>
                        <input type="text" name="username" class="form-control" required>
                     </div>
                     <div class="mb-3">
                        <label class="form-label">Mot de passe</label> 
                        <input type="password" name="password" class="form-control" required> 
                     </div>
                     <button type="submit" class="btn btn-primary">S'incrire</button>
                     <a href="/login" class="btn btn-secondary ms-2">Retour a la connexion</a>
                 </form>
              </div>
              </body>
              </html>
           """)

         return render_template_string("""
             <!DOCTYPE html>
             <html>
             <head>
                 <title> Inscription</title>
                 <meta http-equiv="Content-Security-Policy" content="default-src 'self'; script-src 'self' https.//cdn.jsdelivr.net; style-src 'self' https://cdn.jsdelivr.net; connect-src 'self';">
                 <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dict/css/bootstrap.min.css" rel="stylesheet">
                 <link href="/assets/style.css" rel="stylesheet">
             </head>
             <body>
             <div class="container mt-5">
                <h2>Inscription Administrateur</h2>
                <form method="post"> 
                    <div class="mb-3"> 
                       <label class="form-label">Nom d'utilisateur</label> 
                       <input type="text" name="username" class="form-control" required> 
                    </div> 
                    <div class="mb-3"> 
                       <label class="form-label">Mot de passe</label> 
                       <input type="password" name="password" class="form-control" required> 
                    </div>
                    <button type="submit" class="btn btn-primary">S'incrire</button>
                    <a href="/login" class="btn btn-secondary ms-2">Retour a la connexion</a>
                </form>
             </div>
             </body>
             </html>
          """)

# Page de connexion Flask
@server.route('/login', methods=['GET','POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        if verify_credentials(username, password):
            session['logged_in'] = True
            session['username'] = username
            return redirect('/dashboard')
        else:
            return render_template_string("""
                <!DOCTYPE html>
                <html>
                <head>
                    <title>Connexion</title>
                    <meta http-equiv="Content-Security-Policy" content="default-src 'self'; script-src 'self' https.//cdn.jsdelivr.net; style-src 'self' https://cdn.jsdelivr.net; connect-src 'self';">
                    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dict/css/bootstrap.min.css" rel="stylesheet">
                    <link href="/assets/style.css" rel="stylesheet">
                </head>
                <body>
                <div class="container mt-5">
                   <h2>Connexion Administrateur</h2>
                   <div class="alert alert-danger">Identifiants incorrects.</div>
                   <form method="post"> 
                       <div class="mb-3"> 
                          <label class="form-label">Nom d'utilisateur</label> 
                          <input type="text" name="username" class="form-control" required> 
                       </div> 
                       <div class="mb-3"> 
                          <label class="form-label">Mot de passe</label> 
                          <input type="password" name="password" class="form-control" required> 
                       </div>
                       <button type="submit" class="btn btn-primary">Se connecter</button>
                       <a href="/signup" class="btn btn-secondary ms-2">S'inscrire</a>
                   </form>
                </div>
                </body>
                </html>
             """)
      return render_template_string("""
          <!DOCTYPE html>
          <html>
          <head>
              <title>Connexion</title>
              <meta http-equiv="Content-Security-Policy" content="default-src 'self'; script-src 'self' https.//cdn.jsdelivr.net; style-src 'self' https://cdn.jsdelivr.net; connect-src 'self';">
              <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dict/css/bootstrap.min.css" rel="stylesheet">
              <link href="/assets/style.css" rel="stylesheet">
          </head>
          <body>
          <div class="container mt-5">
             <h2>Connexion Administrateur</h2>
             <form method="post"> 
                 <div class="mb-3"> 
                    <label class="form-label">Nom d'utilisateur</label> 
                    <input type="text" name="username" class="form-control" required> 
                 </div>
                 <div class="mb-3"> 
                    <label class="form-label">Mot de passe</label> 
                    <input type="password" name="password" class="form-control" required> 
                 </div>
                 <button type="submit" class="btn btn-primary">Se connecter</button>
                 <a href="/signup" class="btn btn-secondary ms-2">S'inscrire</a>
             </form>
             </div>
             </body>
             </html>
         """)
# Deconnexion 
@server.route('/logout')
def logout():
    session.pop('logged_in', None)
    session.pop('username', None)
    return redirect('/login')

# Proteger la route Dash
@server.route('/dashboard')
def dashboard():
    if not session.get('logged_in'):
       return redirect('/login')
    return app.index() 


#Layout principal de Dash 
def create_layout():
    return html.Div([
        dcc.Location(id='url', refresh=False),
        html.Div(id='page-content')
    ])

app.layout = create_layout()

# Page principale avec les plateformes
def main_page():
    platforms = ['OFPPT Academy', 'OFPPT Langues', 'ScholarVox', 'Electude']
    platform_cards = [
        dbc.Card([
            dbc.CardBody([
                html.H5(platform, className="card-title"),
                html.P("Cliquez pour voir les logs et anomalies.", className="card-text"),
                dcc.Link("Voir details", href=f"/platform/{platform.replace(' ', '_')}". className="btn btn-primary")
            ])
        ], className="mb-3 platform-card"} for platform in platforms
    ]
    return dbc.Container([
        dbc.Row([
            dbc.Col(html.H2("CMC Dashboard"), width=12, className="text-center my-4")
        ]),
        dbc.Row([
            dbc.Col(html.A("Deconnexion", href="/logout", className="btn btn-danger"), width=12, className="text-end")
        ]),
        dbc.Row([
            dbc.Col(card, width=6, lg=3) for card in platform_cards
        ])
    ], fluid=True)

# Fonction pour convertir un graphique Matplotlib en image base64
def fig_to_base64(fig):
    buf = io.BytesIO()
    fig.savefig(buf, format='png', bbox_inches='tight')
    buf.seek(0)
    img_base64 = base64.b64encode(buf.getvalue()).decode('utf-8')
    buf.close()
    return f"data:image/png;base64,{img_base64}"

#Page des details d'une plateforme
def platform_page(platform):
    # Charger les logs
    try:
       with sqlite3.connect(DB_PATH) as conn:
          time_threshold = (datetime.now() - timedelta(hours=1)).strftime('%Y-%m-%d %H:%M:%S')
          query = 'SELECT * FROM logs WHERE platform = ? AND timestamp >= ?'
          df_logs = pd.read_sql_query(query, conn, params=(platform, time_threshold))
          for col in ['first_name', 'last_name', 'birth_date']:
              if col in df_logs.columns:
                 df_logs[col] = df_logs[col].apply(decrypt_data)
       print(f"Logs DataFrame for {platform}: {df_logs.shape}")
    except Exception as e:
        print(f"Erreur lors du chargement des logs : {e} ")
        df_logs = pd.DataFrame()

# Charger les anomalies
try:
   df_anomalies = pd.read_csv(ANOMALIES_CSV)
   df_anomalies = df_anomalies[df_anomalies['platform'] == platform]
   df_anomalies['details'] = df_anomalies['details'].apply(
       lambda x: ' '.join([decrypt_data(word) if word.startswith('g=') else word for word in x.split()])
   )
   print(f"Anomalies DataFrame for {platform}: {df_anomalies.shape}")
except Exception as e:
   print(f"Erreur lors du chargement des anomalies : {e}")
   df_anomalies = pd.DataFrame()


# Chargee les actions
try:
   with sqlite3.connect(DB_PATH) as conn:
      query = 'SELECT * FROM audit_log WHERE details LIKE ?'
      df_actions = pd.read_sql_query(query, conn, params=(f'%{platform}%',))
   print(f"Actions DataFrame for {platform}: {df_actions.shape}")
except Exception as e:
   print(f"Erreur lors du chargement des actions : {e}")
   df_actions = pd.DataFrame()

# Creer l'histogramme des types d'anomalies avec Matplotlib
if not df_anomalies.empty:
    plt.figure(figsize=(6, 3))
    df_anomalies['anomaly_type'].value_counts().plot(kind='bar', color='skyblue')
    plt.title("Repqrtition des types d'anomalies")
    plt.xlabel("Type d'anomalie")
    plt.ylabel("Nombre")
    plt.tight_layout()
    histogram_img = fig_to_base64(plt.gcf())
    plt.close()
else:
    histogram_img = None

# Creer uen courbe temporelle des anomalies avec Matplotlib
if not df_anomalies.empty:
    df_anomalies['timestamp'] = pd.to_datetime(df_anomalies['timestamp'])
    df_time = df_anomalies.groupby(df_anomalies['timestamp'].dt.floor('h')).size().reset_index(name='count')
    plt.figure(figsize=(6, 3))
    plt.plot(df_time['timestamp'], df_time['count'], marker='o', colors='coral')
    plt.title("Evolution des anomalies par heure")
    plt.xlabel("Heure")
    plt.ylabel("Nombre d'anomalies")
    plt.xticks(rotation=45)
    plt.tight_layout()
    histogram_img = fig_to_base64(plt.gcf())
    plt.close()
else:
    timeline_img = None

return dbc.Container([
    dbc.Row([
        dbc.Col(html.H2(f"Plateform : {platform}"), width=12, className="text-center my-4")
    ]),
    dbc.Row([
        dbc.Col(dcc.Link("Retour", href="/", className="btn btn-secondary"), width=6),
        dbc.Col(html.A("Deconnexion", hred="/logout", className="btn btn-danger"), width=6, className="text-end")
    ]),
    dbc.Row([
        dbc.Col([
            html.H4("Logs recents (derniere heure)"),
            dash_table.DataTable(
                data=df_logs.to_dict('records'),
                columns=[{'name': col, 'id': col} for col in df_logs.columns],
                style_table={'overflowX': 'auto'},
                page_size=10,
                style_cell={'textAlign': 'left', 'padding': '8px'},
                style_header={'backgroundColor': '#2c3e50', 'color': 'white', 'fontWeight': 'bold'}
            )
        ], width=12)
    ], className="my-4"),
    dbc.Row([
        dbc.Col([
            html.H4("Anomalies detectees"),
            dash_table.DataTable(
                data=df_anomalies.to_dict('records'),
                columns=[{'name': col, 'id': col} for col in df_logs.columns],
                style_table={'overflowX': 'auto'},
                page_size=10,
                style_cell={'textAlign': 'left', 'padding': '8px'},
                style_header={'backgroundColor': '#2c3e50', 'color': 'white', 'fontWeight': 'bold'}
            )
        ], width=12)
    ], className="my-4"),
    dbc.Row([
        dbc.Col([
            html.H4("Historiique des actions"),
            dash_table.DataTable(
                data=df_anomalies.to_dict('records'),
                columns=[{'name': col, 'id': col} for col in df_logs.columns],
                style_table={'overflowX': 'auto'},
                page_size=10,
                style_cell={'textAlign': 'left', 'padding': '8px'},
                style_header={'backgroundColor': '#2c3e50', 'color': 'white', 'fontWeight': 'bold'}
            )
        ], width=12)
    ], className="my-4"),
    dbc.Row([
        dbc.Col([
            html.H4("Visualisations"),
            html.Img(src=histogram_img, className="matplotlib-graph", style={'width': '100%', 'height': '250px'}) if histogram_img else html.P("Aucune anomalie detectee")
        ], width=6),
        dbc.Col([
            html.H4("Evolution temporelle"),
            html.Img(src=histogram_img, className="matplotlib-graph", style={'width': '100%', 'height': '250px'}) if timeline_img else html.P("Aucune anomalie detectee")
        ], width=6),
    ], classeName="my-4")
], fluid=True)

# Callback pour gerer la navigation
@app.callback(
    Output('page-content', 'children'),
    [Input('url', 'pathname')]
)
def display_page(pathname):
    if pathname == '/':
       return main_page()
    elif pathname.startswith('/platform/'):
         platform = pathname.split('/platform/')[1].replace('_', ' ')
         return platform_page(platform)
    else:
        return main_page()

# Lancer l'application
if __name__ == "__main__":
    server.run(host='0.0.0.0', port=8050, debug=True)


