CMC_GUID

Description

CMC_GUID est une application web développée avec Flask et Dash pour surveiller et sécuriser les activités des utilisateurs sur plusieurs plateformes éducatives (OFPPT Academy, OFPPT Langues, ScholarVox, Electude). Elle génère des identifiants uniques, journalise les actions des utilisateurs, détecte automatiquement les anomalies de sécurité, et fournit une interface administrateur interactive pour visualiser les logs, anomalies, et statistiques. Les données sensibles sont chiffrées avec cryptography.fernet, et les mots de passe des administrateurs sont hachés avec flask_bcrypt. Le projet utilise une base de données SQLite et exécute des tâches périodiques via multiprocessing.




_______________________________________________________________________________________________________________



Fonctionnalités

Gestion des utilisateurs : Stockage des informations chiffrées (prénom, nom, date de naissance) dans une base SQLite.

Journalisation : Enregistrement des actions (login, logout, access_resource) avec métadonnées (horodatage, plateforme, IP, statut).

Détection des anomalies : Identification des comportements suspects, tels que :

Échecs de connexion multiples (≥2 en 10 minutes).

Connexions à des heures inhabituelles (0h-6h).

Multiples adresses IP pour un même utilisateur.

Tentatives d'accès non autorisées.

Connexions depuis des IPs suspectes (par exemple, 203.0.113.1).

Blocage automatique : Blocage temporaire des utilisateurs en cas d'anomalies, avec journalisation dans un audit.

Tableau de bord : Interface Dash avec Tailwind CSS pour :

Visualiser les logs récents (dernière heure).

Afficher les anomalies détectées avec graphiques (histogramme des types d'anomalies, courbe temporelle).

Consulter l'historique des actions administratives.

Authentification sécurisée : Connexion et inscription des administrateurs avec hachage des mots de passe via bcrypt.

Génération de logs simulés : Création de données de test avec Faker pour simuler l'activité des utilisateurs.

Exportation des données : Sauvegarde des logs (simulated_logs.csv) et anomalies (anomalies_detected.csv).

Exécution parallèle : Gestion des tâches périodiques (génération de logs, détection d'anomalies) et du tableau de bord via multiprocessing.




______________________________________________________________________________________________________________


Prérequis

Python : Version 3.8 ou supérieure.

Dépendances Python :

flask==2.0.1
flask-bcrypt==1.0.1
dash==2.17.1
dash-bootstrap-components==1.6.0
pandas==2.0.3
cryptography==42.0.8
faker==25.8.0
matplotlib==3.7.2


Navigateur web : Chrome, Firefox, ou équivalent pour le tableau de bord.

Base de données : SQLite (fichier logs.db créé automatiquement).




________________________________________________________________________________________________________________



Installation

Clonez le dépôt :

git clone https://github.com/HalaRami/CMC_Project.git


Accédez au répertoire du projet :

cd cmc-anomaly-detection

Créez un environnement virtuel (recommandé) :

python -m venv venv
source venv/bin/activate  # Sur Windows : venv\Scripts\activate


Installez les dépendances :

pip install -r requirements.txt

Initialisez la base de données et configurez l'authentification :

python scripts/create_database.py
python scripts/setup_auth.py



___________________________________________________________________________________________________________

Utilisation

Initialisation de la base de données : Exécutez create_database.py pour créer les tables SQLite (users, logs, blocked_users, audit_log, admins) et un compte administrateur par défaut (admin / admin123).

=> python scripts/create_database.py


Configuration de l'authentification : Exécutez setup_auth.py pour configurer ou réinitialiser le compte administrateur par défaut.

=> python scripts/setup_auth.py


Lancement de l'application : Exécutez main.py pour démarrer l'application. Ce script lance :

Le tableau de bord Dash (new_dash.py) sur http://localhost:8050.

Des tâches périodiques (toutes les 10 minutes) pour générer des logs (generate_logs.py --append) et détecter des anomalies (detect_anomalies.py).

=> python main.py

Connectez-vous au tableau de bord via http://localhost:8050 avec les identifiants administrateur (admin / admin123 par défaut).



Génération de logs simulés (manuelle) : Utilisez generate_logs.py pour créer des données de test (100 utilisateurs, 50 logs par exécution). Options :

--append : Ajoute des logs sans réinitialiser les utilisateurs.

--continuous : Génère des logs toutes les 30 secondes.

=> python scripts/generate_logs.py
=> python scripts/generate_logs.py --append
=> python scripts/generate_logs.py --continuous

Les logs sont enregistrés dans logs.db et simulated_logs.csv.



Détection des anomalies (manuelle) : Exécutez detect_anomalies.py pour analyser les logs de la dernière heure et enregistrer les anomalies dans anomalies_detected.csv.

=> python scripts/detect_anomalies.py


Inscription d'un nouvel administrateur : Accédez à http://localhost:8050/signup pour créer un compte administrateur.



_______________________________________________________________________________________________________________

Structure du projet

cmc_guid/
├── scripts/
│   ├── create_database.py    # Initialise la base SQLite
│   ├── setup_auth.py         # Configure l'authentification
│   ├── test_auth.py          # Vérifie les identifiants
│   ├── generate_logs.py      # Génère des logs simulés
│   ├── detect_anomalies.py   # Détecte les anomalies
│   ├── new_dash.py           # Tableau de bord Flask/Dash
├── main.py                   # Script principal
├── logs.db                   # Base de données SQLite
├── simulated_logs.csv        # Logs simulés exportés
├── anomalies_detected.csv    # Anomalies détectées exportées
├── encryption_key.key        # Clé de chiffrement
├── requirements.txt          # Dépendances
└── cmc_anomaly_detection.log # Journal des exécutions