import os
import sys
import time
from multiprocessing import Process
import logging

# Configuration du logging pour le script principal
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('cmc_anomaly_detection.log'),
        logging.StreamHandler(sys.stdout)
    ]
)

# Chemins des scripts
SCRIPT_DIR = os.path.join(os.getcwd(), 'scripts')
GENERATE_LOGS_SCRIPT = os.path.join(SCRIPT_DIR, 'generate_logs.py')
DETECT_ANOMALIES_SCRIPT = os.path.join(SCRIPT_DIR, 'detect_anomalies.py')
DASHBOARD_SCRIPT = os.path.join(SCRIPT_DIR, 'new_dash.py')

def run_script(script_path, args=None):
    """Exécute un script Python donné avec des arguments optionnels."""
    try:
        cmd = f'python {script_path}' if args is None else f'python {script_path} {" ".join(args)}'
        logging.info(f"Démarrage du script : {cmd}")
        os.system(cmd)
    except Exception as e:
        logging.error(f"Erreur lors de l'exécution de {script_path}: {e}")

def check_scripts_exist():
    """Vérifie si tous les scripts existent."""
    for script in [GENERATE_LOGS_SCRIPT, DETECT_ANOMALIES_SCRIPT, DASHBOARD_SCRIPT]:
        if not os.path.exists(script):
            logging.error(f"Le script {script} n'existe pas.")
            sys.exit(1)

def run_periodic_scripts():
    """Exécute les scripts generate_logs.py et detect_anomalies.py toutes les 10 minutes."""
    while True:
        # Créer des processus pour les scripts périodiques
        processes = [
            Process(target=run_script, args=(GENERATE_LOGS_SCRIPT, ['--append'])),
            Process(target=run_script, args=(DETECT_ANOMALIES_SCRIPT, None))
        ]

        # Démarrer les processus périodiques
        for process in processes:
            process.start()
            logging.info(f"Processus périodique démarré pour {process}")

        # Attendre que les processus périodiques se terminent
        for process in processes:
            process.join()

        # Attendre 10 minutes avant la prochaine exécution
        logging.info("Attente de 10 minutes avant la prochaine exécution des scripts périodiques.")
        time.sleep(600)

def main():
    """Fonction principale pour exécuter les scripts."""
    # Vérifier l'existence des scripts
    check_scripts_exist()

    # Lancer le script de l'interface web dans un processus séparé
    dashboard_process = Process(target=run_script, args=(DASHBOARD_SCRIPT, None))
    dashboard_process.start()
    logging.info(f"Processus de l'interface web démarré pour {dashboard_process}")

    # Lancer les scripts périodiques dans un autre processus
    periodic_process = Process(target=run_periodic_scripts)
    periodic_process.start()
    logging.info(f"Processus périodique démarré pour {periodic_process}")

    # Surveiller les processus
    try:
        while True:
            # Vérifier si le processusRetriever de l'interface web est toujours actif
            if not dashboard_process.is_alive():
                logging.warning("Le processus de l'interface web s'est arrêté.")
                logging.info("Arrêt de tous les processus.")
                dashboard_process.terminate()
                periodic_process.terminate()
                sys.exit(1)

            # Vérifier si le processus périodique est toujours actif
            if not periodic_process.is_alive():
                logging.warning("Le processus périodique s'est arrêté.")
                logging.info("Arrêt de tous les processus.")
                dashboard_process.terminate()
                periodic_process.terminate()
                sys.exit(1)

            time.sleep(5)  # Vérifier toutes les 5 secondes
    except KeyboardInterrupt:
        logging.info("Arrêt demandé par l'utilisateur.")
        dashboard_process.terminate()
        periodic_process.terminate()
        logging.info("Tous les processus ont été arrêtés.")

if __name__ == "__main__":
    main()