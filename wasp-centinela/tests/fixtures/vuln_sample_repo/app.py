"""App de prueba deliberadamente vulnerable — usada solo para demostrar las guardias de WASP.
NO usar como referencia de código real. NO desplegar."""

import sqlite3
import subprocess

# Secreto hardcodeado (para que Gitleaks lo detecte) — NO es un ejemplo de la doc oficial de AWS
# (los ejemplos oficiales estan en la allowlist de la mayoria de escaneres), es un valor
# generado al azar con el mismo formato para que dispare la regla real.
AWS_ACCESS_KEY_ID = "AKIA3XM2K9PQRSTUVWXY"
AWS_SECRET_ACCESS_KEY = "aB3dEfGh9kLmNoPqRsTu1234567890ZzYyXxWwVv"


def get_user(username):
    """Inyección SQL deliberada: concatenación directa del input del usuario."""
    conn = sqlite3.connect("app.db")
    cursor = conn.cursor()
    query = "SELECT * FROM users WHERE username = '" + username + "'"
    cursor.execute(query)
    return cursor.fetchall()


def run_diagnostic(hostname):
    """Inyección de comandos deliberada: input del usuario pasado directo a shell=True."""
    result = subprocess.run("ping -n 1 " + hostname, shell=True, capture_output=True)
    return result.stdout


def load_config(path):
    """Deserialización insegura deliberada."""
    import pickle
    with open(path, "rb") as f:
        return pickle.load(f)
