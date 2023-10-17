import socket
import threading
import secrets
import sqlite3
import json
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, hmac

# Definir el HOST y el PORT para escuchar conexiones entrantes
HOST = "127.0.0.1"
PORT = 3030

# Clave secreta utilizada para generar y verificar el HMAC
SECRET_KEY = b"this_is_a_super_secret_key"

# Funciones globales (sin cambios)
def verify_hmac(data, received_hmac):
    h = hmac.HMAC(SECRET_KEY, hashes.SHA256(), backend=default_backend())
    h.update(data.encode())
    try:
        h.verify(bytes.fromhex(received_hmac))
        return True
    except:
        return False

# Función para asegurar que la tabla 'kpis' exista
def ensure_kpis_table_exists(cursor):
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS kpis (
        id INTEGER PRIMARY KEY,
        message TEXT,
        hmac TEXT,
        nonce TEXT,
        integrity BOOLEAN,
        reason TEXT
    )''')

# Función para manejar la comunicación con un cliente
def handle_client(conn, addr):
    conn_db = sqlite3.connect('nonces.db')
    cursor = conn_db.cursor()

    conn_kpi_local = sqlite3.connect('dbKPI.db')
    cursor_kpi_local = conn_kpi_local.cursor()

    ensure_kpis_table_exists(cursor_kpi_local)

    cursor.execute('''
    CREATE TABLE IF NOT EXISTS nonces (
        nonce TEXT,
        count INTEGER
    )''')
    conn_db.commit()

    def generate_nonce():
        while True:
            nonce = secrets.token_hex(16)
            cursor.execute("SELECT count FROM nonces WHERE nonce=?", (nonce,))
            if cursor.fetchone() is None:
                break

        with conn_db:
            cursor.execute("INSERT INTO nonces (nonce, count) VALUES (?, ?)", (nonce, 0))
        return nonce

    def check_and_update_nonce(nonce):
        cursor.execute("SELECT count FROM nonces WHERE nonce=?", (nonce,))
        result = cursor.fetchone()
        if result:
            count = result[0]
            if count == 0:
                with conn_db:
                    cursor.execute("UPDATE nonces SET count=? WHERE nonce=?", (1, nonce))
                return True
            else:
                return False
        else:
            return False

    print(f"Connected by {addr}")
    with conn:
        while True:
            data = conn.recv(1024)
            if not data:
                break

            received_message = data.decode()
            if received_message == "nonce_peticion":
                nonce = generate_nonce()
                conn.sendall(nonce.encode())
            else:
                integrity = True
                reasons = []

                try:
                    json_data = json.loads(received_message)
                    message = json_data.get('message', {})
                    nonce_received = json_data.get('nonce', '')
                    hmac_received = json_data.get('hmac', '')

                    print(f"HMAC received from {addr}: {hmac_received}")

                    if not verify_hmac(json.dumps(message), hmac_received):
                        reasons.append("Invalid HMAC!")
                        integrity = False

                    if not check_and_update_nonce(nonce_received):
                        reasons.append("Possible Repeat Attack")
                        integrity = False

                    if integrity:
                        print(f"Message received from {addr}: {message}")
                        conn.sendall(data)
                    else:
                        response_msg = "; ".join(reasons)
                        conn.sendall(response_msg.encode())

                except json.JSONDecodeError:
                    reasons.append("Invalid JSON data received")
                    integrity = False
                    conn.sendall(reasons[-1].encode())

                reason_string = "; ".join(reasons)

                with conn_kpi_local:
                    cursor_kpi_local.execute("INSERT INTO kpis (message, hmac, nonce, integrity, reason) VALUES (?, ?, ?, ?, ?)",
                                (json.dumps(message), hmac_received, nonce_received, integrity, reason_string))


        print(f"Connection with {addr} closed")
        conn_db.close()
        conn_kpi_local.close()

        
with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.bind((HOST, PORT))
    s.listen()
    print(f"Listening on {HOST}:{PORT}")

    while True:
        conn, addr = s.accept()
        client_thread = threading.Thread(target=handle_client, args=(conn, addr))
        client_thread.start()
