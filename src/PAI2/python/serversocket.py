# Importar las bibliotecas necesarias
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

# Inicializar conexión con la base de datos y crear tabla si no existe
conn = sqlite3.connect('nonces.db')
cursor = conn.cursor()
cursor.execute('''
CREATE TABLE IF NOT EXISTS nonces (
    nonce TEXT,
    count INTEGER
)''')
conn.commit()

# Función para generar un nonce único
def generate_nonce():
    while True:
        nonce = secrets.token_hex(16)
        cursor.execute("SELECT count FROM nonces WHERE nonce=?", (nonce,))
        if cursor.fetchone() is None:
            break

    # Guardar el nonce en la base de datos
    with conn:
        cursor.execute("INSERT INTO nonces (nonce, count) VALUES (?, ?)", (nonce, 0))
    return nonce

# Función para verificar y actualizar el nonce en la base de datos
def check_and_update_nonce(nonce):
    cursor.execute("SELECT count FROM nonces WHERE nonce=?", (nonce,))
    result = cursor.fetchone()
    if result:
        count = result[0]
        if count == 0:
            with conn:
                cursor.execute("UPDATE nonces SET count=? WHERE nonce=?", (1, nonce))
            return True
        else:
            return False
    else:
        return False

# Función para verificar el HMAC recibido
def verify_hmac(data, received_hmac):
    h = hmac.HMAC(SECRET_KEY, hashes.SHA256(), backend=default_backend())
    h.update(data.encode())
    try:
        h.verify(bytes.fromhex(received_hmac))
        return True
    except:
        return False

# Función para manejar la comunicación con un cliente
def handle_client(conn, addr):
    # Crear una nueva conexión y cursor específicamente para este hilo
    conn_db = sqlite3.connect('nonces.db')
    cursor = conn_db.cursor()
    
    # Asegurarse de que la tabla exista
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS nonces (
        nonce TEXT,
        count INTEGER
    )''')
    conn_db.commit()

    # Generar un nonce único
    def generate_nonce():
        while True:
            nonce = secrets.token_hex(16)
            cursor.execute("SELECT count FROM nonces WHERE nonce=?", (nonce,))
            if cursor.fetchone() is None:
                break

        # Guardar el nonce en la base de datos
        with conn_db:
            cursor.execute("INSERT INTO nonces (nonce, count) VALUES (?, ?)", (nonce, 0))
        return nonce

    # Verificar y actualizar el nonce en la base de datos
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

            # Si el cliente solicita un nonce
            if received_message == "nonce_peticion":
                nonce = generate_nonce()
                conn.sendall(nonce.encode())
            else:
                try:
                    # Decodificar el mensaje JSON
                    json_data = json.loads(received_message)
                    message = json_data.get('message', '')
                    hmac_received = json_data.get('hmac', '')

                    # Imprimir el HMAC recibido
                    print(f"HMAC received from {addr}: {hmac_received}")

                    # Verificar el HMAC
                    if not verify_hmac(json.dumps({'message': message, 'nonce': json_data.get('nonce')}), hmac_received):
                        conn.sendall("Invalid HMAC!".encode())
                        continue

                    # Verificar y actualizar el nonce
                    nonce = json_data.get('nonce', '')
                    if not check_and_update_nonce(nonce):
                        conn.sendall("Possible Repeat Attack".encode())
                    else:
                        # Imprimir el mensaje recibido
                        print(f"Message received from {addr}: {message}")
                        conn.sendall(data)
                except json.JSONDecodeError:
                    conn.sendall("Invalid JSON data received".encode())

    print(f"Connection with {addr} closed")
    
    # Cerrar la conexión con la base de datos al finalizar la función
    conn_db.close()


# Iniciar el servidor y esperar conexiones de clientes
with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.bind((HOST, PORT))
    s.listen()
    print(f"Listening on {HOST}:{PORT}")

    # Aceptar conexiones de clientes y manejarlas en hilos separados
    while True:
        conn, addr = s.accept()
        client_thread = threading.Thread(target=handle_client, args=(conn, addr))
        client_thread.start()

# Cerrar la conexión con la base de datos al finalizar la ejecución del programa
conn.close()
