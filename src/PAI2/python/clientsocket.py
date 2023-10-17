# Importar las bibliotecas necesarias
import socket
import json
import sqlite3
import random
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, hmac

# Definir el HOST y el PORT para la conexión del cliente al servidor
HOST = "127.0.0.1"
PORT = 3030

# Clave secreta utilizada para generar y verificar el HMAC
SECRET_KEY = b"this_is_a_super_secret_key"

# Inicializar la base de datos
conn = sqlite3.connect('client_nonces.db')
cursor = conn.cursor()
cursor.execute('''
CREATE TABLE IF NOT EXISTS nonces (
    nonce TEXT PRIMARY KEY,
    count INTEGER
)''')
conn.commit()

def get_used_nonce():
    cursor.execute("SELECT nonce FROM nonces WHERE count=1")
    nonces = cursor.fetchall()
    if nonces:
        return random.choice(nonces)[0]
    return None

def store_nonce(nonce):
    with conn:
        cursor.execute("INSERT OR IGNORE INTO nonces (nonce, count) VALUES (?, 0)", (nonce,))

def update_nonce_count(nonce):
    with conn:
        cursor.execute("UPDATE nonces SET count=1 WHERE nonce=?", (nonce,))

def generate_hmac(data):
    h = hmac.HMAC(SECRET_KEY, hashes.SHA256(), backend=default_backend())
    h.update(data.encode())
    return h.finalize().hex()

# Establecer conexión con el servidor
with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.connect((HOST, PORT))

    while True:
        try:
            nonce_request = "nonce_peticion"
            s.sendall(nonce_request.encode())

            nonce_response = s.recv(1024).decode()
            store_nonce(nonce_response)

            origen = 1234567887654321
            destino = input("Introduce el numero de cuenta destino: ")
            if destino.lower() == "exit":
                break

            cantidad = input("Introduce la cantidad a transferir: ")
            message = {
                'origen': origen,
                'destino':destino,
                'cantidad':cantidad
            }

            json_message = json.dumps(message)
            mac = generate_hmac(json_message)

            data_object = {
                'message': message,
                'nonce': nonce_response,
                'hmac': mac
            }

            # Factor de aleatoriedad
            dice = random.randint(1, 6)
            if dice == 1:
                print("Resultado del dado: 1 - Usando un nonce ya utilizado.")
                used_nonce = get_used_nonce()
                if used_nonce:
                    data_object['nonce'] = used_nonce
            elif dice == 2:
                print("Resultado del dado: 2 - Usando un HMAC aleatorio.")
                data_object['hmac'] = "random_hmac_value_{}".format(random.randint(1, 10000))
            elif dice == 3:
                print("Resultado del dado: 3 - Usando un nonce ya utilizado y un HMAC aleatorio.")
                used_nonce = get_used_nonce()
                if used_nonce:
                    data_object['nonce'] = used_nonce
                data_object['hmac'] = "random_hmac_value_{}".format(random.randint(1, 10000))
            else:
                print(f"Resultado del dado: {dice} - Comportamiento normal.")

            s.sendall(json.dumps(data_object).encode())

            if dice not in [1, 3]:  # Actualizamos el nonce solo si no hemos utilizado uno antiguo
                update_nonce_count(nonce_response)

            data = s.recv(1024)
            print(f"Received from server: {data.decode()}")

        except Exception as e:
            print(f"Error: {e}")
            break

print("Client has exited.")
conn.close()