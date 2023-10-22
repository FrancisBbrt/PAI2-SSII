import socket
import json
import sqlite3
import random
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, hmac
import time

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

def generate_random_messages(n):
    messages = []
    for _ in range(n):
        destino = random.randint(1000000000000000, 9999999999999999)  # Cuentas de 16 dígitos
        cantidad = round(random.uniform(10.0, 5000.0), 2)  # Cantidad entre 10 y 5000 con dos decimales
        messages.append({'origen': 1234567887654321, 'destino': destino, 'cantidad': cantidad})
    return messages

# Establecer conexión con el servidor
with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.connect((HOST, PORT))

    number_messages = 10 # Define el número de mensajes que quieras generar
    messages_to_send = generate_random_messages(number_messages)

    print(f"\nGenerando {number_messages} messages aleatorias con diferentes comportamientos, 2 segundos para empezar\n")
    time.sleep(2)

    for message in messages_to_send:
        try:
            nonce_request = "nonce_peticion"
            s.sendall(nonce_request.encode())

            nonce_response = s.recv(1024).decode()
            store_nonce(nonce_response)

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
                print("Mensaje - Usando un nonce ya utilizado.")
                used_nonce = get_used_nonce()
                if used_nonce:
                    data_object['nonce'] = used_nonce
            elif dice == 2:
                print("Mensaje - Usando un HMAC modificado aleatorio.")
                data_object['hmac'] = "random_hmac_value_{}".format(random.randint(1, 10000))
            elif dice == 3:
                print("Mensaje - Usando un nonce ya utilizado y un HMAC modificado aleatorio.")
                used_nonce = get_used_nonce()
                if used_nonce:
                    data_object['nonce'] = used_nonce
                data_object['hmac'] = "random_hmac_value_{}".format(random.randint(1, 10000))
            else:
                print(f"Mensaje - Comportamiento normal.")

            s.sendall(json.dumps(data_object).encode())

            if dice not in [1, 3]:  # Actualizamos el nonce solo si no hemos utilizado uno antiguo
                update_nonce_count(nonce_response)

            data = s.recv(1024)
            print(f"Received from server: {data.decode()}\n")

            time.sleep(0.5)

        except Exception as e:
            print(f"Error: {e}")
            break

print("Client has exited.")
conn.close()
