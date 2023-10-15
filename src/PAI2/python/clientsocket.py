# Importar las bibliotecas necesarias
import socket
import json
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, hmac

# Definir el HOST y el PORT para la conexión del cliente al servidor
HOST = "127.0.0.1"
PORT = 3030

# Clave secreta utilizada para generar y verificar el HMAC
SECRET_KEY = b"this_is_a_super_secret_key"

# Función para generar el HMAC de los datos
def generate_hmac(data):
    # Iniciar el HMAC con la clave secreta y el algoritmo SHA256
    h = hmac.HMAC(SECRET_KEY, hashes.SHA256(), backend=default_backend())
    # Actualizar el HMAC con los datos que queremos autenticar
    h.update(data.encode())
    # Finalizar y retornar el HMAC en formato hexadecimal
    return h.finalize().hex()

# Establecer conexión con el servidor
with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.connect((HOST, PORT))

    # Bucle principal para enviar y recibir mensajes del servidor
    while True:
        try:
            # Solicitar nonce al servidor
            nonce_request = "nonce_peticion"
            s.sendall(nonce_request.encode())

            # Esperar la respuesta del servidor con el nonce
            nonce_response = s.recv(1024).decode()

            # Recoger datos de entrada del usuario para la transacción
            origen = 1234567887654321
            destino = input("Introduce el numero de cuenta destino: ")
            
            # Si el usuario introduce "exit", se sale del bucle
            if destino.lower() == "exit":
                break

            cantidad = input("Introduce la cantidad a transferir: ")
            message = (origen, destino, cantidad)

            # Crear un objeto con el mensaje y el nonce para enviar al servidor
            data_object = {
                'message': message,
                'nonce': nonce_response
            }

            # Convertir el objeto a un string JSON y generar el HMAC para ese mensaje
            json_message = json.dumps(data_object)
            mac = generate_hmac(json_message)

            # Añadir el HMAC al objeto antes de enviarlo al servidor
            data_object['hmac'] = mac
            s.sendall(json.dumps(data_object).encode())

            # Esperar la respuesta del servidor y mostrarla
            data = s.recv(1024)
            print(f"Received from server: {data.decode()}")

        # Manejar cualquier excepción que pueda surgir y mostrar el error
        except Exception as e:
            print(f"Error: {e}")
            break

# Indicar que el cliente ha finalizado su ejecución
print("Client has exited.")
