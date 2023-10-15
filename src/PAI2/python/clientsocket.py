import socket
import json

HOST = "127.0.0.1"  # The server's hostname or IP address
PORT = 3030  # The port used by the server

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.connect((HOST, PORT))
    

    
    while True:  # Infinite loop to keep client running and sending data
        
        # Enviar una solicitud de nonce inmediatamente después de establecer la conexión
        nonce_request = "nonce_peticion"
        s.sendall(nonce_request.encode())

        # Esperar y recibir el nonce del servidor
        nonce_response = s.recv(1024).decode()
        origen = 1234567887654321
        destino = input("Introduce el numero de cuenta destino: ")
        cantidad = input("Introduce la cantidad a transferir: ")
        message = (origen, destino, cantidad)
        
        if message.lower() == "exit":
            break

        # Combinar el mensaje y el nonce en un objeto JSON
        data_object = {
            'message': message,
            'nonce': nonce_response
        }
        json_message = json.dumps(data_object)
        s.sendall(json_message.encode())
        
        data = s.recv(1024)
        print(f"Received from server: {data.decode()}")

print("Client has exited.")
