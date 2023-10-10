import socket
import threading
import secrets

HOST = "127.0.0.1"  # Standard loopback interface address (localhost)
PORT = 3030  # Port to listen on (non-privileged ports are > 1023)

def generate_nonce():
    """Function to generate a random nonce."""
    return secrets.token_hex(16)

def handle_client(conn, addr, nonce):
    """Function to handle communication with a client."""
    print(f"Connected by {addr}")
    with conn:
        while True:
            data = conn.recv(1024)
            if not data:
                break
            print(f"Received from {addr}: {data.decode()}")  # Imprimir los mensajes recibidos
            conn.sendall(data)  # Aquí simplemente se devuelve el mismo mensaje al cliente, pero puedes modificar esto según sea necesario.
    print(f"Connection with {addr} closed")

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.bind((HOST, PORT))
    s.listen()
    print(f"Listening on {HOST}:{PORT}")
    
    while True:  # Infinite loop to keep server running and listening for new connections
        conn, addr = s.accept()
        
        nonce = generate_nonce()  # Generar un nonce
        conn.sendall(nonce.encode())  # Enviar el nonce al cliente inmediatamente después de aceptar la conexión
        
        # Start a new thread to handle the client connection
        client_thread = threading.Thread(target=handle_client, args=(conn, addr, nonce))
        client_thread.start()
