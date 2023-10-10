import socket
import threading
import secrets

HOST = "127.0.0.1"  # Standard loopback interface address (localhost)
PORT = 3030  # Port to listen on (non-privileged ports are > 1023)

def generate_nonce():
    """Function to generate a random nonce."""
    return secrets.token_hex(16)

def handle_client(conn, addr):
    """Function to handle communication with a client."""
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
                print(f"Received from {addr}: {received_message}")
                conn.sendall(data)  # En este caso, simplemente se devuelve el mismo mensaje al cliente.
    print(f"Connection with {addr} closed")

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.bind((HOST, PORT))
    s.listen()
    print(f"Listening on {HOST}:{PORT}")
    
    while True:  # Infinite loop to keep server running and listening for new connections
        conn, addr = s.accept()

        # Start a new thread to handle the client connection
        client_thread = threading.Thread(target=handle_client, args=(conn, addr))
        client_thread.start()
