import socket
import threading
import secrets
import sqlite3
import json

HOST = "127.0.0.1"  # Standard loopback interface address (localhost)
PORT = 3030  # Port to listen on (non-privileged ports are > 1023)

# Crear e inicializar la base de datos
conn = sqlite3.connect('nonces.db')
cursor = conn.cursor()
cursor.execute('''CREATE TABLE IF NOT EXISTS nonces (nonce TEXT)''')
conn.commit()

def generate_nonce():
    """Function to generate a random nonce."""
    nonce = secrets.token_hex(16)

    # Guardar el nonce en la base de datos
    with conn:
        cursor.execute("INSERT INTO nonces (nonce) VALUES (?)", (nonce,))
    return nonce

def check_nonce_in_db(nonce):
    """Check if a nonce exists in the database."""
    cursor.execute("SELECT nonce FROM nonces WHERE nonce=?", (nonce,))
    result = cursor.fetchone()
    return result is not None

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
                try:
                    json_data = json.loads(received_message)
                    nonce = json_data.get('nonce', '')
                    if check_nonce_in_db(nonce):
                        conn.sendall("Posible Repeat Attack".encode())
                    else:
                        print(f"Received from {addr}: {received_message}")
                        conn.sendall(data)
                except json.JSONDecodeError:
                    conn.sendall("Invalid JSON data received".encode())
                    
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

# No olvides cerrar la conexión a la base de datos cuando ya no la necesites
conn.close()
