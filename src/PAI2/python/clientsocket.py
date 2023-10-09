import socket

HOST = "127.0.0.1"  # The server's hostname or IP address
PORT = 3030  # The port used by the server

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.connect((HOST, PORT))
    
    while True:  # Infinite loop to keep client running and sending data
        message = input("Enter your message (or 'exit' to quit): ")
        
        if message.lower() == "exit":
            break
        
        s.sendall(message.encode())
        data = s.recv(1024)
        print(f"Received from server: {data.decode()}")

print("Client has exited.")
