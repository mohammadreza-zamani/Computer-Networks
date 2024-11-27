import socket
import threading
from cryptography.hazmat.primitives import serialization

class Server:
    def __init__(self, host, port):
        self.host = host
        self.port = port
        self.clients = {}
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.bind((self.host, self.port))
        self.server_socket.listen(5)
        print(f"Server listening on {self.host}:{self.port}")

    def broadcast_user_list(self):
        users = "|".join(self.clients.keys()).encode()
        for client_socket, _ in self.clients.values():
            client_socket.sendall(b"USERS:" + users)

    def handle_client(self, client_socket, client_address):
        try:
            name = client_socket.recv(1024).decode()
            print(f"New connection: {name} from {client_address}")
            public_key_pem = client_socket.recv(4096)
            self.clients[name] = (client_socket, public_key_pem)
            self.broadcast_user_list()

            while True:
                data = client_socket.recv(4096)
                if not data:
                    break
                if data == b"DISCONNECT":
                    print(f"{name} has disconnected.")
                    break
                if data.startswith(b"GET_KEY:"):
                    target_name = data[8:].decode()
                    if target_name in self.clients:
                        target_key = self.clients[target_name][1]
                        client_socket.sendall(b"KEY:" + target_key)
                elif data.startswith(b"MSG:"):
                    target_name, message = data[4:].split(b":", 1)
                    target_name = target_name.decode()
                    if target_name in self.clients:
                        target_socket, _ = self.clients[target_name]
                        sender_message = f"{name}: ".encode() + message
                        target_socket.sendall(b"MSG:" + sender_message)

        except Exception as e:
            print(f"Error with client {client_address}: {e}")
        finally:
            # Remove client from the active list
            for client_name, (sock, _) in list(self.clients.items()):
                if sock == client_socket:
                    del self.clients[client_name]
                    break
            self.broadcast_user_list()
            client_socket.close()

    def start(self):
        print("Server is running...")
        while True:
            client_socket, client_address = self.server_socket.accept()
            threading.Thread(target=self.handle_client, args=(client_socket, client_address)).start()


if __name__ == "__main__":
    server = Server("127.0.0.1", 12353)
    server.start()
