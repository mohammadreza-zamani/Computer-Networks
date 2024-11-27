import socket
import threading
from tkinter import Tk, Label, Entry, Button, Text, Listbox, END, messagebox
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes


class Client:
    def __init__(self):
        self.sock = None
        self.name = None
        self.public_key, self.private_key = self.generate_keys()
        self.active_users = {}
        self.gui = None

    def disconnect(self):
        if self.sock:
            try:
                self.sock.sendall(b"DISCONNECT")
                self.sock.close()
            except Exception as e:
                print(f"Error during disconnect: {e}")
            finally:
                self.sock = None
                
    def generate_keys(self):
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )
        public_key = private_key.public_key()
        return public_key, private_key

    def connect(self, host, port, name):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.connect((host, port))
        self.name = name
        self.sock.sendall(name.encode())
        print('name sent to the server')
        self.sock.sendall(self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ))
        threading.Thread(target=self.listen_to_server).start()

    def listen_to_server(self):
        while True:
            try:
                data = self.sock.recv(4096)
                if data.startswith(b"USERS:"):
                    user_list = data[6:].decode().split("|")
                    self.gui.update_user_list(user_list)
                elif data.startswith(b"KEY:"):
                    public_key = serialization.load_pem_public_key(data[4:])
                    self.active_users[self.target_user] = public_key
                elif data.startswith(b"MSG:"):
                    name_index = data[4:].find(b':') + 6
                    sender_name = data[4:name_index].decode()
                    decrypted_message = self.private_key.decrypt(
                        data[name_index:],
                        padding.OAEP(
                            mgf=padding.MGF1(algorithm=hashes.SHA256()),
                            algorithm=hashes.SHA256(),
                            label=None
                        )
                    ).decode()
                    msg = f'{sender_name}{decrypted_message}'
                    self.gui.display_message(msg)
            except Exception as e:
                print(f"Error receiving data: {e}")
                break

    def request_key(self, target_user):
        self.target_user = target_user
        self.sock.sendall(b"GET_KEY:" + target_user.encode())

    def send_message(self, target_user, message):
        if target_user in self.active_users:
            public_key = self.active_users[target_user]
            encrypted_message = public_key.encrypt(
                message.encode(),
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            self.sock.sendall(b"MSG:" + target_user.encode() + b":" + encrypted_message)


class ChatGUI:
    def __init__(self):
        self.client = Client()
        self.target_user = None
        self.window = Tk()
        self.window.title("Secure Chat")
        self.build_gui()

    def build_gui(self):
        Label(self.window, text="Server IP:").grid(row=0, column=0)
        self.server_ip = Entry(self.window)
        self.server_ip.grid(row=0, column=1)
    
        Label(self.window, text="Port:").grid(row=1, column=0)
        self.port = Entry(self.window)
        self.port.grid(row=1, column=1)
    
        Label(self.window, text="Name:").grid(row=2, column=0)
        self.name = Entry(self.window)
        self.name.grid(row=2, column=1)
    
        Button(self.window, text="Connect", command=self.connect).grid(row=3, column=0)
        Button(self.window, text="Disconnect", command=self.disconnect).grid(row=3, column=1)
    
        self.chat_area = Text(self.window, state="disabled", height=15, width=50)
        self.chat_area.grid(row=4, column=0, columnspan=2)
    
        self.message_entry = Entry(self.window, width=40)
        self.message_entry.grid(row=5, column=0)
        Button(self.window, text="Send", command=self.send_message).grid(row=5, column=1)
    
        self.user_list = Listbox(self.window, height=10, width=20)
        self.user_list.grid(row=4, column=2)
        Label(self.window, text="Active Users").grid(row=3, column=2)
        self.user_list.bind("<<ListboxSelect>>", self.select_user)


    def connect(self):
        try:
            host = self.server_ip.get()
            port = int(self.port.get())
            name = self.name.get()
            self.client.connect(host, port, name)
            self.client.gui = self
        except Exception as e:
            messagebox.showerror("Connection Error", str(e))

    def disconnect(self):
        self.client.disconnect()
        self.window.destroy()

    def update_user_list(self, users):
        self.user_list.delete(0, END)
        for user in users:
            cleaned_user = user.strip()
            if cleaned_user != self.client.name:
                self.user_list.insert(END, cleaned_user)

    def select_user(self, event):
        selection = self.user_list.curselection()
        if selection:
            self.target_user = self.user_list.get(selection[0])
            self.client.request_key(self.target_user)

    def send_message(self):
        if not self.target_user:
            messagebox.showerror("No User Selected", "Please select a user to send a message.")
            return
        message = self.message_entry.get()
        if message:
            self.client.send_message(self.target_user, message)
            self.message_entry.delete(0, END)

    def display_message(self, message):
        self.chat_area.config(state="normal")
        self.chat_area.insert(END, f"{message}\n")
        self.chat_area.config(state="disabled")

    def run(self):
        self.window.mainloop()



if __name__ == "__main__":
    gui = ChatGUI()
    gui.run()
