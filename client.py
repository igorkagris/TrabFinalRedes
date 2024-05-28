import socket
import threading

# Configurações do cliente
SERVER_HOST = '127.0.0.1'
SERVER_PORT = 12345

# Função para enviar mensagens ao servidor
def send_message(client_socket):
    while True:
        message = input()
        client_socket.send(message.encode('utf-8'))

# Função para receber mensagens do servidor
def receive_message(client_socket):
    while True:
        try:
            message = client_socket.recv(1024).decode('utf-8')
            if message:
                print(message)
        except:
            print("Você foi desconectado do servidor.")
            client_socket.close()
            break

# Função para iniciar o cliente
def start_client():
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect((SERVER_HOST, SERVER_PORT))
    
    threading.Thread(target=send_message, args=(client_socket,)).start()
    threading.Thread(target=receive_message, args=(client_socket,)).start()

if __name__ == "__main__":
    start_client()
