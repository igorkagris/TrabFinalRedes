import socket
import threading
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import os

# Configurações do cliente
SERVER_HOST = '127.0.0.1'
SERVER_PORT = 12345

# Gerar par de chaves pública/privada para o cliente
client_private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=1024
)
client_public_key = client_private_key.public_key()

# Carregar chave pública do servidor a partir do arquivo PEM
def load_server_public_key(file_path):
    try:
        with open(file_path, 'rb') as pem_file:
            server_public_key_pem = pem_file.read()
        server_public_key = serialization.load_pem_public_key(server_public_key_pem)
        return server_public_key
    except (ValueError, FileNotFoundError) as e:
        print(f"Erro ao carregar a chave pública do servidor: {e}")
        return None

server_public_key = load_server_public_key("server_public_key.pem")
if not server_public_key:
    raise ValueError("Falha ao carregar a chave pública do servidor.")

# Função para criptografar mensagens
def encrypt_message(message, key):
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv))
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(message.encode('utf-8')) + encryptor.finalize()
    return iv + ciphertext

# Função para descriptografar mensagens
def decrypt_message(encrypted_message, key):
    iv = encrypted_message[:16]
    ciphertext = encrypted_message[16:]
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv))
    decryptor = cipher.decryptor()
    return decryptor.update(ciphertext) + decryptor.finalize()

# Função para enviar mensagens ao servidor
def send_message(client_socket, shared_key):
    while True:
        message = input()
        encrypted_message = encrypt_message(message, shared_key)
        client_socket.send(encrypted_message)

# Função para receber mensagens do servidor
def receive_message(client_socket, shared_key):
    while True:
        try:
            encrypted_message = client_socket.recv(1024)
            if encrypted_message:
                message = decrypt_message(encrypted_message, shared_key).decode('utf-8')
                print(message)
        except Exception as e:
            print(f"Erro ao receber mensagem: {e}")
            client_socket.close()
            break

# Função para iniciar o cliente
def start_client():
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect((SERVER_HOST, SERVER_PORT))

    # Enviar chave pública do cliente para o servidor
    client_public_key_pem = client_public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    client_socket.send(client_public_key_pem)

    # Receber chave simétrica criptografada do servidor
    encrypted_shared_key = client_socket.recv(256)
    shared_key = client_private_key.decrypt(
        encrypted_shared_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    threading.Thread(target=send_message, args=(client_socket, shared_key)).start()
    threading.Thread(target=receive_message, args=(client_socket, shared_key)).start()

if __name__ == "__main__":
    start_client()