import socket
import threading
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import os
import json

# Configurações do servidor
SERVER_HOST = '127.0.0.1'
SERVER_PORT = 12345
CLIENTS_FILE = 'clients.json'

# Estrutura de dados para armazenar clientes, nomes e salas
clients = {}
names = set()
rooms = {}

# Gerar par de chaves pública/privada para o servidor
server_private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=1024
)
server_public_key = server_private_key.public_key()

# Salvar a chave pública do servidor em um arquivo PEM
with open("server_public_key.pem", "wb") as pem_file:
    pem_file.write(server_public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ))


def encrypt_message(message, key):
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv))
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(message.encode('utf-8')) + encryptor.finalize()
    return iv + ciphertext

def decrypt_message(encrypted_message, key):
    iv = encrypted_message[:16]
    ciphertext = encrypted_message[16:]
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv))
    decryptor = cipher.decryptor()
    return decryptor.update(ciphertext) + decryptor.finalize()

# Carregar clientes do arquivo
def load_clients():
    if os.path.exists(CLIENTS_FILE):
        with open(CLIENTS_FILE, 'r') as file:
            return json.load(file)
    return {}

# Salvar clientes no arquivo
def save_clients(clients_data):
    with open(CLIENTS_FILE, 'w') as file:
        json.dump(clients_data, file)

# Verificar nome de usuário e senha
def authenticate(client_socket, shared_key):
    clients_data = load_clients()
    client_socket.send(encrypt_message("Digite seu nome de usuário: ", shared_key))
    username = decrypt_message(client_socket.recv(1024), shared_key).decode('utf-8').strip()

    if ' ' in username:
        client_socket.send(encrypt_message("O nome de usuário não pode conter espaços.", shared_key))
        return None

    if username in clients:
        client_socket.send(encrypt_message("Este nome de usuário já está conectado.", shared_key))
        return None

    if username in clients_data:
        client_socket.send(encrypt_message("Digite sua senha: ", shared_key))
        password = decrypt_message(client_socket.recv(1024), shared_key).decode('utf-8').strip()
        if clients_data[username] == password:
            client_socket.send(encrypt_message("Autenticação bem-sucedida.", shared_key))
            return username
        else:
            client_socket.send(encrypt_message("Senha incorreta.", shared_key))
            return None
    else:
        client_socket.send(encrypt_message("Novo usuário. Digite uma senha para se registrar: ", shared_key))
        password = decrypt_message(client_socket.recv(1024), shared_key).decode('utf-8').strip()
        clients_data[username] = password
        save_clients(clients_data)
        client_socket.send(encrypt_message("Registro bem-sucedido.", shared_key))
        return username

# Função para lidar com clientes conectados
def handle_client(client_socket, client_address):
    try:
        # Receber chave pública do cliente
        client_public_key_pem = client_socket.recv(1024)
        client_public_key = serialization.load_pem_public_key(client_public_key_pem)

        # Gerar chave simétrica
        shared_key = os.urandom(32)

        # Criptografar chave simétrica com a chave pública do cliente
        encrypted_shared_key = client_public_key.encrypt(
            shared_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        # Enviar chave simétrica criptografada para o cliente
        client_socket.send(encrypted_shared_key)

        # Autenticação do cliente
        username = None
        while not username:
            username = authenticate(client_socket, shared_key)
        
        names.add(username)
        clients[client_socket] = {'name': username, 'room': None, 'symmetric_key': shared_key}

        # Oferecer opções para criar ou entrar em uma sala
        offer_room_options(client_socket)

        # Continuar recebendo mensagens
        while True:
            encrypted_message = client_socket.recv(1024)
            if encrypted_message:
                message = decrypt_message(encrypted_message, shared_key).decode('utf-8')
                if message.startswith('$'):
                    handle_command(client_socket, message)
                else:
                    room_name = clients[client_socket]['room']
                    formatted_message = f"[{clients[client_socket]['name']}: {message}]"
                    broadcast(formatted_message, client_socket, room_name)
            else:
                remove(client_socket)
                break
    except Exception as e:
        print(f"Erro: {e}")
        remove(client_socket)

# Função para oferecer opções de sala
def offer_room_options(client_socket):
    shared_key = clients[client_socket]['symmetric_key']
    while True:
        client_socket.send(encrypt_message("Digite 1 para criar uma sala ou 2 para entrar em uma sala existente: ", shared_key))
        choice = decrypt_message(client_socket.recv(1024), shared_key).decode('utf-8').strip()

        if choice == '1':
            client_socket.send(encrypt_message("Digite o nome da sala para criar: ", shared_key))
            room_name = decrypt_message(client_socket.recv(1024), shared_key).decode('utf-8').strip()
            
            if room_name in rooms:
                client_socket.send(encrypt_message("Sala já existe. Tente outro nome.", shared_key))
            else:
                client_socket.send(encrypt_message("Digite uma senha para a sala ou deixe em branco para uma sala pública: ", shared_key))
                room_password = decrypt_message(client_socket.recv(1024), shared_key).decode('utf-8').strip()
                
                if room_password:
                    rooms[room_name] = {'admin': client_socket, 'clients': [client_socket], 'password': room_password}
                    client_socket.send(encrypt_message(f"Sala privada '{room_name}' criada e você é o administrador.", shared_key))
                else:
                    rooms[room_name] = {'admin': client_socket, 'clients': [client_socket], 'password': None}
                    client_socket.send(encrypt_message(f"Sala pública '{room_name}' criada e você é o administrador.", shared_key))
                
                clients[client_socket]['room'] = room_name
                break

        elif choice == '2':
            if rooms:
                room_list = "\n".join([f"{i}. {room}" for i, room in enumerate(rooms.keys(), 1)])
                client_socket.send(encrypt_message(f"Salas disponíveis:\n{room_list}\nDigite o índice da sala para entrar: ", shared_key))
                
                try:
                    room_index = int(decrypt_message(client_socket.recv(1024), shared_key).decode('utf-8').strip()) - 1
                    room_name = list(rooms.keys())[room_index]
                    if rooms[room_name]['password']:
                        client_socket.send(encrypt_message("Digite a senha da sala: ", shared_key))
                        room_password = decrypt_message(client_socket.recv(1024), shared_key).decode('utf-8').strip()
                        
                        if room_password == rooms[room_name]['password']:
                            rooms[room_name]['clients'].append(client_socket)
                            clients[client_socket]['room'] = room_name
                            client_socket.send(encrypt_message(f"Você entrou na sala privada '{room_name}'.", shared_key))
                            break
                        else:
                            client_socket.send(encrypt_message("Senha incorreta. Tente novamente.", shared_key))
                    else:
                        rooms[room_name]['clients'].append(client_socket)
                        clients[client_socket]['room'] = room_name
                        client_socket.send(encrypt_message(f"Você entrou na sala pública '{room_name}'.", shared_key))
                        break
                except:
                    client_socket.send(encrypt_message("Índice inválido. Tente novamente.", shared_key))
            else:
                client_socket.send(encrypt_message("Não há salas disponíveis no momento.", shared_key))
        else:
            client_socket.send(encrypt_message("Escolha inválida. Tente novamente.", shared_key))

# Função para lidar com comandos
def handle_command(client_socket, command):
    room_name = clients[client_socket]['room']
    user_name = clients[client_socket]['name']
    shared_key = clients[client_socket]['symmetric_key']
    
    if command == '$help':
        help_message = ("Comandos disponíveis:\n"
                        "$help : mostrar os comandos\n"
                        "$users : mostrar usuários da sala\n"
                        "$quit : sair da sala\n"
                        "$close : sair do bate-papo (aplicativo)\n")
        
        if client_socket == rooms[room_name]['admin']:
            help_message += ("Comandos do administrador:\n"
                             "$adm {nome_do_usuário} : transferir administrador para outro usuário\n"
                             "$remove {nome_do_usuário} : remover o usuário\n")
        
        client_socket.send(encrypt_message(help_message, shared_key))
    
    elif command == '$users':
        user_list = "\n".join([clients[client]['name'] for client in rooms[room_name]['clients']])
        client_socket.send(encrypt_message(f"Usuários na sala '{room_name}':\n{user_list}", shared_key))
    
    elif command == '$quit':
        client_socket.send(encrypt_message("Você saiu da sala.", shared_key))
        remove_from_room(client_socket)
        offer_room_options(client_socket)
    
    elif command == '$close':
        client_socket.send(encrypt_message("Você saiu do bate-papo.", shared_key))
        remove(client_socket)
        client_socket.close()
    
    elif command.startswith('$adm '):
        if client_socket == rooms[room_name]['admin']:
            new_admin_name = command.split(' ', 1)[1]
            new_admin_socket = get_client_by_name(new_admin_name)
            if new_admin_socket in rooms[room_name]['clients']:
                rooms[room_name]['admin'] = new_admin_socket
                client_socket.send(encrypt_message(f"{new_admin_name} agora é o administrador da sala.", shared_key))
                new_admin_socket.send(encrypt_message("Você agora é o administrador da sala.", shared_key))
            else:
                client_socket.send(encrypt_message("Usuário não encontrado na sala.", shared_key))
        else:
            client_socket.send(encrypt_message("Apenas o administrador pode usar este comando.", shared_key))
    
    elif command.startswith('$remove '):
        if client_socket == rooms[room_name]['admin']:
            remove_name = command.split(' ', 1)[1]
            remove_socket = get_client_by_name(remove_name)
            if remove_socket in rooms[room_name]['clients']:
                client_socket.send(encrypt_message(f"Você removeu {remove_name} da sala.", shared_key))
                remove_from_room(remove_socket, notify=True)
            else:
                client_socket.send(encrypt_message("Usuário não encontrado na sala.", shared_key))
        else:
            client_socket.send(encrypt_message("Apenas o administrador pode usar este comando.", shared_key))
    else:
        client_socket.send(encrypt_message("Comando não reconhecido. Digite $help para ver a lista de comandos.", shared_key))

# Função para enviar mensagens a todos os clientes na mesma sala
def broadcast(message, connection, room_name):
    for client in rooms[room_name]['clients']:
        if client != connection:
            try:
                shared_key = clients[client]['symmetric_key']
                client.send(encrypt_message(message, shared_key))
            except:
                remove(client)

# Função para remover clientes desconectados
def remove(connection):
    if connection in clients:
        name = clients[connection]['name']
        room_name = clients[connection]['room']
        names.remove(name)

        if room_name:
            rooms[room_name]['clients'].remove(connection)
            if not rooms[room_name]['clients']:
                del rooms[room_name]
        
        del clients[connection]

# Função para remover clientes de uma sala
def remove_from_room(connection, notify=False):
    room_name = clients[connection]['room']
    if room_name:
        rooms[room_name]['clients'].remove(connection)
        clients[connection]['room'] = None
        if notify:
            shared_key = clients[connection]['symmetric_key']
            connection.send(encrypt_message("Você foi removido da sala pelo administrador.", shared_key))
            offer_room_options(connection)
        if not rooms[room_name]['clients']:
            del rooms[room_name]

# Função para obter cliente pelo nome
def get_client_by_name(name):
    for client, info in clients.items():
        if info['name'] == name:
            return client
    return None

# Função para iniciar o servidor
def start_server():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind((SERVER_HOST, SERVER_PORT))
    server.listen(5)
    
    print("Servidor em funcionamento... Pressione 'Ctrl+C' para encerrar.")

    def accept_connections():
        while True:
            client_socket, client_address = server.accept()
            threading.Thread(target=handle_client, args=(client_socket, client_address)).start()

    try:
        accept_connections()
    except KeyboardInterrupt:
        print("Encerrando o servidor...")
        server.close()
        os._exit(0)

if __name__ == "__main__":
    start_server()