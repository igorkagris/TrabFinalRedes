import socket
import threading
import json
import os
import sys
import msvcrt

# Configurações do servidor
SERVER_HOST = '127.0.0.1'
SERVER_PORT = 12345
CLIENTS_FILE = 'clients.json'

# Estrutura de dados para armazenar clientes, nomes e salas
clients = {}
names = set()
rooms = {}

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
def authenticate(client_socket):
    clients_data = load_clients()
    client_socket.send("Digite seu nome de usuário: ".encode('utf-8'))
    username = client_socket.recv(1024).decode('utf-8').strip()

    if ' ' in username:
        client_socket.send("O nome de usuário não pode conter espaços.".encode('utf-8'))
        return None

    if username in clients:
        client_socket.send("Este nome de usuário já está conectado.".encode('utf-8'))
        return None

    if username in clients_data:
        client_socket.send("Digite sua senha: ".encode('utf-8'))
        password = client_socket.recv(1024).decode('utf-8').strip()
        if clients_data[username] == password:
            client_socket.send("Autenticação bem-sucedida.".encode('utf-8'))
            return username
        else:
            client_socket.send("Senha incorreta.".encode('utf-8'))
            return None
    else:
        client_socket.send("Novo usuário. Digite uma senha para se registrar: ".encode('utf-8'))
        password = client_socket.recv(1024).decode('utf-8').strip()
        clients_data[username] = password
        save_clients(clients_data)
        client_socket.send("Registro bem-sucedido.".encode('utf-8'))
        return username

# Função para lidar com clientes conectados
def handle_client(client_socket, client_address):
    try:
        # Autenticação do cliente
        username = None
        while not username:
            username = authenticate(client_socket)
        
        names.add(username)
        clients[client_socket] = {'name': username, 'room': None}

        # Oferecer opções para criar ou entrar em uma sala
        offer_room_options(client_socket)

        # Continuar recebendo mensagens
        while True:
            message = client_socket.recv(1024).decode('utf-8')
            if message:
                if message.startswith('$'):
                    handle_command(client_socket, message)
                else:
                    room_name = clients[client_socket]['room']
                    formatted_message = f"[{clients[client_socket]['name']}: {message}]"
                    broadcast(formatted_message, client_socket, room_name)
            else:
                remove(client_socket)
                break
    except:
        remove(client_socket)

# Função para oferecer opções de sala
def offer_room_options(client_socket):
    while True:
        client_socket.send("Digite 1 para criar uma sala ou 2 para entrar em uma sala existente: ".encode('utf-8'))
        choice = client_socket.recv(1024).decode('utf-8').strip()

        if choice == '1':
            client_socket.send("Digite o nome da sala para criar: ".encode('utf-8'))
            room_name = client_socket.recv(1024).decode('utf-8').strip()
            
            if room_name in rooms:
                client_socket.send("Sala já existe. Tente outro nome.".encode('utf-8'))
            else:
                rooms[room_name] = {'admin': client_socket, 'clients': [client_socket]}
                clients[client_socket]['room'] = room_name
                client_socket.send(f"Sala '{room_name}' criada e você é o administrador.".encode('utf-8'))
                break

        elif choice == '2':
            if rooms:
                room_list = "\n".join([f"{i}. {room}" for i, room in enumerate(rooms.keys(), 1)])
                client_socket.send(f"Salas disponíveis:\n{room_list}\nDigite o índice da sala para entrar: ".encode('utf-8'))
                
                try:
                    room_index = int(client_socket.recv(1024).decode('utf-8').strip()) - 1
                    room_name = list(rooms.keys())[room_index]
                    rooms[room_name]['clients'].append(client_socket)
                    clients[client_socket]['room'] = room_name
                    client_socket.send(f"Você entrou na sala '{room_name}'.".encode('utf-8'))
                    break
                except:
                    client_socket.send("Índice inválido. Tente novamente.".encode('utf-8'))
            else:
                client_socket.send("Não há salas disponíveis no momento.".encode('utf-8'))
        else:
            client_socket.send("Escolha inválida. Tente novamente.".encode('utf-8'))

# Função para lidar com comandos
def handle_command(client_socket, command):
    room_name = clients[client_socket]['room']
    user_name = clients[client_socket]['name']
    
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
        
        client_socket.send(help_message.encode('utf-8'))
    
    elif command == '$users':
        user_list = "\n".join([clients[client]['name'] for client in rooms[room_name]['clients']])
        client_socket.send(f"Usuários na sala '{room_name}':\n{user_list}".encode('utf-8'))
    
    elif command == '$quit':
        client_socket.send("Você saiu da sala.".encode('utf-8'))
        remove_from_room(client_socket)
        offer_room_options(client_socket)
    
    elif command == '$close':
        client_socket.send("Você saiu do bate-papo.".encode('utf-8'))
        remove(client_socket)
        client_socket.close()
    
    elif command.startswith('$adm '):
        if client_socket == rooms[room_name]['admin']:
            new_admin_name = command.split(' ', 1)[1]
            new_admin_socket = get_client_by_name(new_admin_name)
            if new_admin_socket in rooms[room_name]['clients']:
                rooms[room_name]['admin'] = new_admin_socket
                client_socket.send(f"{new_admin_name} agora é o administrador da sala.".encode('utf-8'))
                new_admin_socket.send("Você agora é o administrador da sala.".encode('utf-8'))
            else:
                client_socket.send("Usuário não encontrado na sala.".encode('utf-8'))
        else:
            client_socket.send("Apenas o administrador pode usar este comando.".encode('utf-8'))
    
    elif command.startswith('$remove '):
        if client_socket == rooms[room_name]['admin']:
            remove_name = command.split(' ', 1)[1]
            remove_socket = get_client_by_name(remove_name)
            if remove_socket in rooms[room_name]['clients']:
                remove_from_room(remove_socket)
                remove_socket.send("Você foi removido da sala pelo administrador.".encode('utf-8'))
            else:
                client_socket.send("Usuário não encontrado na sala.".encode('utf-8'))
        else:
            client_socket.send("Apenas o administrador pode usar este comando.".encode('utf-8'))
    else:
        client_socket.send("Comando não reconhecido. Digite $help para ver a lista de comandos.".encode('utf-8'))

# Função para enviar mensagens a todos os clientes na mesma sala
def broadcast(message, connection, room_name):
    for client in rooms[room_name]['clients']:
        if client != connection:
            try:
                client.send(message.encode('utf-8'))
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
def remove_from_room(connection):
    room_name = clients[connection]['room']
    if room_name:
        rooms[room_name]['clients'].remove(connection)
        clients[connection]['room'] = None
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
    
    print("Servidor em funcionamento... Pressione 'Esc' para encerrar.")
    
    def accept_connections():
        while True:
            client_socket, client_address = server.accept()
            threading.Thread(target=handle_client, args=(client_socket, client_address)).start()
    
    def wait_for_esc():
        while True:
            if msvcrt.kbhit():
                key = msvcrt.getch()
                if key == b'\x1b':  # 'Esc' key
                    print("Encerrando o servidor...")
                    server.close()
                    os._exit(0)

    # Thread para aceitar conexões
    threading.Thread(target=accept_connections).start()
    
    # Thread para esperar pela tecla 'Esc' para encerrar o servidor
    threading.Thread(target=wait_for_esc).start()

if __name__ == "__main__":
    start_server()