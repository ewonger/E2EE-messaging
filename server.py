import socket
import threading
import sys
import rsa

HEADER_LENGTH = 10
# List of connected clients
client_socket_list = []
# User information(username, public key, public key for signature)
clients = {}

def get_header(text):
    return f'{len(text):<{HEADER_LENGTH}}'.encode()

# Broadcasts message to all connected clients
def broadcast(client_socket_list, msg):
    for client in client_socket_list:
        client.send(get_header(msg) + msg.encode())

# Shares public key with each client
def broadcast_pub_key(client_socket_list):
    client_socket_list[0].send(get_header(clients[client_socket_list[1]]['pubkey_pem']) + clients[client_socket_list[1]]['pubkey_pem'])
    client_socket_list[1].send(get_header(clients[client_socket_list[0]]['pubkey_pem']) + clients[client_socket_list[0]]['pubkey_pem'])

def receive_client(client_socket, addr):
    while True:
        try:
            # Receive message and signature from client message
            msg_header = client_socket.recv(HEADER_LENGTH)
            msg = client_socket.recv(int(msg_header.decode().strip()))
            signature_header = client_socket.recv(HEADER_LENGTH)
            signature = client_socket.recv(int(signature_header.decode().strip()))
        
        # Closes socket if client disconnects
        except Exception as e:
            client_socket.shutdown(socket.SHUT_RDWR)
            client_socket_list.remove(client_socket)
            print('{} disconnected'.format(addr))
            
            broadcast(client_socket_list, '\n{} has left the chat.\nThere are currently {} on the server.'.format(clients[client_socket]['username'], len(client_socket_list)))
            del clients[client_socket]
            break
        
        print('{} sent:\n{}'.format(clients[client_socket]['username'], msg))

        if msg != '':
            try:
                # Verifies signature matches message with public key for signature
                if rsa.verify(msg, signature, clients[client_socket]['pubkeysign']):
                    for client in client_socket_list:
                        if client != client_socket:
                            client.send(msg_header + msg)
            except rsa.pkcs1.VerificationError:
                print('error with verification')
            

def main():
    # Setup server socket
    s = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
    # Allow clients to reconnect
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    try:
        # Set up IP and port
        s.bind((sys.argv[1], int(sys.argv[2])))
        s.listen()

    except:
        if len(sys.argv) != 3:
            print('Missing address or port')
        else:
            print('Could not create server')
        quit()

    print('Server has started')
    print('Server is listening on {}:{}'.format(sys.argv[1], sys.argv[2]))

    while True:
        client_socket, addr = s.accept()
        # Prevents clients from joining if room is max capacity (2 clients)
        if len(client_socket_list) >= 2:
            client_socket.shutdown(socket.SHUT_RDWR)
            client_socket.close()
            continue

        # Receives username, public key, public key for signature from connected clients
        username_header = client_socket.recv(HEADER_LENGTH)
        username = client_socket.recv(int(username_header.decode().strip())).decode()
        pubkey_header = client_socket.recv(HEADER_LENGTH)
        pubkey = client_socket.recv(int(pubkey_header.decode().strip()))
        pubkeysign_header = client_socket.recv(HEADER_LENGTH)
        pubkeysign = client_socket.recv(int(pubkeysign_header.decode().strip()))

        user = {'username': username,
                'pubkey_pem': pubkey,
                'pubkeysign': rsa.PublicKey.load_pkcs1(pubkeysign)}

        print('{} connected'.format(addr))
        # Broadcasts connected client to other clients in server
        broadcast(client_socket_list, '{} has joined.'.format(username, len(client_socket_list)))
        clients[client_socket] = user
        client_socket_list.append(client_socket)
        
        # Broadcasts total number of people in server to everyone
        broadcast(client_socket_list, 'There are currently {} people on the server.'.format(len(client_socket_list)))
        print('{} people in server'.format(len(client_socket_list)))

        # Shares public keys with each client
        if len(client_socket_list) == 2:
            broadcast_pub_key(client_socket_list)

        threading.Thread(target=receive_client, args=(client_socket, addr,)).start()

main()