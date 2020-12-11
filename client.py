import socket
import threading
import sys
import rsa

HEADER_LENGTH = 10
stop_threads = False
shared_pub_key = rsa.key.PublicKey
pubkey = rsa.key.PublicKey
privkey = rsa.key.PrivateKey
privkey_sign = rsa.key.PrivateKey

def get_header(text):
    return f'{len(text):<{HEADER_LENGTH}}'.encode()

def receive_msg(s):
    global stop_threads, shared_pub_key

    while not stop_threads:
        if stop_threads:
            break
        else:
            try:
                # Receives message from server 
                msg_header = s.recv(HEADER_LENGTH)
                msg_length = int(msg_header.decode().strip())
                msg = s.recv(msg_length)

                try:
                    # Checks whether it is public key or message
                    msg = msg.decode()
                    if msg[0:30] == '-----BEGIN RSA PUBLIC KEY-----':
                        shared_pub_key = rsa.PublicKey.load_pkcs1(msg, format='PEM')
                    else:
                        print('{}\n'.format(msg))
                except:
                    # Decrypts message
                    msg = rsa.decrypt(msg, privkey).decode()
                    print(msg)
                
            except Exception as e:
                print('\nDisconnected.\n')
                if not stop_threads:
                    stop_threads = True
                    s.shutdown(socket.SHUT_RDWR)
                    s.close()
                break

def send_msg(s, username):
    global stop_threads

    while not stop_threads:
        try:
            # Input for message
            msg = input()
        except:
            print('\nServer closed unexpectedly.\n')
        
        # Exit command
        if msg == '/quit':
            stop_threads = True
            s.shutdown(socket.SHUT_RDWR)
            s.close()
            break
        elif msg == '':
            continue
        else:
            # Prepares message for encoding
            msg = msg.replace('\n', '')
            msg = '{}: {}'.format(username, msg).encode()

            # Prevents client from sending message if there is only one client on server
            if not isinstance(shared_pub_key, rsa.key.PublicKey):
                continue
            
            # Encrypts message with other client's public key
            encrypted_msg = rsa.encrypt(msg, shared_pub_key)
            encrypted_msg_header = get_header(encrypted_msg)
            # Signs message with private key (Detached Signature)
            signature = rsa.sign(encrypted_msg, privkey_sign, 'SHA-1')
            signature_header = get_header(signature)

            try:
                # Sends encrypted message and signature to server
                s.send(encrypted_msg_header + encrypted_msg)
                s.send(signature_header + signature)
            except:
                print('\nServer closed unexpectedly.\n')

def main():
    global pubkey, privkey, privkey_sign
    # Setup socket and connect to server
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    try:
        s.connect((sys.argv[1], int(sys.argv[2])))

    except:
        if len(sys.argv) != 3:
            print('Missing address or port')
        else:
            print('Could not connect to server')
        quit()

    # Generate new keys for message encryption and signature
    (pubkey, privkey) = rsa.newkeys(512)
    (pubkey_sign, privkey_sign) = rsa.newkeys(512)

    # Saves keys in PKCS#1 PEM format for sharing
    pubkey_pem = rsa.PublicKey.save_pkcs1(pubkey, format='PEM')
    pubkey_pem_header = get_header(pubkey_pem)
    pubkeysign_pem = rsa.PublicKey.save_pkcs1(pubkey_sign, format='PEM')
    pubkeysign_pem_header = get_header(pubkeysign_pem)

    # Get input for username
    username = ''
    while username == '':
        username = input('Enter username: ')
    username_header = get_header(username)

    try:
        # Sends username, public key, public key for signture to server
        s.send(username_header + username.encode())
        s.send(pubkey_pem_header + pubkey_pem)
        s.send(pubkeysign_pem_header + pubkeysign_pem)

    # Executes if room is at max capacity
    except BrokenPipeError:
        print('\nRoom is full\n')
        quit()

    print('\nSuccessfully joined the server.\n')

    receive_thread = threading.Thread(target=receive_msg, args=(s,)).start()
    send_thread = threading.Thread(target=send_msg, args=(s, username)).start()

main()