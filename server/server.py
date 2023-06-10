import socket
import threading
import json
from mycipher import encrypt_aes256, decrypt_aes256

def secureEncode(packet,dst_ip):
    packet_str = base64.b64encode(packet).decode('utf-8')
    packet_json = json.dumps({'pid': dst_ip, 'packet': packet_str})
    ciphertext = encrypt_aes256(key, packet_json)
    ciphertext_base64 = base64.b64encode(ciphertext).decode('utf-8')
    return ciphertext_base64

def secureDecode(data):
    ciphertext = base64.b64decode(data)
    packet_json = decrypt_aes256(key, ciphertext)
    data = json.loads(packet_json)
    pid = data['pid']
    packet_str = data['packet']
    packet = base64.b64decode(packet_str)
    return packet

key = "012345dgda012345dgda012345dgda01"

# Define a function to handle each client connection
def handle_client(client_socket, name, client_sockets):
    while True:
        # Receive data from the client
        data = client_socket.recv(1024)
        if not data:
            break
        json_data = data.decode()
        packet = secureDecode(json_data)
        src_ip = socket.inet_ntoa(packet[12:16])
        dst_ip = socket.inet_ntoa(packet[16:20])
        print("Packet goes from ",src_ip,' to ',dst_ip)
        client_sockets[dst_ip].send(data)
    # Remove the client socket from the dictionary
    del client_sockets[name]

    # Close the client socket
    client_socket.close()

# Create a TCP/IP socket
server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

# Bind the socket to a specific IP address and port
server_socket.bind(('0.0.0.0', 8000))

# Listen for incoming connections
server_socket.listen(5)

# Initialize the dictionary of client sockets and names
client_sockets = {}

while True:
    # Accept incoming client connections
    client_socket, address = server_socket.accept()

    # Receive the name of the client as the first message
    name = client_socket.recv(1024).decode()

    # Add the client socket and name to the dictionary
    client_sockets[name] = client_socket

    # Create a new thread to handle the client connection
    client_thread = threading.Thread(target=handle_client, args=(client_socket, name, client_sockets))
    client_thread.start()

    # Print a message to confirm the new connection
    print(f"New connection: {name}")