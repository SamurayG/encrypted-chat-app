from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.exceptions import InvalidSignature
import os
import csv
import threading
import socket

host = '0.0.0.0'
port = 59000
server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.bind((host, port))
print('Socket binded.')
server.listen()
print('Server is running and listening ...')
clients = []
clientInfo = [] # clientInfo is a list of format [username, isLoggedIn, nonce]

# This funtion is called from the main method in a new thread whenever a client connects to the server
def handle_client(client):
    while True:
        try:
            # Wait for a message from client
            message = bytearray(client.recv(4096))
        except:
            remove_client(client)
            break
        if len(message) < 1:
            continue
        
        code = chr(message[0])
        # Handle message
        if code == "q":
            remove_client(client)
            break
        elif code == "u":
            index = clients.index(client) 
            clientInfo[index] = [None, False, None]
            continue
        parse_message(client, message)

# This function is called when a user disconnects from the server
def remove_client(client):
    index = clients.index(client)
    clients.remove(client)
    client.close()
    clientInfo.pop(index)

# This function is called whenever a client send a message to the server.
# These messages include Login and Register,
# As well as messages that are relayed between users.
# The messages that are sent between users are changed by the server before being relayed
def parse_message(client, message):
    index = clients.index(client)
    
    code = chr(message[0])
    if (code == "r"):
        # Register
        padded_username = message[1:17].decode('utf-8')
        key_string = message[17:].decode('utf-8')

        if register_account(padded_username, key_string) == False:
            client.sendall(b"eUsername is taken")
            return
        clientInfo[index][0] = padded_username
        clientInfo[index][1] = True

    elif (code == "l"):
        # Login part 1
        padded_username = message[1:].decode('utf-8')
        if len(padded_username) != 16:
            client.sendall(b"eInvalid username length sent in login request")
            return
        
        public_key = read_account(padded_username)
        if public_key == None:
            client.sendall(b"eUsername not found")
            return
        
        nonce = os.urandom(16)
        message = b"l" + nonce
        client.sendall(message)
        clientInfo[index][2] = nonce

    elif (code == "s"):
        # Login part 2
        padded_username = message[1:17].decode('utf-8')
        signature = message[17:]

        nonce = clientInfo[index][2]
        if nonce == None:
            client.sendall(b"eMust send login part 1 first")
            return

        public_key_str = read_account(padded_username)
        if (public_key_str == None):
            client.sendall(b"eUsername not found")
            return
        
        public_key = serialization.load_pem_public_key(public_key_str.encode('utf-8'))

        if rsa_validate_signature(public_key, nonce, signature) == False:
            client.sendall(b"eInvalid signature")
            return

        clientInfo[index][0] = padded_username
        clientInfo[index][1] = True

        client.sendall(b"eLogin Success")

    elif (code == "m"):
        # Message part 1
        if clientInfo[index][1] == False:
            client.sendall(b"eYou must be logged in to send a message")
            return

        padded_username = message[1:17].decode('utf-8')

        receiver_index = [idx for idx, tup in enumerate(clientInfo) if tup[0] == padded_username]
        if len(receiver_index) < 1:
            client.sendall(b"eUser does not exist, or is not logged in")
            return

        # Parse message, and create new message with sender username and RSA public key
        rsa_signature = message[17:273]
        dh_public_key_bytes = message[273:]

        sender_username = clientInfo[index][0]
        sender_rsa_pub = read_account(sender_username).encode('utf-8')
        sender_username_bytes = sender_username.encode('utf-8')
        dh_length = len(dh_public_key_bytes).to_bytes(2, 'little')
        new_message = b"m" + sender_username_bytes + rsa_signature + dh_length + dh_public_key_bytes + sender_rsa_pub
        
        clients[receiver_index[0]].sendall(new_message)

    elif (code == "b"):
        # Message part 1 response
        if clientInfo[index][1] == False:
            client.sendall(b"eError. Message response sent, but you are not logged in")
            client.sendall(b"ePlease try logging in again")
            return
        
        padded_username = message[1:17].decode('utf-8')

        receiver_index = [idx for idx, tup in enumerate(clientInfo) if tup[0] == padded_username]
        if len(receiver_index) < 1:
            print("Message request received from invalid user")
            return
        
        # Parse message, and create new message with sender username and RSA public key
        rsa_signature = message[17:273]
        dh_public_key = message[273:]

        sender_username = clientInfo[index][0]
        sender_rsa_pub = read_account(sender_username).encode('utf-8')
        sender_username_bytes = sender_username.encode('utf-8')
        dh_length = len(dh_public_key).to_bytes(2, 'little')

        new_message = b"b" + sender_username_bytes + rsa_signature + dh_length + dh_public_key + sender_rsa_pub

        clients[receiver_index[0]].sendall(new_message)

    elif (code == "n"):
        # Message part 2
        if clientInfo[index][1] == False:
            client.sendall(b"eError. Message response sent, but you are not logged in")
            client.sendall(b"ePlease try logging in again")
            return
        
        padded_username = message[1:17].decode('utf-8')
        
        receiver_index = [idx for idx, tup in enumerate(clientInfo) if tup[0] == padded_username]
        if len(receiver_index) < 1:
            client.sendall(b"eUser does not exist, or is not logged in")
            return

        sender_username = clientInfo[index][0].encode('utf-8')
        rest_of_message = message[17:]
        
        new_message = b"n" + sender_username + rest_of_message
            
        clients[receiver_index[0]].sendall(new_message)

# csv file name to store the accounts
account_list = "accounts.csv"

# initialize the CSV file with two columns: username and public_key
def initialize_csv():
    with open(account_list, 'w', encoding='UTF8', newline='') as f:
        writer = csv.writer(f)
        writer.writerow(["username", "public_key"])
    # print("Initialize the csv file successfully")

# load the new account into that csv file
# if the username already exists, return False, else, return True
def register_account(username, public_key):
    with open(account_list) as f:
        csv_reader = csv.reader(f)
        for row in csv_reader:
            if (row[0] == username):
                return False
    with open(account_list, 'a', encoding='UTF8', newline='') as f:
        writer = csv.writer(f)
        writer.writerow([username,public_key])
    # print("Write " + username + " into the csv file successfully")
    return True

# return the public_key for that specific username
def read_account(username):
    with open(account_list) as f:
        csv_reader = csv.reader(f)
        for row in csv_reader:
            if (row[0] == username):
                return row[1]
        return None

# Validates an RSA signature using an RSA public key
# Used to authenticate a user when logging in
def rsa_validate_signature(public_key, message, signature):
    try:
        public_key.verify(
            bytes(signature),
            bytes(message),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except InvalidSignature:
        return False

def main():
    initialize_csv()
    while True:
        client, address = server.accept()
        conn_msg = 'Connection is established with' + str(address)
        print(conn_msg)

        clients.append(client)
        clientInfo.append([None, False, None])
        
        thread = threading.Thread(target=handle_client, args=(client,))
        thread.start()

if __name__ == "__main__":
    main()
