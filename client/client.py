from cryptography.hazmat.primitives import hashes, serialization, hmac
from cryptography.hazmat.primitives.asymmetric import rsa, dh, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.exceptions import InvalidSignature
import os
import threading
import socket


# Import a private key that was read from a PEM file
def import_private_key(private_key_pem):
    return serialization.load_pem_private_key(private_key_pem, password=None)

# Import a public key that was read from a PEM file
def import_public_key(public_key_pem):
    return serialization.load_pem_public_key(public_key_pem)

################################
## RSA CRYPTOGRAPHY FUNCTIONS ##
################################

# Generate a private key, used to register
def rsa_generate_private_key():
    return rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )

# Generate a public key from private key
def rsa_generate_public_key(private_key):
    return private_key.public_key()

# Get private bytes, used to save the private key to a file
def rsa_get_private_bytes(private_key):
    return private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )

# Get public bytes, used to send the public key in a message
def rsa_get_public_bytes(public_key):
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    
# Sign a message using an RSA private key
def rsa_sign_message(private_key, message):
    return private_key.sign(
        message,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )

# Validate a signature using an RSA public key
def rsa_validate_signature(public_key, message, signature):
    try:
        public_key.verify(
            signature,
            message,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except InvalidSignature:
        return False

# Encrypt a message using an RSA private key
def rsa_encrypt_message(public_key, message):
    return public_key.encrypt(
        message,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

# Decrypt a message using an RSA private key
def rsa_decrypt_message(private_key, message):
    return private_key.decrypt(
        message,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    
###########################################
## DIFFIE-HELLMAN CRYPTOGRAPHY FUNCTIONS ##
###########################################

# Generate a private key for a single message
def dh_generate_private_key(parameters):
    return parameters.generate_private_key()

# Get public key from a private key
def dh_generate_public_key(private_key):
    return private_key.public_key()

# Get a byte array from a public key so that it can be signed
def dh_get_public_bytes(public_key):
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

# Generate a shared key based on private key and the recieved public key
def dh_generate_shared_key(private_key, peer_public_key):
    shared_key = private_key.exchange(peer_public_key)
    return HKDF(
        algorithm=hashes.SHA256(),
        length=16, #256 bits for AES 
        salt=None,
        info=None,
    ).derive(shared_key)

################################
## AES CRYPTOGRAPHY FUNCTIONS ##
################################

# Generate a 128 bit initialization vector
def generate_iv():
    return os.urandom(16)

# Encrypt a message with the shared key bytes
def aes_cbc_encrypt_message(shared_key, message, iv):
    encryptor = Cipher(algorithms.AES(shared_key), modes.CBC(iv)).encryptor()
    return encryptor.update(message) + encryptor.finalize()

# Decrypt a message with the shared key bytes
def aes_cbc_decrypt_message(shared_key, message, iv):
    decryptor = Cipher(algorithms.AES(shared_key), modes.CBC(iv)).decryptor()
    return decryptor.update(message) + decryptor.finalize()

# This function pads a message (bytes) until its size is a multiple of 16
def pad_message(message):
    while len(message) % 16 != 0:
        message += b' '
    return message

#################################
## HMAC CRYPTOGRAPHY FUNCTIONS ##
#################################

# This function gets a SHA256 hash, which is used as the key for HMAC key
def get_sha256_hash(input):
    h = hashes.Hash(hashes.SHA256())
    h.update(input)
    return h.finalize()

# Generate an HMAC signature using an HMAC key
def hmac_generate_signature(key, message):
    h = hmac.HMAC(key, hashes.SHA256())
    h.update(message)
    return h.finalize()

# Validate an HMAC signature using an HMAC key
def hmac_verify_signature(key, signature, message):
    h = hmac.HMAC(key, hashes.SHA256())
    h.update(message)
    try:
        h.verify(signature)
        return True
    except InvalidSignature:
        return False

###############################
## MESSAGE PARSING FUNCTIONS ##
###############################

# Pad a string with spaces until it has 16 charcters
def pad_string(message):
    while len(message) % 16 != 0:
        message += ' '
    return message

# This function is called whenever a message is received by the server. This typically is done by relaying a message from another user
# The server will change the username in the message from the receiver to the sender, and will also append the senders RSA public key
# in some cases
def parse_message(message):
    global rsa_priv_global
    global dh_priv_global
    global username_global
    global loggedIn
    global shared_key_global
    global msg_input_global

    code = chr(message[0])
    if (code == "l"):
        # Login part 1 response
        nonce = message[1:]
        if username_global == "":
            print("Error. Log in response received but no username found")
            print("Please try logging in again")
            return

        # Open private key file
        try:
            file_name = username_global.strip() + ".pem"
            with open(file_name, "r") as f:
                rsa_priv_pem = f.read()
        except:
            print("Private key file invalid or not found")
            return

        rsa_priv_global = import_private_key(rsa_priv_pem.encode('utf-8'))

        signature = rsa_sign_message(rsa_priv_global, nonce)
        username_bytes = pad_string(username_global).encode('utf-8')

        # Get a byte array in the following format: b"s"[16 bytes username][rsa signature]
        message = b"s" + username_bytes + signature

        client_send(message)
        loggedIn = True
    
    elif (code == "e"):
        # Error message from server
        print_msg = message[1:].decode('utf-8')
        print(print_msg)
        print("> ", end='')

    elif (code == "m"):
        # Message part 1 (another client is attempting to send a message to this client)
        # Note: This message is changed by the server and is different than the one that was sent by the other client
        if loggedIn == False:
            print("Error. Message request received but not logged in")
            print("Please try logging in again")
            return
        if rsa_priv_global == None:
            print("Error. Message request received but no RSA key found")
            print("Please try logging in again")
            return

        padded_username = message[1:17].decode('utf-8')
        sender_rsa_signature = message[17:273]
        dh_public_key_len = int.from_bytes(message[273:275], 'little', signed=False)
        sender_dh_public_key_pem = message[275:275+dh_public_key_len]
        sender_rsa_pub_pem = message[275+dh_public_key_len:]

        sender_rsa_pub = import_public_key(sender_rsa_pub_pem)
        if rsa_validate_signature(sender_rsa_pub, sender_dh_public_key_pem, sender_rsa_signature) == False:
            print("Invalid RSA signature in received message")
            return
        
        # Create DH keys and sign DH public key
       
        parameters = dh.DHParameterNumbers(31316445495521676428187952232369783442765586753757915473647765060453095814335222549808839990545027952239915350268690894477747998072001686126320547649416473918727167199143061764084117346011689165816814201810052181388047483724216779673510089716950796069695957492797890459863874914267921574565797661035685983056313213003768220589047111460978107861802482426073394045366004328266766772627142228827025902187242430995266734830211970256381182266075929430064372250311218544593519292433377081375401081361262592914015216982328887631217471460895254975277369296757574187051074891024171590437552144226168950976774671613515252336487, 2).parameters()
        dh_priv_global = dh_generate_private_key(parameters)
        dh_pub = dh_generate_public_key(dh_priv_global)
        peer_dh_public_key = import_public_key(sender_dh_public_key_pem)
        shared_key_global = dh_generate_shared_key(dh_priv_global, peer_dh_public_key)
        rsa_signature = rsa_sign_message(rsa_priv_global, dh_get_public_bytes(dh_pub))

        username_bytes = pad_string(padded_username).encode('utf-8')
        dh_public_key_bytes = dh_get_public_bytes(dh_pub)

        # Get bytes array in the following format: b"b"[16 bytes username][256 bytes rsa signature][DH public key] 
        message = b"b" + username_bytes + rsa_signature + dh_public_key_bytes
        client_send(message)

    elif (code == "b"):
        # Message part 1 response (another client responded to this clients message request)
        # Note: This message is changed by the server and is different than the one that was sent by the other client
        if loggedIn == False:
            print("Error. Message response received but not logged in")
            print("Please try logging in again")
            return
        if len(msg_input_global) < 1:
            print("Error. Message reponse received but no stored message was found")
            return
        
        # Parse message
        padded_username = message[1:17].decode('utf-8')
        sender_rsa_signature = message[17:273]
        dh_public_key_len = int.from_bytes(message[273:275], 'little', signed=False)
        sender_dh_public_key_pem = message[275:275+dh_public_key_len]
        sender_rsa_pub_pem = message[275+dh_public_key_len:]

        sender_rsa_pub = import_public_key(sender_rsa_pub_pem)
        if rsa_validate_signature(sender_rsa_pub, sender_dh_public_key_pem, sender_rsa_signature) == False:
            print("Invalid RSA signature in received message response")
            return
        
        # Generate shared key
        peer_dh_public_key = import_public_key(sender_dh_public_key_pem)
        shared_key = dh_generate_shared_key(dh_priv_global, peer_dh_public_key)

        # Encrypt message and get HMAC
        iv = generate_iv()
        msg_enc = aes_cbc_encrypt_message(shared_key, pad_message(msg_input_global.encode('utf-8')), iv)
        hmac_key = get_sha256_hash(shared_key)
        hmac_sig = hmac_generate_signature(hmac_key, msg_enc)
        username_bytes = pad_string(padded_username).encode('utf-8')

        # Get string in the following format: "n"[16 bytes username][32 bytes hmac signature][16 bytes iv][Encrypted message]   
        message = b"n" + username_bytes + hmac_sig + iv + msg_enc
        client_send(message)

        # Since this is the last transaction from this user in this message, the message is assumed to be correctly received
        formatted_msg = username_global.strip() + ": " + msg_input_global
        write_msg_history(rsa_generate_public_key(rsa_priv_global), padded_username, formatted_msg)


    elif (code == "n"):
        # Message part 2

        padded_username_n = message[1:17].decode('utf-8')
        hmac_sig = message[17:49]
        iv = message[49:65]
        msg_enc = message[65:]

        hmac_key = get_sha256_hash(shared_key_global)
        if hmac_verify_signature(hmac_key, hmac_sig, msg_enc) == False:
            print("Invalid HMAC in final received message")
            return

        msg_dec = aes_cbc_decrypt_message(shared_key_global, msg_enc, iv)

        formatted_msg = padded_username_n.strip() + ": " + msg_dec.decode('utf-8')

        write_msg_history(rsa_generate_public_key(rsa_priv_global), padded_username_n, formatted_msg)
        print(formatted_msg)
        
    # else:
        # Invalid message recieved, it will be ignored


###############################
## MESSAGE STORAGE FUNCTIONS ##
###############################

# Write a new message in encrypted form to local storage
def write_msg_history(rsa_public_key, username, message):
    with open(username_global.strip() + " with " + username.strip() + ".msgenc", "a+b") as f:
        encrypted_msg = rsa_encrypt_message(rsa_public_key, pad_message(message.encode('utf-8'))) + b"kesterissmartandcool"
        f.write(encrypted_msg)

# Decrpyt a full message history between this user and another user, and print it
def read_msg_history(rsa_private_key, username):
    if os.path.exists(username_global.strip() + " with " + username.strip() + ".msgenc"):
        with open(username_global.strip() + " with " + username.strip() + ".msgenc", "rb") as f:
            file_contents = f.read()
            messages = file_contents.split(b"kesterissmartandcool")
            for enc_msg in messages:
                if enc_msg:
                    decrypted_msg = rsa_decrypt_message(rsa_private_key, enc_msg)
                    print(decrypted_msg.decode('utf-8'))
    else:
        print("There is no chat history between you and " + username.strip())

# Delete a file containing an entire message history between this user and another user
def delete_msg_history(username):
    if os.path.exists(username_global.strip() + " with " + username.strip() + ".msgenc"):
        os.remove(username_global.strip() + " with " + username.strip() + ".msgenc")
    else:
        print("There is no chat history between you and " + username.strip())
    

######################
## SOCKET FUNCTIONS ##
######################

client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
print("Connecting...")
client.connect(('server', 59000))

# This function gets called from a new thread in main()
def client_receive():
    while True:
        try:
            message = client.recv(4096)
        except:
            print('Socket error')
            print('Shutting down...')
            client.close()
            exit()
        if len(message) > 0:
            parse_message(message)

# This function is used to send a message in a byte array form to the server
def client_send(message):
    client.sendall(message)

##############
## COMMANDS ##
##############

loggedIn = False
rsa_priv_global = None
dh_priv_global = None
shared_key_global = None
username_global = ""
msg_input_global = ""

# This funtion runs when the user inputs the 'h' command
def help_cmd():
    print("h (help) - Show this list of commands")
    print("r (register) - Register a new account")
    print("l (login) - Login to an existing account")
    print("m (message) - Message another user")
    print("v (view) - View message history with a user")
    print("d (delete) - Delete message history with a user")
    print("u (logout) - Logout of account")
    print("q (quit) - Exit program safely")

# This funtion runs when the user inputs the 'r' command
def register_cmd():
    global rsa_priv_global
    global loggedIn
    global username_global

    loggedIn = False
    rsa_priv_global = rsa_generate_private_key()
    rsa_pub = rsa_generate_public_key(rsa_priv_global)

    username_global = ""
    while True:
        username_global = input("Please input a username: ")
        if len(username_global) > 0 and len(username_global) < 16:
            break
        print("Username must be between 1 and 16 characters")

    print("Saving new private key file...")
    file_name = username_global.strip() + ".pem"
    file_contents = rsa_get_private_bytes(rsa_priv_global).decode('utf-8')
    with open(file_name, 'w') as file:
        file.write(file_contents)
    print("Done. Please move the file to a secure location")

    username_bytes = pad_string(username_global).encode('utf-8')
    key_bytes = rsa_get_public_bytes(rsa_pub)

    # Get bytes array in the following format: b"r"[16 bytes username][rsa public key in PEM format]
    message = b"r" + username_bytes + key_bytes
    client_send(message)
    loggedIn = True

# This funtion runs when the user inputs the 'l' command
def login_cmd():
    global username_global
    global loggedIn

    loggedIn = False
    while True:
        username_global = input("Please input your existing username: ")
        if len(username_global) > 0 and len(username_global) < 16:
            break
        print("Username must be between 1 and 16 characters")
    
    username_bytes = pad_string(username_global).encode('utf-8')
    
    # Get string in the following format: "l"[16 bytes username]
    message = b"l" + username_bytes
    client_send(message)

# This funtion runs when the user inputs the 'm' command
def message_cmd():
    global username_global
    global loggedIn
    global rsa_priv_global
    global msg_input_global
    global dh_priv_global
    global rsa_priv_global

    if loggedIn == False:
        print("You must register or log in first to send a messge")
        return
    if rsa_priv_global == None:
        print("Error. Logged in but no RSA key found")
        print("Please try logging in again")
        loggedIn = False
        return
    
    while True:
        msg_username = input("Who do you want to message, input his/her username: ")
        if msg_username.strip() == username_global.strip():
            print("You cannot send a message to yourself")
            continue
        if len(msg_username) > 0 and len(msg_username) < 16:
            break
        print("Username must be between 1 and 16 characters")
    
    msg_input_global = ""
    while True:
        msg_input_global = input("Please input a message to send: ")
        if len(msg_input_global) > 0:
            break
        print("You must send at least one character")
    
    parameters = dh.DHParameterNumbers(31316445495521676428187952232369783442765586753757915473647765060453095814335222549808839990545027952239915350268690894477747998072001686126320547649416473918727167199143061764084117346011689165816814201810052181388047483724216779673510089716950796069695957492797890459863874914267921574565797661035685983056313213003768220589047111460978107861802482426073394045366004328266766772627142228827025902187242430995266734830211970256381182266075929430064372250311218544593519292433377081375401081361262592914015216982328887631217471460895254975277369296757574187051074891024171590437552144226168950976774671613515252336487, 2).parameters()
    dh_priv_global = dh_generate_private_key(parameters)
    dh_pub = dh_generate_public_key(dh_priv_global)
    dh_public_key_bytes = dh_get_public_bytes(dh_pub)
    rsa_signature = rsa_sign_message(rsa_priv_global, dh_public_key_bytes)

    username_bytes = pad_string(msg_username).encode('utf-8')

    # Get byte array in the following format: b"m"[16 bytes username][256 bytes rsa signature][DH public key] 
    message = b"m" + username_bytes + rsa_signature + dh_public_key_bytes
    client_send(message)

# This funtion runs when the user inputs the 'v' command
def view_cmd():
    global loggedIn
    global rsa_priv_global
    global username_global

    if loggedIn == False:
        print("You must be logged in to view message history")
        return
    if rsa_priv_global == None:
        print("Error. Logged in but RSA key not found")
        return
    if username_global == "":
        print("Error. Logged in but username not found")
        return
    
    while True:
        msg_username = input("Please input the other user's username of the conversation you would like to view: ")
        if len(msg_username) > 0 and len(msg_username) < 16:
            break
        print("Username must be between 1 and 16 characters")
    read_msg_history(rsa_priv_global, msg_username)

# This funtion runs when the user inputs the 'd' command
def delete_cmd():
    while True:
        msg_username = input("Please input the other user's username of the conversation you would like to delete: ")
        if len(msg_username) > 0 and len(msg_username) < 16:
            break
        print("Username must be between 1 and 16 characters")
    
    confirm = input("This process is irreversable, please input 'continue' to continue: ")
    if confirm == "continue":
        print("Deleting conversation...")
        delete_msg_history(pad_string(msg_username))
    else:
        print("Cancelling...")

# This funtion runs when the user inputs the 'u' command
def logout_cmd():
    global loggedIn

    client_send(b"u")
    loggedIn = False
    print("Logging out...")

# This funtion runs when the user inputs the 'q' command
def quit_cmd():
    client_send(b"q")
    exit()

##########
## MAIN ##
##########

def main():
    # Start a thread to accept any messages
    thread = threading.Thread(target=client_receive, daemon=True)
    thread.start()
    print("Welcome to encrypted messenger")
    print("Input h to see a list of available commands")
    while(True):
        cmd = input("> ")
        if len(cmd) == 0:
            continue
        if (cmd[0] == "h"):
            help_cmd()
        if (cmd[0] == "r"):
            register_cmd()
        if (cmd[0] == "u" or cmd == "logout"):
            logout_cmd()
        if (cmd[0] == "l"):
            login_cmd()
        if (cmd[0] == "m"):
            message_cmd()
        if (cmd[0] == "v"):
            view_cmd()
        if (cmd[0] == "d"):
            delete_cmd()
        if (cmd[0] == "q"):
            quit_cmd()

if __name__ == "__main__":
    main()
