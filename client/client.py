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

# Encrypt a message using an RSA public key
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

# Pad a string with spaces until it has 16 characters
def pad_string(message):
    while len(message) % 16 != 0:
        message += ' '
    return message


class ChatClient:
    """High-level client for the encrypted chat protocol.

    The class wraps socket I/O, crypto flows, and local history storage.
    Use the on_event callback to stream updates into a UI or CLI.
    """

    def __init__(self, host="server", port=59000, on_event=None):
        self.host = host
        self.port = port
        self.on_event = on_event or (lambda text, kind: None)
        self._receiver_thread = None
        self._event_lock = threading.Lock()

        self.logged_in = False
        self.rsa_priv = None
        self.dh_priv = None
        self.shared_key = None
        self.username = ""
        self._pending_msg = ""
        self.last_status = ""

        self.client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.client.connect((self.host, self.port))

    def start_receiver(self):
        if self._receiver_thread and self._receiver_thread.is_alive():
            return
        thread = threading.Thread(target=self._client_receive, daemon=True)
        thread.start()
        self._receiver_thread = thread

    def _emit(self, text, kind="system"):
        with self._event_lock:
            try:
                self.on_event(text, kind)
            except Exception:
                pass

    def _client_receive(self):
        while True:
            try:
                message = self.client.recv(4096)
            except Exception:
                self._emit("Socket error", "system")
                self._emit("Shutting down...", "system")
                try:
                    self.client.close()
                except Exception:
                    pass
                return
            if len(message) > 0:
                self.parse_message(message)

    def _client_send(self, message):
        self.client.sendall(message)

    # This function is called whenever a message is received by the server.
    # The server will change the username in the message from the receiver to the sender,
    # and will also append the sender's RSA public key in some cases.
    def parse_message(self, message):
        code = chr(message[0])
        if (code == "l"):
            # Login part 1 response
            nonce = message[1:]
            if self.username == "":
                self._emit("Error. Log in response received but no username found", "system")
                self._emit("Please try logging in again", "system")
                return

            # Open private key file
            try:
                file_name = self.username.strip() + ".pem"
                with open(file_name, "r") as f:
                    rsa_priv_pem = f.read()
            except Exception:
                self._emit("Private key file invalid or not found", "system")
                return

            self.rsa_priv = import_private_key(rsa_priv_pem.encode('utf-8'))

            signature = rsa_sign_message(self.rsa_priv, nonce)
            username_bytes = pad_string(self.username).encode('utf-8')

            # Get a byte array in the following format: b"s"[16 bytes username][rsa signature]
            message = b"s" + username_bytes + signature

            self._client_send(message)

        elif (code == "e"):
            # Status or error message from server
            print_msg = message[1:].decode('utf-8')
            if print_msg.startswith("Login Success"):
                self.logged_in = True
                self.last_status = "Login Success"
            elif print_msg.startswith("Register Success"):
                self.logged_in = False
                self.last_status = "Registration Success"
            else:
                self.last_status = print_msg
            self._emit(print_msg, "system")

        elif (code == "m"):
            # Message part 1 (another client is attempting to send a message to this client)
            if self.logged_in == False:
                self._emit("Error. Message request received but not logged in", "system")
                self._emit("Please try logging in again", "system")
                return
            if self.rsa_priv == None:
                self._emit("Error. Message request received but no RSA key found", "system")
                self._emit("Please try logging in again", "system")
                return

            padded_username = message[1:17].decode('utf-8')
            sender_rsa_signature = message[17:273]
            dh_public_key_len = int.from_bytes(message[273:275], 'little', signed=False)
            sender_dh_public_key_pem = message[275:275+dh_public_key_len]
            sender_rsa_pub_pem = message[275+dh_public_key_len:]

            sender_rsa_pub = import_public_key(sender_rsa_pub_pem)
            if rsa_validate_signature(sender_rsa_pub, sender_dh_public_key_pem, sender_rsa_signature) == False:
                self._emit("Invalid RSA signature in received message", "system")
                return

            # Create DH keys and sign DH public key
            parameters = dh.DHParameterNumbers(31316445495521676428187952232369783442765586753757915473647765060453095814335222549808839990545027952239915350268690894477747998072001686126320547649416473918727167199143061764084117346011689165816814201810052181388047483724216779673510089716950796069695957492797890459863874914267921574565797661035685983056313213003768220589047111460978107861802482426073394045366004328266766772627142228827025902187242430995266734830211970256381182266075929430064372250311218544593519292433377081375401081361262592914015216982328887631217471460895254975277369296757574187051074891024171590437552144226168950976774671613515252336487, 2).parameters()
            self.dh_priv = dh_generate_private_key(parameters)
            dh_pub = dh_generate_public_key(self.dh_priv)
            peer_dh_public_key = import_public_key(sender_dh_public_key_pem)
            self.shared_key = dh_generate_shared_key(self.dh_priv, peer_dh_public_key)
            rsa_signature = rsa_sign_message(self.rsa_priv, dh_get_public_bytes(dh_pub))

            username_bytes = pad_string(padded_username).encode('utf-8')
            dh_public_key_bytes = dh_get_public_bytes(dh_pub)

            # Get bytes array in the following format: b"b"[16 bytes username][256 bytes rsa signature][DH public key]
            message = b"b" + username_bytes + rsa_signature + dh_public_key_bytes
            self._client_send(message)

        elif (code == "b"):
            # Message part 1 response (another client responded to this clients message request)
            if self.logged_in == False:
                self._emit("Error. Message response received but not logged in", "system")
                self._emit("Please try logging in again", "system")
                return
            if len(self._pending_msg) < 1:
                self._emit("Error. Message response received but no stored message was found", "system")
                return

            # Parse message
            padded_username = message[1:17].decode('utf-8')
            sender_rsa_signature = message[17:273]
            dh_public_key_len = int.from_bytes(message[273:275], 'little', signed=False)
            sender_dh_public_key_pem = message[275:275+dh_public_key_len]
            sender_rsa_pub_pem = message[275+dh_public_key_len:]

            sender_rsa_pub = import_public_key(sender_rsa_pub_pem)
            if rsa_validate_signature(sender_rsa_pub, sender_dh_public_key_pem, sender_rsa_signature) == False:
                self._emit("Invalid RSA signature in received message response", "system")
                return

            # Generate shared key
            peer_dh_public_key = import_public_key(sender_dh_public_key_pem)
            shared_key = dh_generate_shared_key(self.dh_priv, peer_dh_public_key)

            # Encrypt message and get HMAC
            iv = generate_iv()
            msg_enc = aes_cbc_encrypt_message(shared_key, pad_message(self._pending_msg.encode('utf-8')), iv)
            hmac_key = get_sha256_hash(shared_key)
            hmac_sig = hmac_generate_signature(hmac_key, msg_enc)
            username_bytes = pad_string(padded_username).encode('utf-8')

            # Get string in the following format: "n"[16 bytes username][32 bytes hmac signature][16 bytes iv][Encrypted message]
            message = b"n" + username_bytes + hmac_sig + iv + msg_enc
            self._client_send(message)

            # Since this is the last transaction from this user in this message, the message is assumed to be correctly received
            formatted_msg = self.username.strip() + ": " + self._pending_msg
            self.write_msg_history(rsa_generate_public_key(self.rsa_priv), padded_username, formatted_msg)
            self._emit(formatted_msg, "message")

        elif (code == "n"):
            # Message part 2

            padded_username_n = message[1:17].decode('utf-8')
            hmac_sig = message[17:49]
            iv = message[49:65]
            msg_enc = message[65:]

            hmac_key = get_sha256_hash(self.shared_key)
            if hmac_verify_signature(hmac_key, hmac_sig, msg_enc) == False:
                self._emit("Invalid HMAC in final received message", "system")
                return

            msg_dec = aes_cbc_decrypt_message(self.shared_key, msg_enc, iv)

            formatted_msg = padded_username_n.strip() + ": " + msg_dec.decode('utf-8')

            self.write_msg_history(rsa_generate_public_key(self.rsa_priv), padded_username_n, formatted_msg)
            self._emit(formatted_msg, "message")

        # else:
            # Invalid message received, it will be ignored

    ###############################
    ## MESSAGE STORAGE FUNCTIONS ##
    ###############################

    # Write a new message in encrypted form to local storage
    def write_msg_history(self, rsa_public_key, username, message):
        with open(self.username.strip() + " with " + username.strip() + ".msgenc", "a+b") as f:
            encrypted_msg = rsa_encrypt_message(rsa_public_key, pad_message(message.encode('utf-8'))) + b"kesterissmartandcool"
            f.write(encrypted_msg)

    # Decrypt a full message history between this user and another user
    def read_msg_history(self, rsa_private_key, username):
        history_file = self.username.strip() + " with " + username.strip() + ".msgenc"
        if os.path.exists(history_file):
            messages_out = []
            with open(history_file, "rb") as f:
                file_contents = f.read()
                messages = file_contents.split(b"kesterissmartandcool")
                for enc_msg in messages:
                    if enc_msg:
                        decrypted_msg = rsa_decrypt_message(rsa_private_key, enc_msg)
                        messages_out.append(decrypted_msg.decode('utf-8'))
            return messages_out

        self._emit("There is no chat history between you and " + username.strip(), "system")
        return []

    # Delete a file containing an entire message history between this user and another user
    def delete_msg_history(self, username):
        history_file = self.username.strip() + " with " + username.strip() + ".msgenc"
        if os.path.exists(history_file):
            os.remove(history_file)
            self._emit("Deleted history with " + username.strip(), "system")
        else:
            self._emit("There is no chat history between you and " + username.strip(), "system")

    ######################
    ## PUBLIC COMMANDS  ##
    ######################

    def register(self, username):
        self.logged_in = False
        username = (username or "").strip()
        if len(username) < 1 or len(username) > 15:
            self._emit("Username must be between 1 and 16 characters", "system")
            return False

        self.rsa_priv = rsa_generate_private_key()
        rsa_pub = rsa_generate_public_key(self.rsa_priv)
        self.username = username

        self._emit("Saving new private key file...", "system")
        file_name = self.username.strip() + ".pem"
        file_contents = rsa_get_private_bytes(self.rsa_priv).decode('utf-8')
        with open(file_name, 'w') as file:
            file.write(file_contents)
        self._emit("Done. Please move the file to a secure location", "system")

        username_bytes = pad_string(self.username).encode('utf-8')
        key_bytes = rsa_get_public_bytes(rsa_pub)

        # Get bytes array in the following format: b"r"[16 bytes username][rsa public key in PEM format]
        message = b"r" + username_bytes + key_bytes
        self._client_send(message)
        return True

    def login(self, username):
        self.logged_in = False
        username = (username or "").strip()
        if len(username) < 1 or len(username) > 15:
            self._emit("Username must be between 1 and 16 characters", "system")
            return False

        self.username = username
        username_bytes = pad_string(self.username).encode('utf-8')

        # Get string in the following format: "l"[16 bytes username]
        message = b"l" + username_bytes
        self._client_send(message)
        return True

    def send_message(self, to_username, message_text):
        if self.logged_in == False:
            self._emit("You must register or log in first to send a message", "system")
            return False
        if self.rsa_priv == None:
            self._emit("Error. Logged in but no RSA key found", "system")
            self._emit("Please try logging in again", "system")
            self.logged_in = False
            return False

        to_username = (to_username or "").strip()
        if to_username == self.username.strip():
            self._emit("You cannot send a message to yourself", "system")
            return False
        if len(to_username) < 1 or len(to_username) > 15:
            self._emit("Username must be between 1 and 16 characters", "system")
            return False

        message_text = (message_text or "")
        if len(message_text) < 1:
            self._emit("You must send at least one character", "system")
            return False

        self._pending_msg = message_text

        parameters = dh.DHParameterNumbers(31316445495521676428187952232369783442765586753757915473647765060453095814335222549808839990545027952239915350268690894477747998072001686126320547649416473918727167199143061764084117346011689165816814201810052181388047483724216779673510089716950796069695957492797890459863874914267921574565797661035685983056313213003768220589047111460978107861802482426073394045366004328266766772627142228827025902187242430995266734830211970256381182266075929430064372250311218544593519292433377081375401081361262592914015216982328887631217471460895254975277369296757574187051074891024171590437552144226168950976774671613515252336487, 2).parameters()
        self.dh_priv = dh_generate_private_key(parameters)
        dh_pub = dh_generate_public_key(self.dh_priv)
        dh_public_key_bytes = dh_get_public_bytes(dh_pub)
        rsa_signature = rsa_sign_message(self.rsa_priv, dh_public_key_bytes)

        username_bytes = pad_string(to_username).encode('utf-8')

        # Get byte array in the following format: b"m"[16 bytes username][256 bytes rsa signature][DH public key]
        message = b"m" + username_bytes + rsa_signature + dh_public_key_bytes
        self._client_send(message)
        return True

    def view_history(self, other_username):
        if self.logged_in == False:
            self._emit("You must be logged in to view message history", "system")
            return []
        if self.rsa_priv == None:
            self._emit("Error. Logged in but RSA key not found", "system")
            return []
        if self.username == "":
            self._emit("Error. Logged in but username not found", "system")
            return []

        other_username = (other_username or "").strip()
        if len(other_username) < 1 or len(other_username) > 15:
            self._emit("Username must be between 1 and 16 characters", "system")
            return []

        return self.read_msg_history(self.rsa_priv, other_username)

    def delete_history(self, other_username):
        other_username = (other_username or "").strip()
        if len(other_username) < 1 or len(other_username) > 15:
            self._emit("Username must be between 1 and 16 characters", "system")
            return False

        self.delete_msg_history(pad_string(other_username))
        return True

    def logout(self):
        self._client_send(b"u")
        self.logged_in = False
        self._emit("Logging out...", "system")

    def quit(self):
        try:
            self._client_send(b"q")
        except Exception:
            pass
        try:
            self.client.close()
        except Exception:
            pass


##############
## COMMANDS ##
##############

# This function runs when the user inputs the 'h' command
def help_cmd():
    print("h (help) - Show this list of commands")
    print("r (register) - Register a new account")
    print("l (login) - Login to an existing account")
    print("m (message) - Message another user")
    print("v (view) - View message history with a user")
    print("d (delete) - Delete message history with a user")
    print("u (logout) - Logout of account")
    print("q (quit) - Exit program safely")


##########
## MAIN ##
##########

def run_cli():
    def print_event(text, kind):
        print(text)

    client = ChatClient(on_event=print_event)
    client.start_receiver()

    print("Welcome to encrypted messenger")
    print("Input h to see a list of available commands")
    while(True):
        cmd = input("> ")
        if len(cmd) == 0:
            continue
        if (cmd[0] == "h"):
            help_cmd()
        if (cmd[0] == "r"):
            username = input("Please input a username: ")
            client.register(username)
        if (cmd[0] == "u" or cmd == "logout"):
            client.logout()
        if (cmd[0] == "l"):
            username = input("Please input your existing username: ")
            client.login(username)
        if (cmd[0] == "m"):
            msg_username = input("Who do you want to message, input his/her username: ")
            msg_input = input("Please input a message to send: ")
            client.send_message(msg_username, msg_input)
        if (cmd[0] == "v"):
            msg_username = input("Please input the other user's username of the conversation you would like to view: ")
            history = client.view_history(msg_username)
            for msg in history:
                print(msg)
        if (cmd[0] == "d"):
            msg_username = input("Please input the other user's username of the conversation you would like to delete: ")
            confirm = input("This process is irreversible, please input 'continue' to continue: ")
            if confirm == "continue":
                print("Deleting conversation...")
                client.delete_history(msg_username)
            else:
                print("Cancelling...")
        if (cmd[0] == "q"):
            client.quit()
            break


if __name__ == "__main__":
    run_cli()
