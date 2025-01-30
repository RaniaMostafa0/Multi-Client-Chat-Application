# server.py

import socket
import threading
import sqlite3
import json
import os
import ssl
import time
import logging
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding

# =================
# LOGGING CONFIGURATION
# =================
logging.basicConfig(
    level=logging.DEBUG,  # Set to DEBUG for detailed logs
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("server.log"),
        logging.StreamHandler()
    ]
)

# =================
# KEY MANAGEMENT
# =================
def load_or_create_key(file_path="encryption.key"):
    """
    Load the Fernet key from a file if it exists;
    otherwise, generate a new key and store it.
    """
    if os.path.exists(file_path):
        with open(file_path, "rb") as f:
            key = f.read()
        logging.info(f"Loaded existing encryption key from {file_path}.")
    else:
        key = Fernet.generate_key()
        with open(file_path, "wb") as f:
            f.write(key)
        logging.info(f"Generated new encryption key and saved to {file_path}.")
    return key

encryption_key = load_or_create_key()
cipher_suite = Fernet(encryption_key)

# ==================
# SHARED SYMMETRIC KEY MANAGEMENT
# ==================
def load_or_create_shared_key(file_path="shared.key"):
    """
    Load the shared symmetric key from a file if it exists;
    otherwise, generate a new key and store it.
    """
    if os.path.exists(file_path):
        with open(file_path, "rb") as f:
            key = f.read()
        logging.info(f"Loaded existing shared symmetric key from {file_path}.")
    else:
        key = Fernet.generate_key()
        with open(file_path, "wb") as f:
            f.write(key)
        logging.info(f"Generated new shared symmetric key and saved to {file_path}.")
    return key

shared_key = load_or_create_shared_key()
shared_fernet = Fernet(shared_key)

# ==================
# DATABASE SETUP
# ==================
def setup_database(db_path="clients.db"):
    """
    Ensure the clients.db has the required tables:
    - clients: to store username and encrypted public keys
    - messages: to store encrypted chat history
    """
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()

    # Create clients table if it doesn't exist
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS clients (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            public_key TEXT NOT NULL
        )
    """)

    # Create messages table if it doesn't exist
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS messages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            sender TEXT NOT NULL,
            recipient TEXT NOT NULL,
            message TEXT NOT NULL,
            timestamp INTEGER NOT NULL
        )
    """)

    conn.commit()
    conn.close()
    logging.info("Database setup complete.")

def add_or_update_client(username, public_key, db_path="clients.db"):
    """
    Insert or update a client's public key in the database.
    Public key is stored encrypted via Fernet.
    """
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    encrypted_public_key = cipher_suite.encrypt(public_key.encode())
    cursor.execute(
        "INSERT INTO clients (username, public_key) VALUES (?, ?) "
        "ON CONFLICT(username) DO UPDATE SET public_key=excluded.public_key",
        (username, encrypted_public_key)
    )
    conn.commit()
    conn.close()
    logging.info(f"Added/Updated client '{username}' in database.")

def get_all_clients(db_path="clients.db"):
    """
    Return a dict {username: public_key (decrypted)} for all clients in DB.
    """
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    cursor.execute("SELECT username, public_key FROM clients")
    rows = cursor.fetchall()
    conn.close()

    # Decrypt the public keys
    clients = {}
    for row in rows:
        username, encrypted_public_key = row
        try:
            public_key = cipher_suite.decrypt(encrypted_public_key).decode()
            clients[username] = public_key
        except Exception as e:
            logging.error(f"Failed to decrypt public key for user '{username}': {e}")
    return clients

def store_message_in_db(sender, recipient, message, db_path="clients.db"):
    """
    Store an encrypted message in the messages table with a timestamp.
    The message is first encrypted by the client using shared_fernet (or RSA for private messages).
    To secure it at rest, the server encrypts the already encrypted message again using cipher_suite.
    """
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    timestamp = int(time.time())  # store an integer timestamp

    try:
        # Encrypt the already encrypted message with cipher_suite
        double_encrypted_message = cipher_suite.encrypt(message.encode()).decode()
        cursor.execute(
            "INSERT INTO messages (sender, recipient, message, timestamp) VALUES (?, ?, ?, ?)",
            (sender, recipient, double_encrypted_message, timestamp)
        )
        conn.commit()
        logging.info(f"Stored message from '{sender}' to '{recipient}' in database.")
    except Exception as e:
        logging.error(f"Failed to store message from '{sender}' to '{recipient}': {e}")
    finally:
        conn.close()

def get_user_messages(username, db_path="clients.db"):
    """
    Retrieve all messages sent by or to a specific user.
    Includes broadcast ('All') and self ('Self') messages.
    Returns a list of dictionaries with keys: sender, recipient, message, timestamp.
    The messages are decrypted using cipher_suite before being returned.
    """
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    cursor.execute("""
        SELECT sender, recipient, message, timestamp 
        FROM messages 
        WHERE sender = ? OR recipient = ? OR recipient = 'All' OR recipient = 'Self'
        ORDER BY timestamp ASC
    """, (username, username))
    rows = cursor.fetchall()
    conn.close()

    messages = []
    for row in rows:
        sender, recipient, encrypted_message, timestamp = row
        # For private messages, ensure that only messages sent to the user or by the user are included
        if recipient not in ["All", "Self"] and sender != username and recipient != username:
            continue
        try:
            # Decrypt the message with cipher_suite
            decrypted_message = cipher_suite.decrypt(encrypted_message.encode()).decode()
            messages.append({
                "sender": sender,
                "recipient": recipient,
                "message": decrypted_message,
                "timestamp": timestamp
            })
        except Exception as e:
            logging.error(f"Failed to decrypt message from '{sender}' to '{recipient}': {e}")
    logging.info(f"Retrieved messages for user '{username}' from database.")
    return messages

# =====================
# SERVER FUNCTIONALITY
# =====================
clients = {}  # Mapping: username -> client socket
clients_lock = threading.Lock()
all_users = set()  # Set of all usernames

def broadcast_user_list():
    """
    Broadcast the list of all users along with their connection statuses and public keys to every connected client.
    """
    with clients_lock:
        user_status = {}
        current_connected_users = set(clients.keys())
        for user in all_users:
            user_status[user] = "Connected" if user in current_connected_users else "Disconnected"

        # Fetch all public keys
        public_keys = get_all_clients()

        # Build the user data
        user_data = {
            "type": "user_list",
            "users": user_status,
            "public_keys": public_keys  # Include public keys
        }

        # Send the data to all connected clients
        message = json.dumps(user_data) + "\n"
        for user, client in clients.items():
            try:
                client.send(message.encode())
                logging.debug(f"Sent user list to '{user}'.")
            except Exception as e:
                logging.error(f"Failed to send user list to '{user}': {e}")

def broadcast_message(sender, message, recipient="All"):
    """
    Broadcast a message to a specific recipient or all.
    Also store the message in the database for future retrieval.
    """
    # Store message in DB
    store_message_in_db(sender, recipient, message)

    # Now broadcast to relevant clients
    with clients_lock:
        if recipient not in ["All", "Self"] and recipient not in clients:
            # Recipient is disconnected or does not exist
            try:
                sender_socket = clients.get(sender)
                if sender_socket:
                    error_msg = json.dumps({
                        "type": "error",
                        "message": f"User '{recipient}' is not connected. Message not delivered."
                    }) + "\n"
                    sender_socket.send(error_msg.encode())
                    logging.info(f"Notified '{sender}' that '{recipient}' is not connected.")
            except Exception as e:
                logging.error(f"Failed to notify '{sender}': {e}")
            return

        for user, client in clients.items():
            if recipient == "All":
                try:
                    # Forward the encrypted message as-is (already encrypted by client)
                    data = {
                        "type": "message",
                        "sender": sender,
                        "message": message,  # Already encrypted by client
                        "recipient": recipient
                    }
                    message_str = json.dumps(data) + "\n"
                    client.send(message_str.encode())
                    logging.debug(f"Sent broadcast message from '{sender}' to '{user}'.")
                except Exception as e:
                    logging.error(f"Failed to send broadcast message to '{user}': {e}")
            elif recipient == "Self":
                if user == sender:
                    try:
                        # Forward the encrypted message as-is
                        data = {
                            "type": "message",
                            "sender": sender,
                            "message": message,  # Already encrypted by client
                            "recipient": recipient
                        }
                        message_str = json.dumps(data) + "\n"
                        client.send(message_str.encode())
                        logging.debug(f"Sent self message from '{sender}' to themselves.")
                    except Exception as e:
                        logging.error(f"Failed to send self message to '{user}': {e}")
            else:
                if user == recipient:
                    try:
                        # Private messages are already encrypted by sender
                        data = {
                            "type": "message",
                            "sender": sender,
                            "message": message,  # Already encrypted by sender
                            "recipient": recipient
                        }
                        message_str = json.dumps(data) + "\n"
                        client.send(message_str.encode())
                        logging.debug(f"Sent private message from '{sender}' to '{user}'.")
                    except Exception as e:
                        logging.error(f"Failed to send private message to '{user}': {e}")

def send_shared_key(client_socket, public_key_pem):
    """
    Encrypt the shared symmetric key with the client's public RSA key and send it.
    """
    try:
        public_key = serialization.load_pem_public_key(public_key_pem.encode())
        encrypted_shared_key = public_key.encrypt(
            shared_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        # Send the encrypted shared key as a hex string
        data = {
            "type": "shared_key",
            "shared_key": encrypted_shared_key.hex()
        }
        message_str = json.dumps(data) + "\n"
        client_socket.send(message_str.encode())
        logging.debug("Sent encrypted shared key to client.")
    except Exception as e:
        logging.error(f"Failed to send shared key to client: {e}")

def remove_client(username):
    """
    Safely remove client from the connected users and broadcast updated user list.
    """
    with clients_lock:
        if username in clients:
            del clients[username]
            logging.info(f"{username} disconnected and removed from active clients.")
        
        # Keep the username in all_users but mark it as Disconnected
        if username in all_users:
            logging.info(f"{username} marked as Disconnected.")

    try:
        broadcast_user_list()
    except Exception as e:
        logging.error(f"Error broadcasting user list after '{username}' disconnect: {e}")

def send_chat_history(client, username):
    """
    Send all relevant messages (sent and received) to the newly connected client.
    """
    all_messages = get_user_messages(username)
    history_data = {
        "type": "history",
        "messages": all_messages
    }
    try:
        message_str = json.dumps(history_data) + "\n"
        client.send(message_str.encode())
        logging.debug(f"Sent chat history to '{username}'.")
    except Exception as e:
        logging.error(f"Failed to send chat history to '{username}': {e}")

def handle_client(client_socket, addr):
    """
    Main per-client thread function:
    1. Receives username/public_key
    2. Adds to DB
    3. Sends the shared symmetric key encrypted with the client's public key
    4. Waits for acknowledgment
    5. Updates connected users
    6. Sends chat history (all relevant messages)
    7. Listens for messages
    """
    username = None
    try:
        client_socket.settimeout(60)  # 60 seconds timeout

        data = client_socket.recv(4096).decode()
        if not data:
            raise ValueError("No data received from client.")
        try:
            data = json.loads(data)
        except json.JSONDecodeError:
            raise ValueError("Invalid JSON data received.")

        username = data.get("username")
        public_key = data.get("public_key")

        if not username or not public_key:
            raise ValueError("Incomplete data: 'username' or 'public_key' missing.")

        with clients_lock:
            if username in clients:
                old_socket = clients[username]
                try:
                    disconnect_message = json.dumps({
                        "type": "disconnect",
                        "message": "You have been disconnected due to a new login from the same username."
                    }) + "\n"
                    old_socket.send(disconnect_message.encode())
                    logging.info(f"Sent disconnect message to '{username}' (old connection).")
                except Exception as e:
                    logging.error(f"Failed to send disconnect message to '{username}': {e}")
                old_socket.close()
                del clients[username]
                logging.info(f"User '{username}' reconnected. Old connection closed.")

            add_or_update_client(username, public_key)
            clients[username] = client_socket
            all_users.add(username)
            logging.info(f"'{username}' connected from {addr}.")

        # Send the shared symmetric key encrypted with the client's public key
        send_shared_key(client_socket, public_key)

        # Wait for acknowledgment
        try:
            ack = client_socket.recv(1024).decode().strip()
            if ack != "KEY_RECEIVED":
                raise ValueError("Client failed to acknowledge shared key.")
            logging.debug(f"Received acknowledgment from '{username}'.")
        except Exception as e:
            logging.error(f"Error waiting for acknowledgment from '{username}': {e}")
            remove_client(username)
            client_socket.close()
            return

        # Proceed with broadcasting user list and sending chat history
        broadcast_user_list()
        send_chat_history(client_socket, username)

        client_socket.settimeout(None)  # Remove timeout after initial setup

        while True:
            try:
                data = client_socket.recv(4096).decode()
                if not data:
                    logging.info(f"No data received. Closing connection for '{username}'.")
                    break

                messages = data.strip().split('\n')
                for msg_str in messages:
                    if not msg_str:
                        continue
                    try:
                        msg = json.loads(msg_str)
                    except json.JSONDecodeError:
                        logging.warning(f"Received invalid JSON from '{username}'.")
                        continue

                    if msg["type"] == "message":
                        sender = msg["sender"]
                        message = msg["message"]
                        recipient = msg["recipient"]
                        broadcast_message(sender, message, recipient)

                    elif msg["type"] == "request_user_list":
                        logging.debug(f"Received user list refresh request from '{username}'.")
                        broadcast_user_list()

            except socket.timeout:
                logging.warning(f"Connection timeout for '{username}'. Disconnecting.")
                break
            except Exception as e:
                logging.error(f"Error while communicating with '{username}': {e}")
                break

    except Exception as e:
        logging.error(f"Error in handle_client: {e}")
    finally:
        if username:
            remove_client(username)
            client_socket.close()
            logging.info(f"Connection closed for '{username}'.")

def start_server():
    setup_database()  # Ensure DB is ready

    # Server address and port
    server_address = ("0.0.0.0", 12345)

    # Create SSL context
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(certfile="server.crt", keyfile="server.key")

    # Create and bind the server socket
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(server_address)
    server.listen(5)
    logging.info(f"Server is running on {server_address[0]}:{server_address[1]} with TLS...")

    while True:
        try:
            client, addr = server.accept()
            # Wrap the client socket with SSL
            ssl_client = context.wrap_socket(client, server_side=True)
            logging.info(f"Accepted TLS connection from {addr}.")
            threading.Thread(target=handle_client, args=(ssl_client, addr), daemon=True).start()
        except Exception as e:
            logging.error(f"Error accepting connections: {e}")

if __name__ == "__main__":
    start_server()
