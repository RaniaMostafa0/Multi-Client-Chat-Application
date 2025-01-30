# client.py

import socket
import threading
import tkinter as tk
from tkinter import messagebox, simpledialog
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.fernet import Fernet
import json
import queue
import os
import ssl
import tkinter.scrolledtext as scrolledtext
import tkinter.ttk as ttk  # Import ttk for Notebook
import logging

# ==================
# LOGGING CONFIGURATION
# ==================
logging.basicConfig(
    level=logging.DEBUG,  # Set to DEBUG for detailed logs
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("client.log"),
        logging.StreamHandler()
    ]
)

# ==================
# RSA KEY MANAGEMENT
# ==================
def load_or_create_keys(private_key_path="private_key.pem", public_key_path="public_key.pem"):
    """
    Load existing RSA keys from files or generate new ones if they don't exist.
    """
    if os.path.exists(private_key_path) and os.path.exists(public_key_path):
        with open(private_key_path, "rb") as f:
            private_key = serialization.load_pem_private_key(
                f.read(),
                password=None
            )
        with open(public_key_path, "rb") as f:
            public_key = serialization.load_pem_public_key(f.read())
        logging.info("Loaded existing RSA key pair.")
    else:
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )
        public_key = private_key.public_key()

        # Serialize and save the private key
        with open(private_key_path, "wb") as f:
            f.write(
                private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.TraditionalOpenSSL,
                    encryption_algorithm=serialization.NoEncryption()
                )
            )

        # Serialize and save the public key
        with open(public_key_path, "wb") as f:
            f.write(
                public_key.public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo
                )
            )
        logging.info("Generated and saved new RSA key pair.")
    return private_key, public_key

private_key, public_key = load_or_create_keys()

# Serialize public key in PEM format
public_key_pem = public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
).decode()

# ==================
# SHARED SYMMETRIC KEY FOR BROADCAST
# ==================
shared_fernet = None  # Will be initialized after receiving from server

# ============
# GLOBAL STATE
# ============
public_keys = {}   # Store other users' public keys
username = None
client_socket = None

root = None
message_entry = None
recipient_var = None
user_listbox = None
notebook = None
chat_tabs = {}  # Dictionary to keep track of chat tabs

# Queue for thread-safe GUI updates
gui_queue = queue.Queue()

# ==================
# RECEIVE_SHARED_KEY FUNCTION
# ==================
def receive_shared_key(encrypted_shared_key_hex):
    """
    Decrypt the shared symmetric key using the client's private RSA key.
    """
    global shared_fernet
    try:
        logging.debug("Attempting to decrypt the shared symmetric key.")
        encrypted_shared_key = bytes.fromhex(encrypted_shared_key_hex)
        decrypted_shared_key = private_key.decrypt(
            encrypted_shared_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        shared_fernet = Fernet(decrypted_shared_key)
        logging.info("Shared symmetric key decrypted and shared_fernet initialized.")

        # Send acknowledgment to the server
        ack_message = "KEY_RECEIVED\n"
        client_socket.send(ack_message.encode())
        logging.debug("Acknowledgment sent to server.")
        return decrypted_shared_key
    except Exception as e:
        logging.error(f"Failed to decrypt shared key: {e}")
        messagebox.showerror("Error", f"Failed to decrypt shared key: {e}")
        return None

# =================
# RECEIVING THREAD
# =================
def receive_messages():
    buffer = ""
    while True:
        try:
            data = client_socket.recv(4096).decode()
            if not data:
                logging.warning("No data received. Connection might be closed.")
                gui_queue.put(("connection_lost", "Disconnected from the server."))
                break
            buffer += data
            while "\n" in buffer:
                message_str, buffer = buffer.split("\n", 1)
                if not message_str:
                    continue
                try:
                    msg = json.loads(message_str)
                except json.JSONDecodeError:
                    logging.warning("Received malformed JSON.")
                    continue

                if msg["type"] == "user_list":
                    # Update user list with statuses
                    users = msg["users"]
                    gui_queue.put(("user_list", users))

                    # Update public_keys dictionary
                    if "public_keys" in msg:
                        public_keys.update(msg["public_keys"])
                        logging.info("Updated public keys.")

                elif msg["type"] == "shared_key":
                    encrypted_shared_key_hex = msg["shared_key"]
                    decrypted_shared_key = receive_shared_key(encrypted_shared_key_hex)
                    if decrypted_shared_key:
                        logging.info("Shared symmetric key received and decrypted successfully.")
                    else:
                        gui_queue.put(("connection_lost", "Failed to receive shared key. Disconnecting."))

                elif msg["type"] == "message":
                    sender = msg["sender"]
                    recipient = msg["recipient"]
                    encrypted_content = msg["message"]

                    # Determine if the message is intended for this user or sent by this user
                    if recipient in ["All", "Self"] or recipient == username or sender == username:
                        if recipient == "All":
                            # Decrypt using shared symmetric key
                            try:
                                decrypted_message = shared_fernet.decrypt(bytes.fromhex(encrypted_content)).decode()
                                logging.debug(f"Decrypted broadcast message from '{sender}': {decrypted_message}")
                            except Exception as e:
                                decrypted_message = "[Decryption Failed]"
                                logging.error(f"Failed to decrypt broadcast message from '{sender}': {e}")
                            chat_target = "All"
                        elif recipient == "Self":
                            # Decrypt using shared symmetric key
                            try:
                                decrypted_message = shared_fernet.decrypt(bytes.fromhex(encrypted_content)).decode()
                                logging.debug(f"Decrypted self-message from '{sender}': {decrypted_message}")
                            except Exception as e:
                                decrypted_message = "[Decryption Failed]"
                                logging.error(f"Failed to decrypt self-message from '{sender}': {e}")
                            chat_target = "Self"
                        elif sender == username:
                            # Message sent by the user to a specific recipient
                            decrypted_message = encrypted_content
                            chat_target = recipient
                        else:
                            # Private messages
                            try:
                                encrypted_symmetric_key_hex, encrypted_message_hex = encrypted_content.split(":", 1)
                                encrypted_symmetric_key = bytes.fromhex(encrypted_symmetric_key_hex)
                                encrypted_message = bytes.fromhex(encrypted_message_hex)

                                # Decrypt the symmetric key with private RSA key
                                symmetric_key = private_key.decrypt(
                                    encrypted_symmetric_key,
                                    padding.OAEP(
                                        mgf=padding.MGF1(algorithm=hashes.SHA256()),
                                        algorithm=hashes.SHA256(),
                                        label=None
                                    )
                                )
                                fernet = Fernet(symmetric_key)

                                # Decrypt the message with the symmetric key
                                decrypted_message = fernet.decrypt(encrypted_message).decode()
                                chat_target = sender  # Private message from sender
                                logging.debug(f"Decrypted private message from '{sender}': {decrypted_message}")
                            except Exception as e:
                                decrypted_message = "[Decryption Failed]"
                                logging.error(f"Failed to decrypt private message from '{sender}': {e}")
                                chat_target = sender

                        # Determine alignment and display sender
                        if sender == username:
                            display_sender = "You"
                            align = "right"
                            bg_color = "#DCF8C6"  # Light green
                            if recipient in ["All", "Self"]:
                                display_message(display_sender, decrypted_message, align=align, bg_color=bg_color, chat_tab=chat_target)
                        else:
                            display_sender = sender
                            align = "left"
                            bg_color = "#FFFFFF"  # White
                            display_message(display_sender, decrypted_message, align=align, bg_color=bg_color, chat_tab=chat_target)

                elif msg["type"] == "history":
                    messages = msg["messages"]
                    for message in messages:
                        sender = message["sender"]
                        recipient = message["recipient"]
                        encrypted_content = message["message"]

                        if recipient in ["All", "Self"] or recipient == username or sender == username:
                            if recipient == "All":
                                # Decrypt using shared symmetric key
                                try:
                                    decrypted_message = shared_fernet.decrypt(bytes.fromhex(encrypted_content)).decode()
                                    logging.debug(f"Decrypted broadcast history message from '{sender}': {decrypted_message}")
                                except Exception as e:
                                    decrypted_message = "[Decryption Failed]"
                                    logging.error(f"Failed to decrypt broadcast history message from '{sender}': {e}")
                                chat_target = "All"
                            elif recipient == "Self":
                                # Decrypt using shared symmetric key
                                try:
                                    decrypted_message = shared_fernet.decrypt(bytes.fromhex(encrypted_content)).decode()
                                    logging.debug(f"Decrypted self-history message from '{sender}': {decrypted_message}")
                                except Exception as e:
                                    decrypted_message = "[Decryption Failed]"
                                    logging.error(f"Failed to decrypt self-history message from '{sender}': {e}")
                                chat_target = "Self"
                            elif sender == username:
                                # Message sent by the user to a specific recipient
                                decrypted_message = encrypted_content
                                chat_target = recipient
                            else:
                                # Private messages
                                try:
                                    encrypted_symmetric_key_hex, encrypted_message_hex = encrypted_content.split(":", 1)
                                    encrypted_symmetric_key = bytes.fromhex(encrypted_symmetric_key_hex)
                                    encrypted_message = bytes.fromhex(encrypted_message_hex)

                                    # Decrypt the symmetric key with private RSA key
                                    symmetric_key = private_key.decrypt(
                                        encrypted_symmetric_key,
                                        padding.OAEP(
                                            mgf=padding.MGF1(algorithm=hashes.SHA256()),
                                            algorithm=hashes.SHA256(),
                                            label=None
                                        )
                                    )
                                    fernet = Fernet(symmetric_key)

                                    # Decrypt the message with the symmetric key
                                    decrypted_message = fernet.decrypt(encrypted_message).decode()
                                    chat_target = sender  # Private message from sender
                                    logging.debug(f"Decrypted historical private message from '{sender}': {decrypted_message}")
                                except Exception as e:
                                    decrypted_message = "[Decryption Failed]"
                                    logging.error(f"Failed to decrypt historical private message from '{sender}': {e}")
                                    chat_target = sender

                            # Determine alignment and display sender
                            if sender == username:
                                display_sender = "You"
                                align = "right"
                                bg_color = "#DCF8C6"  # Light green
                                if recipient in ["All", "Self"]:
                                    display_message(display_sender, decrypted_message, align=align, bg_color=bg_color, chat_tab=chat_target)
                            else:
                                display_sender = sender
                                align = "left"
                                bg_color = "#FFFFFF"  # White
                                display_message(display_sender, decrypted_message, align=align, bg_color=bg_color, chat_tab=chat_target)

                elif msg["type"] == "error":
                    error_message = msg["message"]
                    gui_queue.put(("error", error_message))

                elif msg["type"] == "disconnect":
                    disconnect_message = msg["message"]
                    gui_queue.put(("disconnect", disconnect_message))

        except Exception as e:
            logging.error(f"Error receiving message: {e}")
            gui_queue.put(("connection_lost", "Disconnected from the server."))
            break

# ===============
# SENDING MESSAGES
# ===============
def send_message():
    try:
        current_tab = notebook.tab(notebook.select(), "text")
    except tk.TclError:
        current_tab = "All"

    recipient = current_tab
    raw_message = message_entry.get()
    if not raw_message:
        return

    if recipient in ["All", "Self"]:
        if not shared_fernet:
            messagebox.showerror("Error", "Shared key not received. Cannot send message.")
            return
        # Encrypt message with shared symmetric key
        encrypted_message = shared_fernet.encrypt(raw_message.encode()).hex()
        data = {
            "type": "message",
            "sender": username,
            "message": encrypted_message,
            "recipient": recipient
        }
        display_message("You", raw_message, align="right", bg_color="#DCF8C6", chat_tab=recipient)  # Light green
    else:
        # Private message
        recipient_pub_pem = public_keys.get(recipient)
        if recipient_pub_pem is None:
            messagebox.showerror("Error", f"No public key available for user '{recipient}'.")
            return
        try:
            recipient_public_key = serialization.load_pem_public_key(
                recipient_pub_pem.encode()
            )
            # Generate a new symmetric key for this private message
            symmetric_key = Fernet.generate_key()
            fernet = Fernet(symmetric_key)

            # Encrypt the message with the symmetric key
            encrypted_message = fernet.encrypt(raw_message.encode()).hex()

            # Encrypt the symmetric key with the recipient's public RSA key
            encrypted_symmetric_key = recipient_public_key.encrypt(
                symmetric_key,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            ).hex()

            # Combine encrypted symmetric key and encrypted message
            combined_message = f"{encrypted_symmetric_key}:{encrypted_message}"

            data = {
                "type": "message",
                "sender": username,
                "message": combined_message,
                "recipient": recipient
            }

            display_message(f"You -> {recipient}", raw_message, align="right",
                            bg_color="#DCF8C6", chat_tab=recipient)  # Light green

        except Exception as e:
            messagebox.showerror("Error", f"Encryption failed: {e}")
            return

    try:
        message_str = json.dumps(data) + "\n"
        client_socket.send(message_str.encode())
        logging.info(f"Sent message to '{recipient}': {raw_message}")
    except OSError:
        messagebox.showerror("Error", "Failed to send message. Connection may be lost.")

    message_entry.delete(0, tk.END)

# =====================
# UI HELPER FUNCTIONS
# =====================
def display_message(sender, message, align="left", bg_color="#FFFFFF", chat_tab=None):
    """
    Insert a message into the specified chat_tab with specified alignment and background color.
    'align' can be 'left' or 'right'.
    'bg_color' sets the background color of the message bubble.
    """
    if not chat_tab:
        chat_tab = "All"  # Default to 'All' chat

    # Create the chat_tab if it doesn't exist
    if chat_tab not in chat_tabs:
        handle_new_chat_tab(chat_tab)

    # Get the text widget associated with the chat_tab
    chat_text = chat_tabs.get(chat_tab)
    if not chat_text:
        logging.warning(f"Chat tab '{chat_tab}' does not exist and could not be created.")
        return

    # Enable the chat window to insert messages
    chat_text.config(state=tk.NORMAL)

    # Create a frame for the message
    msg_frame = tk.Frame(chat_text, bg="#F0F0F0")

    # Add the message text with a label
    msg_label = tk.Label(
        msg_frame,
        text=message,
        bg=bg_color,
        wraplength=400,
        justify="left",
        padx=10,
        pady=5,
        bd=0,
        font=("Helvetica", 12)
    )
    msg_label.pack(side=tk.LEFT if align == "left" else tk.RIGHT, padx=5, pady=2)

    # Add the sender label
    sender_label = tk.Label(
        msg_frame,
        text=sender,
        bg=bg_color,
        fg="#555555",
        font=("Helvetica", 10, "italic")
    )
    sender_label.pack(side=tk.LEFT if align == "left" else tk.RIGHT, padx=5)

    # Insert the frame into the chat_text
    # Instead of using 'align', we'll position the frame based on packing
    chat_text.window_create(tk.END, window=msg_frame)
    chat_text.insert(tk.END, "\n")

    # Disable the chat_text to prevent user editing
    chat_text.config(state=tk.DISABLED)
    chat_text.see(tk.END)

def update_user_list(users):
    """
    Update the user listbox with usernames and their statuses.
    """
    user_listbox.delete(0, tk.END)
    logging.info("Updating user list in GUI:")
    for user, status in users.items():
        if user == username:
            display_text = f"{user} (You)"
            user_listbox.insert(tk.END, display_text)
            logging.info(f" - {display_text}")
        elif status == "Connected":
            display_text = f"{user} (Connected)"
            user_listbox.insert(tk.END, display_text)
            logging.info(f" - {display_text}")
    user_listbox.insert(tk.END, "All - Broadcast")
    user_listbox.insert(tk.END, "Self - Private")

def handle_new_chat_tab(recipient):
    """
    Create a new chat tab for the recipient or switch to it if it already exists.
    """
    if recipient in chat_tabs:
        # Tab already exists, switch to it
        notebook.select(chat_tabs[recipient])
    else:
        # Create a new tab
        new_tab = tk.Frame(notebook)
        chat_text = scrolledtext.ScrolledText(new_tab, wrap="word", bg="#ECE5DD",
                                             state=tk.DISABLED, font=("Helvetica", 12))
        chat_text.pack(padx=10, pady=10, fill=tk.BOTH, expand=True)
        chat_tabs[recipient] = chat_text

        # Add the tab to the notebook
        notebook.add(new_tab, text=recipient)
        notebook.select(new_tab)
        logging.info(f"Created new chat tab for '{recipient}'.")

def on_user_select(event):
    """
    Update the recipient selection based on the user clicked in the listbox.
    Open or switch to the corresponding chat tab.
    """
    selection = user_listbox.curselection()
    if selection:
        index = selection[0]
        selected = user_listbox.get(index)
        # Extract username and status
        if selected.endswith("(You)"):
            # Set recipient to 'Self'
            recipient_var.set("Self")
            messagebox.showwarning("Invalid Selection", "You have selected yourself.")
            logging.info("Selected yourself. No action taken.")
        elif selected.startswith("All -"):
            recipient_var.set("All")
            handle_new_chat_tab("All")
            logging.info("Selected recipient: 'All'.")
        elif selected.startswith("Self -"):
            recipient_var.set("Self")
            handle_new_chat_tab("Self")
            logging.info("Selected recipient: 'Self'.")
        else:
            # Extract username and status
            try:
                selected_username = selected.split(" (Connected)")[0]
                recipient_var.set(selected_username)
                handle_new_chat_tab(selected_username)
                logging.info(f"Selected recipient: '{selected_username}'.")
            except ValueError:
                # Handle unexpected format
                messagebox.showerror("Selection Error", "Invalid selection format.")
                recipient_var.set("All")
                logging.warning("Invalid selection format. Recipient set to 'All'.")

def refresh_user_list():
    """
    Manually request a user list update by sending a request to the server.
    """
    try:
        request_data = {
            "type": "request_user_list"
        }
        message_str = json.dumps(request_data) + "\n"
        client_socket.send(message_str.encode())
        logging.info("Sent user list refresh request to server.")
    except Exception as e:
        logging.error(f"Failed to refresh user list: {e}")
        messagebox.showerror("Error", f"Failed to refresh user list: {e}")

def on_disconnect_message(message):
    """
    Handle server-initiated disconnection.
    """
    messagebox.showinfo("Disconnected", message)
    root.quit()

def on_close():
    try:
        if messagebox.askokcancel("Quit", "Do you want to quit?"):
            try:
                client_socket.shutdown(socket.SHUT_RDWR)
            except:
                pass
            client_socket.close()
            root.destroy()
    except OSError:
        root.destroy()

# ================
# MAIN GUI
# ================
def start_gui():
    global root, message_entry, recipient_var, user_listbox, notebook, chat_tabs

    root = tk.Tk()
    root.title(f"Secure Chat Application - {username}")
    root.geometry("1000x700")
    root.configure(bg="#ECE5DD")  # WhatsApp-like background

    # Create main frames
    main_frame = tk.Frame(root, bg="#ECE5DD")
    main_frame.pack(fill=tk.BOTH, expand=True)

    left_frame = tk.Frame(main_frame, width=200, bg="#25D366")
    left_frame.pack(side=tk.LEFT, fill=tk.Y)

    right_frame = tk.Frame(main_frame, bg="#ECE5DD")
    right_frame.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True)

    # User Listbox in left_frame
    user_label = tk.Label(left_frame, text="Users", font=("Helvetica", 14, "bold"),
                         fg="#FFFFFF", bg="#25D366")
    user_label.pack(pady=10)

    user_listbox = tk.Listbox(left_frame, width=30, height=30, bg="#075E54",
                              fg="#FFFFFF", selectbackground="#128C7E")
    user_listbox.pack(padx=10, pady=5, fill=tk.BOTH, expand=True)
    user_listbox.bind('<<ListboxSelect>>', on_user_select)

    # Refresh Button
    refresh_button = tk.Button(left_frame, text="Refresh", command=refresh_user_list,
                               bg="#25D366", fg="#FFFFFF", borderwidth=0,
                               highlightthickness=0, activebackground="#128C7E")
    refresh_button.pack(pady=5)

    # Chat Notebook in right_frame
    notebook = ttk.Notebook(right_frame)
    notebook.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

    chat_tabs = {}  # Dictionary to keep track of chat tabs

    # Initialize default 'All' chat tab
    handle_new_chat_tab("All")

    # Bottom frame for message entry and send button
    bottom_frame = tk.Frame(right_frame, bg="#ECE5DD")
    bottom_frame.pack(side=tk.BOTTOM, fill=tk.X, padx=10, pady=10)

    # Recipient variable (for internal use, not displayed)
    recipient_var = tk.StringVar(value="All")
    # No longer using a dropdown; recipient is selected via the user list

    # Message entry
    message_entry = tk.Entry(bottom_frame, width=80, font=("Helvetica", 12))
    message_entry.pack(side=tk.LEFT, padx=(0, 10), pady=5, fill=tk.X, expand=True)
    message_entry.bind("<Return>", lambda event: send_message())

    # Send button
    send_button = tk.Button(bottom_frame, text="Send", command=send_message,
                            bg="#128C7E", fg="#FFFFFF", font=("Helvetica", 12, "bold"),
                            borderwidth=0, highlightthickness=0, activebackground="#075E54")
    send_button.pack(side=tk.RIGHT)

    root.protocol("WM_DELETE_WINDOW", on_close)

    # Start processing the GUI queue
    process_gui_queue()

    root.mainloop()

def process_gui_queue():
    """
    Periodically process messages from the receiving thread to update the GUI.
    """
    while not gui_queue.empty():
        try:
            item = gui_queue.get_nowait()
        except queue.Empty:
            break
        if item[0] == "user_list":
            users = item[1]
            update_user_list(users)
        elif item[0] == "message":
            sender, message, align, chat_target = item[1]
            if chat_target in ["All", "Self"]:
                display_message(sender, message, align=align, bg_color="#FFFFFF" if align == "left" else "#DCF8C6", chat_tab=chat_target)
            else:
                display_message(sender, message, align=align, bg_color="#FFFFFF" if align == "left" else "#DCF8C6", chat_tab=chat_target)
        elif item[0] == "error":
            error_message = item[1]
            messagebox.showerror("Error", error_message)
        elif item[0] == "disconnect":
            message = item[1]
            on_disconnect_message(message)
        elif item[0] == "connection_lost":
            message = item[1]
            messagebox.showwarning("Connection Lost", message)
            root.quit()
    root.after(100, process_gui_queue)  # Check the queue every 100 ms

# ======================
# CLIENT INITIALIZATION
# ======================
def initialize_client():
    global username, client_socket

    # Prompt for username (blocking popup)
    root_temp = tk.Tk()
    root_temp.withdraw()
    username_input = simpledialog.askstring("Username", "Enter your username:")
    if not username_input:
        messagebox.showerror("Error", "Username is required!")
        root_temp.destroy()
        return
    else:
        username = username_input.strip()
    root_temp.destroy()

    if not username:
        messagebox.showerror("Error", "Username cannot be empty!")
        return

    # Create SSL context
    context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
    # For production, ensure that you have the server's certificate to verify against
    context.load_verify_locations(cafile="server.crt")  # Path to server's certificate
    context.check_hostname = False  # Set to True if using proper hostnames
    context.verify_mode = ssl.CERT_REQUIRED

    # Connect to the server
    server_address = ("127.0.0.1", 12345)
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        wrapped_socket = context.wrap_socket(client_socket, server_hostname=server_address[0])
        wrapped_socket.connect(server_address)
        client_socket = wrapped_socket
        logging.info("Connected to the server with TLS.")
    except ConnectionRefusedError:
        messagebox.showerror("Connection Error", "Unable to connect to the server.")
        return
    except ssl.SSLError as e:
        messagebox.showerror("SSL Error", f"SSL handshake failed: {e}")
        return
    except Exception as e:
        messagebox.showerror("Connection Error", f"Failed to connect: {e}")
        return

    # Send username and public key
    data = {
        "username": username,
        "public_key": public_key_pem
    }
    try:
        message_str = json.dumps(data) + "\n"
        client_socket.send(message_str.encode())
        logging.info(f"Sent connection data: {data}")
    except OSError as e:
        messagebox.showerror("Connection Error", f"Failed to send data: {e}")
        return

    # Start a thread to handle incoming messages
    t = threading.Thread(target=receive_messages, daemon=True)
    t.start()

    # Launch main GUI
    start_gui()

# ======================
# CLIENT FUNCTIONALITY
# ======================
def handle_incoming_message(msg):
    if msg["type"] == "user_list":
        users = msg["users"]
        gui_queue.put(("user_list", users))

        # Update public_keys dictionary
        if "public_keys" in msg:
            public_keys.update(msg["public_keys"])
            logging.info("Updated public keys.")

    elif msg["type"] == "message":
        # Handled in receive_messages
        pass

    elif msg["type"] == "history":
        # Handled in receive_messages
        pass

    elif msg["type"] == "error":
        error_message = msg["message"]
        gui_queue.put(("error", error_message))

    elif msg["type"] == "disconnect":
        disconnect_message = msg["message"]
        gui_queue.put(("disconnect", disconnect_message))

# ================
# RUN THE CLIENT
# ================
if __name__ == "__main__":
    initialize_client()
