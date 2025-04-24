import socket
import os
from _thread import *
import random
import csv
from Crypto.Protocol.KDF import scrypt
from Crypto.Random import get_random_bytes
import base64

class FTPUser:
    def __init__(self, username, password_hash, salt, hint1, hint2, home_dir, root_dir):
        self.username = username
        self.password_hash = password_hash
        self.salt = salt
        self.hint1 = hint1
        self.hint2 = hint2
        self.home_dir = home_dir
        self.current_dir = home_dir
        self.root_dir = root_dir

def initialize_root_directory(root_path):
    if not os.path.exists(root_path):
        os.makedirs(root_path)
    print(f"Root directory {root_path} initialized.")
    return root_path

def hash_password(password, salt):
    if isinstance(salt, str):
        salt = base64.b64decode(salt)
    return scrypt(password.encode(), salt, 32, N=2**14, r=8, p=1)

def generate_salt():
    return get_random_bytes(16)

def Load_users_from_csv(filename, root_dir):
    users = {}
    try:
        with open(filename, "r") as file:
            reader = csv.reader(file)
            for row in reader:
                if len(row) >= 6:
                    try:
                        # Handle Base64 padding
                        salt = row[2].strip()
                        while len(salt) % 4 != 0:
                            salt += '='
                        
                        password_hash = row[1].strip()
                        while len(password_hash) % 4 != 0:
                            password_hash += '='
                        
                        home_dir = os.path.join(root_dir, row[0].strip())
                        os.makedirs(home_dir, exist_ok=True)

                        users[row[0]] = FTPUser(
                            row[0],
                            base64.b64decode(password_hash),
                            salt,
                            row[3],
                            row[4],
                            home_dir,
                            root_dir
                        )
                    except Exception as e:
                        print(f"Error processing user {row[0]}: {e}")
                        continue
    except FileNotFoundError:
        print(f"Warning: user database {filename} not found. Using anonymous access only")
        anon_dir = os.path.join(root_dir, "anonymous")
        os.makedirs(anon_dir, exist_ok=True)
        salt = generate_salt()
        users['anonymous'] = FTPUser('anonymous', b'', base64.b64encode(salt).decode(), '', '', anon_dir, root_dir)
    return users

def searching_pass(username, password, users):
    if username not in users:
        return None, False
        
    user = users[username]
    
    # Anonymous login
    if user.password_hash == b'' and password == '':
        return user, True
    
    try:
        # Hash the input password with the stored salt
        input_hash = hash_password(password, user.salt)
        
        # Compare hashes
        return user, input_hash == user.password_hash
    except Exception as e:
        print(f"Error verifying password: {e}")
        return None, False

def is_path_safe(user, requested_path):
    requested_abs = os.path.abspath(os.path.join(user.current_dir, requested_path))
    root_abs = os.path.abspath(user.root_dir)
    return requested_abs.startswith(root_abs)

def FTPProcess(client_socket, user):
    while True:
        try:
            # Remove the automatic command request - let client initiate
            data = client_socket.recv(1024).decode().strip()
            if not data:
                break
     
            parts = data.split()
            if not parts:
                continue
                
            command = parts[0].upper()
            print(command)
            args = parts[1:] if len(parts) > 1 else []

            if command == 'SYST':
                client_socket.send("CommandResponse-Windows 11\r\n".encode())
            elif command == 'PWD':
                client_socket.send(f"CommandResponse-{user.current_dir}\r\n".encode())
                
            elif command == 'CWD':
                if args:
                    if not is_path_safe(user, args[0]):
                        client_socket.send("CommandResponse-Permission denied".encode())
                        continue
                    new_dir = os.path.join(user.current_dir, args[0])
                    if os.path.isdir(new_dir):
                        user.current_dir = new_dir
                        client_socket.send("CommandResponse-Directory changed".encode())
                    else:
                        client_socket.send("CommandResponse-Directory not found".encode())
                else:
                    client_socket.send("CommandResponse-Syntax error in parameters".encode())
            elif command == 'LIST':
                try:
                    files = os.listdir(user.current_dir)
                    listing = "\r\n".join(files)
                    client_socket.send("CommandResponse-here comes the directory listing".encode())
                    client_socket.send(listing.encode() + b"\r\n")
                    client_socket.send("CommandResponse-Directory send OK".encode())
                except Exception as e:
                    client_socket.send(f"CommandResponse-Error: {str(e)}".encode())
            elif command == 'RETR':
                if args:
                    if not is_path_safe(user, args[0]):
                        client_socket.send("CommandResponse-Permission denied".encode())
                        continue
                    file_path = os.path.join(user.current_dir, args[0])
                    if os.path.isfile(file_path):
                        try:
                            with open(file_path, 'rb') as f:
                                client_socket.send("CommandResponse-opening BINARY mode data connection".encode())
                                client_socket.sendall(f.read())
                                client_socket.send("CommandResponse-transfer complete".encode())
                        except Exception as e:
                            client_socket.send(f"CommandResponse-Error: {str(e)}".encode())
                    else:
                        client_socket.send("CommandResponse-File not found".encode())
                else:
                    client_socket.send("CommandResponse-Syntax error in parameters".encode())
            elif command == 'QUIT':
                client_socket.send("CommandResponse-Goodbye".encode())
                break
            else:
                client_socket.send("CommandResponse-Command not implemented".encode())
        except ConnectionResetError:
            print("Client disconnected abruptly")
            break
        except Exception as e:
            print(f"Error handling command: {e}")
            break

def FTP_server(client_socket, root_dir):
    users = Load_users_from_csv("Salted&HashedV2.csv", root_dir)
    login_attempts = {}
    max_attempts = 5
    
    try:
        client_ip = client_socket.getpeername()[0]
        login_attempts[client_ip] = 0
        
        client_socket.send("AuthRequest-Request".encode())
        
        while True:
            data = client_socket.recv(1024).decode().strip()
            
            if not data:
                break

            parts = data.split('-')
            if not parts:
                continue
                
            command = parts[0].upper()
            args = parts[1:] if len(parts) > 1 else []

            if command == 'USER':
                username = args[0] if args else ''
                if username in users:
                    login_attempts[client_ip] = 0
                    client_socket.send(f"AuthRequest-Password required for {username}".encode())
                    
                    
                    while True:
                        data = client_socket.recv(1024).decode().strip()
                        print(f"{data}")
                        if not data:
                            break
                            
                        if '-' in data:
                            pass_command, *pass_args = data.split('-')
                        else:
                            pass_command, *pass_args = data.split()
                            
                        if pass_command.upper() == 'PASS':
                            password = pass_args[0] if pass_args else ''
                            if password.upper() == "END":
                                break
                                
                            user, success = searching_pass(username, password, users)
                            if success:
                                client_socket.send("AuthRequest-Success".encode())
                                FTPProcess(client_socket, user)
                                break
                            else:
                                login_attempts[client_ip] += 1
                                user_obj = users.get(username)
                                
                                if login_attempts[client_ip] >= max_attempts:
                                    client_socket.send("AuthRequest-Max attempts reached".encode())
                                    break
                                    
                                hint = ""
                                if login_attempts[client_ip] == 1:
                                    hint = user_obj.hint1 if user_obj else ""
                                elif login_attempts[client_ip] == 2:
                                    hint = user_obj.hint2 if user_obj else ""
                                    
                                if hint:
                                    client_socket.send(f"AuthRequest-incorrect-{hint}".encode())
                                else:
                                    client_socket.send("AuthRequest-incorrect".encode())
                else:
                    client_socket.send("AuthRequest-User not found".encode())
            elif command == 'QUIT':
                client_socket.send("AuthRequest-Goodbye".encode())
                break
            else:
                client_socket.send("AuthRequest-Please login with USER and PASS".encode())
    except ConnectionResetError:
        print("Client disconnected abruptly")
    except Exception as e:
        print(f"Client error: {e}")
    finally:
        client_socket.close()
        print(f"Connection with {client_ip} closed")

def main():
    serverIP = "127.0.0.1"
    port = 2121
    root_dir = "/ftp"
    root_directory = os.path.abspath(root_dir)
    initialize_root_directory(root_directory)
    
    try:
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_socket.bind((serverIP, port))
        server_socket.listen(5)
        print(f"FTP Server started on {serverIP}:{port}")
        
        while True:
            try:
                client_connection, addr = server_socket.accept()
                print(f"New connection from {addr}")
                start_new_thread(FTP_server, (client_connection, root_dir))
            except KeyboardInterrupt:
                raise
            except Exception as e:
                print(f"Error accepting connection: {e}")
                continue
                
    except KeyboardInterrupt:
        print("\nShutting down server...")
    finally:
        server_socket.close()

if __name__ == "__main__":
    main()