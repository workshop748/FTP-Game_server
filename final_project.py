import socket
import os
from _thread import *
import random
import csv
from Crypto.Protocol.KDF import scrypt
from Crypto.Random import get_random_bytes
import base64

# this is uses to create an object of the different users that are present.
class FTPUser:
    def __init__(self, username, password_hash,salt,hint1, hint2, home_dir,root_dir):
           self.username = username
           self.password_hash =password_hash
           self.salt =salt
           self.hint1 = hint1
           self.hint2 = hint2
           self.home_dir =home_dir
           self.current_dir = home_dir
           self.root_dir = root_dir

def initialize_root_directory(root_path):
    if not os.path.exists(root_path):
        os.makedirs(root_path)
    print(f"Root directory {root_path} initialized.")
    return root_path
def hash_password(password, salt):
    ## hashes the password
    return scrypt(password,salt, 32,n=2**14, r=8, p=1)
    
def generate_salt():
    return get_random_bytes(16)
def Load_users_from_csv(filename,root_dir):
    users = {}
    try:
        with open(filename, "r") as file:
            reader =csv.reader(file)
            for row in reader:
                if len(row) >= 6:
                    salt = base64.b64decode(row[2].encode())
                    hash_password =base64.b64secode(row[3].encode())
                    home_dir = os.path.join(root_dir, row[4])
                    
                    if not os.path.exists(home_dir):
                        os.makedirs(home_dir)

                    users[row[0]] =FTPUser(row[0],hash_password,salt,row[3],row[4],row[5],row[6])
    except FileNotFoundError:
        print(f" Waring: user database {filename} not found. Using anonymous accesss only")
        
        anon_dir = os.path.join(root_dir, "anonymous")
        if not os.path.exists(anon_dir):
            os.makedirs(anon_dir)
        salt = generate_salt()
        users['anonymous'] = FTPUser('anonymous', b'',salt,'','', os.getcwd())
    return users

def searching_pass(username,password,users):
     # this will be where the main ftp server conecttion will occur.
    # such as transfering files and veiwing directories 
    if username not in users:
        return None,False
    user = users[username]
    
    # this is for anonymous login (empty password)
    if user.password_hash == b'' and password == '':
        return user,True

    input_hash = hash_password(password)
    
    # used to prevent against timeing attacks
    if len(input_hash) != len(user.password_hash):
        return None,False
    
    if input_hash != user.password_hash:
        return None,False
    return user,True

def is_path_safe(user,requested_path):
    # this will check if the path is safe to access
    requested_abs = os.path.abspath(os.path.join(user.current_dir,requested_path))
    root_abs = os.path.abspath(user.root_dir)
    return requested_abs.startswith(root_abs)
def FTPProcess(client_socket,users):
    # handling the normal ftp enter a command request
   while 1:
    try:
        client_socket.send("CommandRequst-Please\tenter\ta\tcommand\t")
        data =client_socket.recv(1024).decode()

        if not data:
            break
     
        command,*args=data.split()
        command = command.upper()

    #handling the commands given by the client
        if command == 'SYST':
            client_socket.send("CommandResponce-Windows 11".encode())
        elif command == 'PWD':
            client_socket.send(f"{users.current_dir}".encode())
        elif command == 'CWD':
            if args:
                if not is_path_safe(users, args[0]):
                    client_socket.send("CommandResponce-Permission denied".encode())
                    continue
                new_dir = os.path.join(users.curret_dir, args[0])
                if os.path.isdir(new_dir):
                    users.current_dir =new_dir
                    client_socket.send("CommandResponce-Directory changed".encode())
                else:
                    client_socket.send("CommandResponce-Directory not found".encode())
            else:
                client_socket.send("CommandResponce-Syntax error in parameters".encode())
        elif command == 'LIST':
            try:
                files=os.listdir(users.current_dr)
                listing="\r\n".join(files)
                client_socket.send(" CommandResponce-here comes the directory listing".encode())
                client_socket.send(listing.encode()+b"\r\n")
                client_socket.send("CommandResponce-Directory send OK".encode())
            except Exception as e:
                    client_socket.send(str(e).encode())
        elif  command == 'RETR':
            if args:
              if not is_path_safe(users, args[0]):
                    client_socket.send("CommandResponce-Permission denied".encode())
                    continue
              file_path = os.path.join(users.current_dir, args[0])
              if os.path.isfile(file_path):
                  try:
                    with open(file_path,'rb') as f:
                      client_socket.send("CommandResponce-opening A BINARY mode data connection".encode())
                      client_socket.sendall(f.read())
                      client_socket.send("CommandResponce-transfer complete".encode())
                  except Exception as e:
                      client_socket.send(str(e).encode())
              else:
                   client_socket.send("CommandResponce-Syntax error in parameters".encode())
        elif command == 'QUIT':
           client_socket.send("CommandResponce-Goodbye".encode())
           break
        else:
         client_socket.send("CommandResponce-Command not implemented".encode())
    except Exception as e:
        print(f"Error handling command :{e}")
        break
    
                       
def FTP_server(cleint_socket,root_dir):
    users = Load_users_from_csv("theUsers.csv",root_dir)
    # this will handle the start of the client socket for logging int
    # sending a login  in request for the users
    login_request = "AuthRequest-Request"
    cleint_socket.send(login_request.encode())
    # the server is waiting for the user name to get a request
    # format of the request AuthRequest-Response-UserName-Response
    try:
        while True:
            data =cleint_socket.recv(1024).decode()

            if not data:
                break
    # this will split the dilemnator
            command, *args =data.split('-')
            command=command.upper()

            if command == 'USER':
                username = args[0] if args else ''
                if username in users:  
                        cleint_socket.send(f"AuthRequest-Password required for {username}\r\n".encode())

                        data =cleint_socket.recv(1024).decode().strip()
                        if '-' in data:
                            pass_command, *pass_args = data.split('-')
                        else:
                            pass_command, *pass_args = data.split()
                        if pass_command.upper() == 'PASS':
                            password = pass_args[0] if pass_args else ''
                           
                            user,success = searching_pass(username, password,users)
                            if success:
                                cleint_socket.send("AuthRequest-Sucess".encode())
                                FTPProcess(cleint_socket,user)
                                break
                            else:
                                user_obj = users.get(username)
                                if user_obj:
                                    hint = random.choice([user_obj.hint1,user_obj.hint2])
                                    cleint_socket.send(f"AuthRequest-incorect-{hint}".encode())
                                else:
                                    cleint_socket.send("AuthRequest-incorect".encode())
                                break
                        else:
                            cleint_socket.send("AuthRequest-login in with user first".encode())
                            break
                else:
                      cleint_socket.send("AuthRequest-User not found".encode())
   
            elif command =='QUIT':
                cleint_socket.send("AuthRequest-Goodbye".encode())
                break
            else:
                   cleint_socket.send("AuthFrequest-Please login with USER and PASS")
    except Exception as e:
        print(f" Client error :{e}")
    finally:
         cleint_socket.close()


def main():
    #handling the inital  server set up
    serverIP = "127.0.0.1"
    port = 2121
    root_dir ="/ftp/"
    root_Direcotry = os.path.abspath(root_dir)
    initialize_root_directory(root_Direcotry)
    try:

        Server_socket = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
        Server_socket.bind(serverIP,port)
        Server_socket.listen()
        print(f"FTP Server started on {serverIP}:{port}")
        while 1:
            clientConnection,addr = Server_socket.accept()
            print(f" there is a new connection from {addr}")
            start_new_thread(FTP_server,(clientConnection,root_dir,))
    except KeyboardInterrupt:
            print("\nShutting down server ...")
    finally:
        Server_socket.close()


if __name__ =="__main__":
     main()
        
    
   