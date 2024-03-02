import sys
import os

# getting the name of the directory
# where the this file is present.
current = os.path.dirname(os.path.realpath(__file__))

# Getting the parent directory name
# where the current directory is present.
parent = os.path.dirname(current)

# adding the parent directory to
# the sys.path.
sys.path.append(parent)

# now we can import the module in the parent
# directory.
import socket
import protocol
import struct
import threading
import uuid
import datetime
import Crypto
from Crypto.Random import get_random_bytes
import utils

PORT_FILE = "port.info.txt"
DEFAULT_PORT = 1256
PACKET_SIZE = 2048
DEFAULT_IP = "127.0.0.1"
VERSION = 24
CLIENTS_FILE = "clients"
SERVERS_FILE = "servers"
START_POS_CODE = 17
END_POS_CODE = 19
EMPTY = 0
EXPIRATION_TIME = 8
class Server:

    def __init__(self):
        self.server = None
        self.port = self.reading_port_server()
        self.ip = DEFAULT_IP
        self.clients = list()
        self.msg_servers = list()
        self.load_details()
        self.request_handle = {
            protocol.ServerRequestsCode.REGISTRATION_CLIENT_REQUEST.value : self.handle_client_register_request,
            protocol.ServerRequestsCode.REGISTRATION_SERVER_REQUEST.value : self.handle_server_register_request,
            protocol.ServerRequestsCode.SERVERS_LIST_REQUEST.value: self.handle_servers_list_request,
            protocol.ServerRequestsCode.SYMMETRY_KEY_REQUEST.value: self.handle_symmetry_key_request
        }


    def reading_port_server(self):
        current_files = os.listdir()
        if PORT_FILE in current_files:
            with open(PORT_FILE,"r") as file:
                file_content = file.read()
            return int(file_content)
        else:
            print(f"[ERROR] - the file {PORT_FILE} is not found, the port will be the default port {DEFAULT_PORT}.")
            return DEFAULT_PORT
    def start_server(self):

        try:
            self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server.bind((self.ip,self.port))
            self.server.listen()
            print(f"[INFO] Authenticator Server starting listening on {self.ip}:{self.port}, Version:{VERSION}.")
            while True:
                connection, client_address = self.server.accept()
                print(f"The client {client_address} connected")
                self.client_thread = threading.Thread(target=self.client_handler, daemon=True,args=(connection,))
                self.client_thread.start()
        except Exception:
            print(f"[ERROR] There is problem to setup the server.\nPlease check the IP and the Port that you entered and try again.")
            exit()


    def client_handler(self,client_connection):
        while True:
            try:
                client_data = client_connection.recv(PACKET_SIZE)
            except ConnectionResetError:
                print("[ERROR] Client closed the connection unexpectedly")
                client_connection.close()
                break
            # If got Empty data from the user it is sign to close the connection.
            if not client_data:
                break
            code_request = struct.unpack(f"<H", client_data[START_POS_CODE:END_POS_CODE])[0] # Unpack the code request
            if code_request:
                # Check whether the code request is valid; if so, call the appropriate function.
                if code_request in self.request_handle.keys():
                    response = self.request_handle[code_request](client_data)
                    if not response:
                        print("[ERROR] Can't send response.")
                        break
                    else:
                        client_connection.send(response)
                        continue
                else:
                    print("[ERROR] Invalid request, please try again.")
            else:
                client_connection.close()
                print("[INFO] connection has been closed!")
                break
            break
        print("[INFO] Process is done, closing the connection.")
        client_connection.close()


    def handle_client_register_request(self,data):
        print("[INFO] server handle client registration request")
        currentTime = datetime.datetime.now().strftime('%d-%m-%y %H:%M')
        client_request = protocol.ClientRegistrationRequest()
        try:
            if not client_request.unpack(data):
                return True
        except:
            print("[ERROR] Something went wrong...")
            return False
        server_response = protocol.ClientRegistrationResponse(uuid.uuid4().bytes)
        if not self.check_user_in_clients_file(client_request.name):
                # registration failed! name is already in the clients file - registration request failed
                server_response.registration_unsuccessful()
                response_data = self.create_response(server_response)
                return response_data
        encrypt_password = utils.hash_password(client_request.password)
        user_data = [server_response.client_id.hex(), client_request.name, encrypt_password, str(currentTime)] # All the relevant data to store in clients file.
        self.clients.append([server_response.client_id, client_request.name]) # Add the client data to the RAM's program.
        current_client = self.add_user_to_clients_file(user_data)
        if not current_client:
            print("[ERROR] Can't add the client to the clients file.")
            return False
        response_data = self.create_response(server_response)
        return response_data

    def handle_server_register_request(self,data):
        print("[INFO] server handle messages server registration request")
        msg_server_request = protocol.ServerRegistrationRequest()
        try:
            if not msg_server_request.unpack(data):
                return True
        except:
            print("[ERROR] Something went wrong...")
            return False

        server_response = protocol.ServerRegistrationResponse(uuid.uuid4().bytes)
        if not self.check_server_in_servers_file(msg_server_request.server_name):
            # registration failed! name is already in the clients file - registration request failed
            print("[ERROR] Server registration failed.")
            server_response.registration_unsuccessful()
            response_data = self.create_response(server_response)
            return response_data
        # All the relevant data to store in Servers file.
        msg_server_data = [msg_server_request.ip,str(msg_server_request.port),server_response.server_id.hex(), msg_server_request.server_name, msg_server_request.AES_key.hex()]
        self.msg_servers.append([server_response.server_id, msg_server_request.server_name]) # Add the Server data to the RAM's program.
        current_server = self.add_server_to_servers_file(msg_server_data)
        if not current_server:
            print("[ERROR] Can't add the client to the servers file.")
            return False
        print("[INFO] Server registration was successful.")
        response_data = self.create_response(server_response)
        return response_data

    def handle_symmetry_key_request(self, data):
        print("[INFO] Server handle symmetry key request")
        response_code = protocol.ServerResponseCode.RESPONSE_SYMMETRY_KEY.value
        server_response = protocol.SymmetryKeyResponse()
        client_request = protocol.SymmetryKeyRequest()
        if not client_request.unpack(data):
            return False

        current_time = datetime.datetime.now()
        expiration_time = current_time + datetime.timedelta(minutes=EXPIRATION_TIME)
        timestamp = datetime.datetime.now().strftime('%d-%m-%y %H:%M').encode("utf-8")
        expiration_time = expiration_time.strftime('%d-%m-%y %H:%M').encode("utf-8")
        iv = get_random_bytes(protocol.IV_SIZE) # IV to encrypt and decrypt with client symmetry key
        ticket_iv = get_random_bytes(protocol.IV_SIZE)  # IV to encrypt and decrypt with server key
        aes_key = get_random_bytes(protocol.AES_KEY_SIZE) # Session key
        client_password = bytes.fromhex(utils.find_password_by_uuid(client_request.id)) # Find user password from clients file and convert it to digest from hexdigest
        msg_server_key = utils.find_server_key_by_uuid(client_request.server_id)# Find the server key from servers files
        if not msg_server_key or not client_password:
            return False
        client_aes_key = utils.encrypt_data(client_password,aes_key,iv) # Creating the symmetry key between auth server to the client from his password
        encrypted_nonce = utils.encrypt_data(client_password,client_request.nonce,iv)
        server_aes_key = utils.encrypt_data(msg_server_key,aes_key,ticket_iv) # Encrypt the session key.
        encrypted_expiration_time = utils.encrypt_data(msg_server_key,expiration_time,ticket_iv)
        server_response.encrypt_symmetry_key(encrypted_nonce,client_aes_key,iv)
        if not self.check_ids(client_request.id,client_request.server_id):
            print("[ERROR] There is no match between client ids and servers ids")
            return False
        server_response.ticket(client_request.id,client_request.server_id,timestamp,ticket_iv,server_aes_key,encrypted_expiration_time)
        response_data = server_response.pack(response_code)
        return response_data


    def handle_servers_list_request(self,data):
        print("[INFO] Server handle servers list request")
        response_code = protocol.ServerResponseCode.RESPONSE_SERVERS_LIST.value
        client_request = protocol.ServersListRequest()
        if not client_request.unpack(data):
            return False
        servers_list = self.read_servers_file()
        server_response_data = protocol.ServersListResponse().pack(response_code,servers_list)
        if not server_response_data:
            print("[ERROR] Unable to pack the data.")
            return False
        return server_response_data

    """Check weather is some server is in the servers file."""
    def check_server_in_servers_file(self, name):
        if not os.path.exists(SERVERS_FILE):
            print("[ERROR] The servers file is not exists")
            exit(1)
        with open(SERVERS_FILE, "r") as file:
            lines = file.readlines()
            for line in lines:
                if name in line.split(":"):
                    print("[ERROR] The server is already registered.")
                    return False
        return True

    """Add server to the servers file."""
    def add_server_to_servers_file(self, data):
        client_line_data = ":".join(data) + "\n"
        if not os.path.exists(SERVERS_FILE):
            print("[ERROR] The servers file is not exists")
            exit(1)
        try:
            with open(SERVERS_FILE, "a") as file:
                file.writelines(client_line_data)
            return True
        except:
            print("[ERROR] Can't add the client to the clients file.")
            return False

    """Check weather is some client is in the clients file."""
    def check_user_in_clients_file(self,client_name):
        if not os.path.exists(CLIENTS_FILE):
            print("[ERROR] The clients file is not exists")
            exit(1)
        with open(CLIENTS_FILE, "r") as file:
            lines = file.readlines()
            for line in lines:
                if client_name in line.split(":"):
                    print("[ERROR] The client is already registered.")
                    return False
        return True

    """Add client to the clients file."""
    def add_user_to_clients_file(self,client_data):
        client_line_data = ":".join(client_data)
        if not os.path.exists(CLIENTS_FILE):
            print("[ERROR] The clients file is not exists")
            exit(1)
        try:
            with open(CLIENTS_FILE, "a") as file:
                file.write(client_line_data + "\n")
            return True
        except:
            return False

    """Read the servers details that in servers file for Servers list request."""
    def read_servers_file(self):
        servers = list()
        if not os.path.exists(SERVERS_FILE):
            print("[ERROR] The servers file is not exists")
            exit(1)
        with open(SERVERS_FILE, "r") as file:
            lines = file.readlines()
            for line in lines:
                server_details = line.split(":")
                server_details[2] = bytes.fromhex(server_details[2]) # Back server id from hex to bytes
                servers.append(server_details[:len(server_details) - 1])
        return servers

    """Loading the clients details and servers details to RAM"""
    def load_details(self):
        if not os.path.exists(SERVERS_FILE):
            print("[ERROR] The servers file is not exists")
            exit(1)
        if not os.path.exists(CLIENTS_FILE):
            print("[ERROR] The clients file is not exists")
            exit(1)
        with open(CLIENTS_FILE, "r") as file:
            lines = file.readlines()
            for line in lines:
                client_details = line.split(":")
                client_id = bytes.fromhex(client_details[0])  # Back server id from hex to bytes
                client_name = client_details[1]
                self.clients.append([client_id,client_name])
        with open(SERVERS_FILE, "r") as file:
            lines = file.readlines()
            for line in lines:
                server_details = line.split(":")
                server_id = bytes.fromhex(server_details[2])  # Back server id from hex to bytes
                server_name = server_details[3]
                self.msg_servers.append([server_id, server_name])

    """Check weather the ids are exists"""
    def check_ids(self,client_id,server_id):
        valid_server_id = False
        valid_client_id = False
        for server in self.msg_servers:
            if server_id in server:
                valid_server_id = True
        for client in self.clients:
            if client_id in client:
                valid_client_id = True
        return valid_server_id and valid_client_id

    """Create Server's response"""
    def create_response(self, response):
        try:
            data_response = response.pack()
            print("[INFO] server response to the register request.")
            return data_response
        except:
            return False

if __name__ == '__main__':
    Server().start_server()

