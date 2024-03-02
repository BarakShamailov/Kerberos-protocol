import socket
from client_session import ClientRequestHeader
import os

VERSION = 24
AUTH_FILE = "auth.info.txt"
SIZE_PACKET = 2048
DEFAULT_IP = "127.0.0.1"
DEFAULT_PORT = 8080
DEFAULT_VAL = 0
ERROR = 1029
REGISTER_REQUEST = 1024
SYMMETRY_KEY_REQUEST = 1027
SERVERS_LIST_REQUEST = 1026
MSG_REQUEST = 1029
ME_FILE = "me.info.txt"
class Client:

    def __init__(self):
        self.ip_auth_server = ""
        self.port_auth_server = DEFAULT_VAL
        self.ip_msg_server = ""
        self.port_msg_server = DEFAULT_VAL
        # initialize the ips and ports servers.
        self.read_auth_info()

    def connect_to_server(self):
        print(f"[INFO] Starting client program, Version:{VERSION}.")
        request_handler = ClientRequestHeader(self.ip_auth_server, self.port_auth_server)
        server_address = (self.ip_auth_server, self.port_auth_server)
        print(f"[INFO] Connecting to authenticator server.")
        try:
            self.client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.client.connect(server_address)
        except:
            print(f"[ERROR] Can't connect to the server.\nPlease try again.")
            exit()
        # Sending register request
        if not os.path.exists(ME_FILE):
            print("[INFO] Sending register request to authenticator server.")
            data = request_handler.send_request(REGISTER_REQUEST)
            self.client.send(data)
            data_auth_server = self.client.recv(SIZE_PACKET)
            send_data = request_handler.handle_response(data_auth_server)
        # Sending Servers list request
        print("[INFO] Client registration was successful.")
        data = request_handler.send_request(SERVERS_LIST_REQUEST)
        self.client.send(data)
        data_auth_server = self.client.recv(SIZE_PACKET)
        self.ip_msg_server,self.port_msg_server = request_handler.handle_response(data_auth_server)
        # Sending symmetry key request to auth server
        print("[INFO] Sending symmetry key request to authenticator server.")
        data = request_handler.send_request(SYMMETRY_KEY_REQUEST)
        self.client.send(data)
        data_auth_server = self.client.recv(SIZE_PACKET)
        send_data = request_handler.handle_response(data_auth_server)
        self.client.close()
        self.client = None
        server_address = (self.ip_msg_server, self.port_msg_server)
        print("[INFO] Connected to message server.")
        print("[INFO] Sending symmetry key request to message server.")
        try:
            self.client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.client.connect(server_address)
        except:
            print(
                f"[ERROR] Can't connect to the server.")
        # Sending symmetry key request to msg server
        self.client.send(send_data)
        data_msg_server = self.client.recv(SIZE_PACKET)
        send_data = request_handler.handle_response(data_msg_server)
        if send_data != ERROR:
            print("[INFO] Sending message request to message server.")
            send_data = request_handler.send_request(MSG_REQUEST)
            self.client.send(send_data)
            data_msg_server = self.client.recv(SIZE_PACKET)
            request_handler.handle_response(data_msg_server)
            print("[INFO] Closing connection.")
        else:
            print("[INFO] Due to an error message from the message server, the connection is being closed. Please try again.")
        self.client.close()
        exit()
    """Reading the IP and Port to connect the authenticator user. """
    def read_auth_info(self):
        if os.path.exists(AUTH_FILE):
            with open(AUTH_FILE, "r") as file:
                line = file.readline()
                auth_line = line.split(":")
                self.ip_auth_server,self.port_auth_server = auth_line[0],int(auth_line[1])
        else:
            print(f"[ERROR] The {AUTH_FILE} is not exists, please try again.")
            exit(1)

if __name__ == '__main__':

    Client().connect_to_server()
