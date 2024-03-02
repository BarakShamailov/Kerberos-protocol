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
import socket
import protocol
import struct
import base64
from Crypto.Random import get_random_bytes
import threading
import utils
import datetime

SERVER_NAME = "Barak's Server"
MSG_FILE = "msg.info.txt"
AUTH_FILE = "auth.info.txt"
PACKET_SIZE = 2048
DEFAULT_IP = "127.0.0.1"
DEFAULT_PORT = 9999
VERSION = 24
CLIENTS_FILE = "clients"
START_POS_CODE = 17
END_POS_CODE = 19
REGISTER_REQUEST = 1025
MAX_LINES = 4
ERROR_MSG = "[ERROR] Server responded with an error."
class MessagesServer:

    def __init__(self):
        self.session_key = b""
        self.server_name = ""
        self.server_key = b""
        self.server_id = b""
        self.ip, self.port = self.reading_connection_server(MSG_FILE)
        self.version = VERSION
        self.clients = list()
        self.request_handle = {
            protocol.ServerRequestsCode.REGISTRATION_SERVER_REQUEST.value : self.send_register_request,
            protocol.EMessagesServerRequestCode.SYMMETRY_KEY_REQUEST.value : self.handle_symmetry_key_request,
            protocol.EMessagesServerRequestCode.MESSAGE_REQUEST.value: self.handle_msg_request
        }

    def reading_connection_server(self,file_name):
        if os.path.exists(MSG_FILE):
            with open(file_name,"r") as file:
                lines = file.readlines()
                ip,port = lines[0][:-1].split(":")# Without \n
                if file_name == MSG_FILE:
                    self.server_name = lines[1][:-1] # Without \n
                    self.server_id = bytes.fromhex(lines[2][:-1])# Without \n
                    self.server_key = base64.b64decode(lines[3])
            return ip, int(port)
        else:
            print(f"[INFO] - the file {MSG_FILE} is not exists.")
            self.server_name = input("Please insert the server name: ")
            with open(MSG_FILE, "w") as file:
                file.write(f"{DEFAULT_IP}:{DEFAULT_PORT}\n")
                file.write(self.server_name + "\n")
            return DEFAULT_IP,DEFAULT_PORT

    def start_server(self):
        # If the server is not registered
        if not self.server_id and not self.server_key:
            server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            server.connect((self.reading_connection_server(AUTH_FILE)))
            print("[INFO] Connecting to authenticator server.")
            data_packed = self.request_handle[REGISTER_REQUEST](REGISTER_REQUEST)
            server.send(data_packed)
            response_data = server.recv(PACKET_SIZE)
            print("[INFO] received response from auth server. ")
            auth_server_response = protocol.ServerRegistrationResponse()
            if not auth_server_response.unpack(response_data):
                print("[INFO] The registration failed, please try again.")
                exit(1)
            print("[INFO] The registration was successful.")
            self.server_id = auth_server_response.id
            if not self.update_msg_info():
                print("[ERROR] There was an issue while trying to create the 'msg.info' file.")

        try:
            server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            server.bind((self.ip, self.port))
            server.listen()
            print(f"[INFO] Message Server starting listening on {self.ip}:{self.port}, , Version:{VERSION}.")
            while True:
                connection, client_address = server.accept()
                print(f"The client {client_address} connected")
                self.client_thread = threading.Thread(target=self.client_handler, daemon=True, args=(connection,))
                self.client_thread.start()
        except Exception:
            print(
                f"[ERROR] There is problem to setup the server.\nPlease check the IP and the Port that you entered and try again.")
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
            code_request = struct.unpack(f"<H", client_data[START_POS_CODE:END_POS_CODE])[0]# Unpack the code request
            if code_request:
                # Check whether the code request is valid; if so, call the appropriate function.
                if code_request in self.request_handle.keys():
                    response = self.request_handle[code_request](client_data)
                    if not response:
                        print("[ERROR] can't send response.")
                    else:
                        client_connection.send(response)
                        continue
                else:
                    print("[ERROR] Invalid request, please try again.")
            else:
                client_connection.close()
                print("[INFO] Connection has been closed!")
                break
            break
        print("[INFO] Closing connection with the client.")
        client_connection.close()

    """Handle the symmetry key request from the user"""
    def handle_symmetry_key_request(self,data):
        print("[INFO] Symmetry key request has been received.")
        client_request = protocol.SendMsgServerSymmetryKeyRequest()
        client_id_header,version_header = client_request.unpack_header(data)
        version_ticket, client_id_ticket, server_id_ticket, timestamp_ticket, ticket_iv, aes_key_ticket, expiration_time_ticket = client_request.unpack_ticket(data)
        auth_iv, encrypted_version_auth, encrypted_client_id_auth, server_id_auth, creation_time_auth = client_request.unpack_auth(data)
        # Check match between the header request data to the ticket data
        if version_ticket != version_header or client_id_ticket.hex() != client_id_header.hex() or server_id_ticket != self.server_id:
            server_msg = ERROR_MSG.encode("utf-8")
            response = protocol.SendMsgServerResponse().pack(
                protocol.EMessagesServerResponseCode.RESPONSE_GENERAL_ERROR.value, server_msg)
            return response
        aes_key = utils.decrypt_data(self.server_key, aes_key_ticket, ticket_iv)
        self.session_key = aes_key

        expiration_time_ticket = utils.decrypt_data(self.server_key, expiration_time_ticket, ticket_iv)

        expiration_time = datetime.datetime.strptime(expiration_time_ticket.decode(), '%d-%m-%y %H:%M')
        current_time = datetime.datetime.strptime(datetime.datetime.now().strftime('%d-%m-%y %H:%M'), '%d-%m-%y %H:%M')
        if expiration_time < current_time:
            print("[ERROR] The ticket expiration time is expired.")
            server_msg = ERROR_MSG.encode("utf-8")
            response = protocol.SendMsgServerResponse().pack(
                protocol.EMessagesServerResponseCode.RESPONSE_GENERAL_ERROR.value, server_msg)
            return response
        original_exp_time = datetime.datetime.strptime(expiration_time_ticket.decode(), '%d-%m-%y %H:%M')
        original_timestamp = original_exp_time - datetime.timedelta(minutes=8)
        timestamp_ticket = original_timestamp.strftime('%d-%m-%y %H:%M')

        # Decrypted the authenticator
        creation_time_auth = utils.decrypt_data(aes_key,creation_time_auth,auth_iv)
        decrypted_version_auth = struct.unpack(f"<B",utils.decrypt_data(aes_key,encrypted_version_auth,auth_iv))[0]
        decrypted_client_id_auth = utils.decrypt_data(aes_key, encrypted_client_id_auth, auth_iv)
        server_id_auth = utils.decrypt_data(aes_key, server_id_auth, auth_iv)

        # Checking if there is match between ticket data to authenticator data.
        if server_id_auth != self.server_id:
            print("[ERROR] There is no match between server id.")
            server_msg = ERROR_MSG.encode("utf-8")
            response = protocol.SendMsgServerResponse().pack(
                protocol.EMessagesServerResponseCode.RESPONSE_GENERAL_ERROR.value, server_msg)
            return response
        if decrypted_version_auth != version_ticket:
            print("[ERROR] There is no match between version number.")
            server_msg = ERROR_MSG.encode("utf-8")
            response = protocol.SendMsgServerResponse().pack(
                protocol.EMessagesServerResponseCode.RESPONSE_GENERAL_ERROR.value, server_msg)
            return response
        if decrypted_client_id_auth != client_id_ticket:
            print("[ERROR] There is no match between client id.")
            server_msg = ERROR_MSG.encode("utf-8")
            response = protocol.SendMsgServerResponse().pack(
                protocol.EMessagesServerResponseCode.RESPONSE_GENERAL_ERROR.value, server_msg)
            return response
        # Check if there is difference between timestamps
        if creation_time_auth.decode("utf-8") != timestamp_ticket:
            print("[ERROR] The creation time of authenticator and timestamp ticket is not equal.")
            server_msg = ERROR_MSG.encode("utf-8")
            response = protocol.SendMsgServerResponse().pack(
                protocol.EMessagesServerResponseCode.RESPONSE_GENERAL_ERROR.value, server_msg)
            return response
        msg = "Accept symmetry key".encode("utf-8")
        self.clients.append(client_id_ticket.hex())
        response = protocol.SendMsgServerResponse().pack(protocol.EMessagesServerResponseCode.RESPONSE_SYMMETRY_KEY_APPROVE.value,msg)
        print("[INFO] Sending response to Symmetry Key request.")
        return response
    """Handle message request that got from the client"""
    def handle_msg_request(self, data):
        print("[INFO] Message request has been received.")
        client_id, version, code, payload_size, message_size, msg_iv, message_content = protocol.SendMsgServerRequest().unpack(data)

        # Checking if the client id already sent symmetry key
        if client_id.hex() not in self.clients:
            print("[ERROR] unauthorized user.")
            server_msg = ERROR_MSG.encode("utf-8")
            response = protocol.SendMsgServerResponse().pack(
                protocol.EMessagesServerResponseCode.RESPONSE_GENERAL_ERROR.value, server_msg)
            return response
        decrypted_msg = utils.decrypt_data(self.session_key,message_content,msg_iv)
        print(f"[INFO] Printing user message: {decrypted_msg.decode()}.")
        server_msg = "Accept message, thanks.".encode("utf-8")
        response = protocol.SendMsgServerResponse().pack(
            protocol.EMessagesServerResponseCode.RESPONSE_APPROVAL_OF_MESSAGE_RECEIVED.value, server_msg)
        print("[INFO] Sending response to message request.")
        return response

    """Sending register request to authenticator server"""
    def send_register_request(self,code):
        print("[INFO] Sending register request to authenticator server.")
        code_request = code
        self.server_key = get_random_bytes(protocol.AES_KEY_SIZE)
        request = protocol.ServerRegistrationRequest().pack(code_request, self.server_name, self.server_key,self.ip.encode("utf-8"),self.port)
        return request

    def update_msg_info(self):
        try:
            with open(MSG_FILE, "a") as file:
                file.write(self.server_id.hex()+ "\n")
                file.write(base64.b64encode(self.server_key).decode("utf-8"))
            print("[INFO] The msg.info updated successfully.")
            return True
        except:
            return False



if __name__ == '__main__':
    MessagesServer().start_server()

