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
import datetime
import protocol
import struct
import os
from Crypto.Random import get_random_bytes
import utils
ME_FILE = "me.info.txt"
VERSION = 24
START_POS_CODE = 1
END_POS_CODE = 3
NONCE_BYTES = 8
MAX_LINES = 2
exists_me_file = False
class ClientRequestHeader:

    def __init__(self,ip,port):
        self.ip = ip
        self.port = port
        self.name = ""
        self.id = ""
        self.version = VERSION
        self.password = self.check_password()
        self.nonce = b""
        self.session_key = b""
        self.server_id = b""
        self.request_handle = {
            protocol.ServerRequestsCode.REGISTRATION_CLIENT_REQUEST.value: self.send_register_request,
            protocol.ServerRequestsCode.SERVERS_LIST_REQUEST.value : self.send_servers_list_request,
            protocol.ServerRequestsCode.SYMMETRY_KEY_REQUEST.value: self.send_symmetry_key_request,
            protocol.EMessagesServerRequestCode.MESSAGE_REQUEST.value : self.send_message
        }
        self.response_handle = {
            protocol.ServerResponseCode.RESPONSE_SERVERS_LIST.value: self.handle_servers_list_response,
            protocol.ServerResponseCode.RESPONSE_REGISTRATION_SUCCESSFUL.value : self.handle_register_response,
            protocol.ServerResponseCode.RESPONSE_REGISTRATION_FAILED.value : self.handle_register_response,
            protocol.ServerResponseCode.RESPONSE_SYMMETRY_KEY.value : self.handle_symmetry_key_response,
            protocol.EMessagesServerResponseCode.RESPONSE_SYMMETRY_KEY_APPROVE.value : self.msg_symmetry_key_response,
            protocol.EMessagesServerResponseCode.RESPONSE_APPROVAL_OF_MESSAGE_RECEIVED.value: self.handle_msg_response,
            protocol.EMessagesServerResponseCode.RESPONSE_GENERAL_ERROR.value: self.handle_msg_error_response,
        }

    def read_client_details(self):
        """Cheking if me.info file is exists"""
        if os.path.exists(ME_FILE):
            with open(ME_FILE, "r") as file:
                lines = file.readlines()
                self.name = lines[0][:-1] # Without \n
                self.id = bytes.fromhex(lines[1][:-1])# Without \n
        else:
            print(f"[INFO] The {ME_FILE} is not exists.")
            while True:
                self.name = input("Please insert your name: ")
                if len(self.name) < protocol.CLIENT_NAME_SIZE:
                    break
                print("[ERROR] The name is too long, please try again.")
            with open(ME_FILE, "w") as file:
                file.write(self.name + "\n")

    def send_request(self,code_request):
        """Handle the requests from the client"""
        self.read_client_details()
        if code_request in self.request_handle.keys():
            data_packed = self.request_handle[code_request](code_request)
            return data_packed
        else:
            print("[ERROR] Invalid code request.")

    def send_register_request(self,code):
        data = protocol.ClientRegistrationRequest().pack(code,self.name,self.password)
        return data

    def send_servers_list_request(self,code):
        print("[INFO] Sending servers list request to authenticator server.")
        data = protocol.ServersListRequest().pack(code)
        return data

    def send_symmetry_key_request(self, code):
        self.nonce = get_random_bytes(NONCE_BYTES)
        data = protocol.SymmetryKeyRequest().pack(self.id,code, bytes.fromhex(self.server_id),self.nonce)
        return data

    def handle_response(self,response_data):
        code_request = struct.unpack(f"<H", response_data[START_POS_CODE:END_POS_CODE])[0]

        if code_request in self.response_handle.keys():
            response = self.response_handle[code_request](response_data)
            if response == protocol.EMessagesServerResponseCode.RESPONSE_GENERAL_ERROR.value:
                return protocol.EMessagesServerResponseCode.RESPONSE_GENERAL_ERROR.value
            if response:
                return response

        else:
            print("[ERROR] Got invalid request from the server.")

    def handle_servers_list_response(self,response_data):
        unpacked_data = protocol.ServersListResponse().unpack(response_data)
        servers = list()
        first_position = 1
        if not unpacked_data:
            print("[ERROR] Unable to unpack the data response server.")
        else:
            #  Print the server list to the user.
            print("Servers List:")
            for num,server in enumerate(unpacked_data):
                print(f"{num+1}. Server ID: {server[2].hex()} | Server name: {server[3]} | IP: {server[0]} | Port:{server[1]}.")
                servers.append([server[0],server[1],server[2]])
            while True:
                # Wait to input from the user and connect to the message server by his input
                try:
                    user_choice = int(input("Please write the number's server that you want to connect: "))
                    if user_choice > len(servers) or user_choice < first_position:
                        print("[ERROR] Invalid server number, try again.")
                        continue
                    self.server_id = servers[user_choice - 1][2].hex()
                    msg_ip = servers[user_choice - 1][0]
                    msg_port = servers[user_choice - 1][1]
                    return msg_ip,msg_port
                except ValueError:
                    print("[ERROR] Wrong choice, please write only numbers.")
                    continue


    def handle_symmetry_key_response(self,response_data):
        print("[INFO] Handle symmetry key request response form authenticator server.")
        server_response = protocol.SymmetryKeyResponse()
        """The ticket we send to msg server """
        success, packed_ticket = server_response.unpack_encrypted_key(response_data)
        if not success:
            print("[ERROR] Unable to unpack the data response server.")
        else:
            client_key = bytes.fromhex(utils.hash_password(self.password))# Find user password from clients file and convert it to digest from hexdigest
            # Checking if the nonce from the server are equal to the client's nonce.
            decrypted_nonce = utils.decrypt_data(client_key,server_response.nonce,server_response.iv) #
            if decrypted_nonce != self.nonce:
                print("[ERROR] The nonce from the server is not equal to client's nonce, closing...")
                exit()

            decrypted_aes_key = utils.decrypt_data(client_key,server_response.client_encrypted_aes_key,server_response.iv)
            self.session_key = decrypted_aes_key

            # creating the authenticator
            auth_iv = get_random_bytes(protocol.IV_SIZE)
            encrypted_version = utils.encrypt_data(decrypted_aes_key,struct.pack("<B",server_response.version),auth_iv)
            encrypted_client_id = utils.encrypt_data(decrypted_aes_key, server_response.client_id[0], auth_iv)
            encrypted_server_id = utils.encrypt_data(decrypted_aes_key, bytes.fromhex(self.server_id), auth_iv)
            creation_time = datetime.datetime.now().strftime('%d-%m-%y %H:%M').encode("utf-8")
            encrypted_time = utils.encrypt_data(decrypted_aes_key, creation_time, auth_iv)

            # build the request and its data to the msg server.
            request = protocol.SendMsgServerSymmetryKeyRequest(auth_iv,encrypted_version,encrypted_client_id,encrypted_server_id,encrypted_time)
            code_request = protocol.EMessagesServerRequestCode.SYMMETRY_KEY_REQUEST.value
            send_data = request.pack(self.id,code_request,packed_ticket)
            return send_data
    """Send Message request to message server, If the user want to stop he need to insert '-'."""
    def send_message(self,code_request):
        msg_iv = get_random_bytes(protocol.IV_SIZE)
        msg = input("Please write message that the message server will print: ")
        encrypted_msg = utils.encrypt_data(self.session_key,msg.encode("utf-8"),msg_iv)
        data = protocol.SendMsgServerRequest().pack(self.id,code_request,msg_iv,encrypted_msg)
        return data
    def msg_symmetry_key_response(self,response_data):
        print("[INFO] Handle symmetry key request response form message server.")
        version, code, payload_size, msg = protocol.SendMsgServerResponse().unpack(response_data)
        print(f"[INFO] {msg.decode()}.")

    def handle_msg_error_response(self,response_data):
        print("[INFO] Handle error response form message server.")
        version, code, payload_size, msg = protocol.SendMsgServerResponse().unpack(response_data)
        print(f"[INFO] {msg.decode()}")
        return protocol.EMessagesServerResponseCode.RESPONSE_GENERAL_ERROR.value

    def handle_msg_response(self,response_data):
        print("[INFO] Handle message request response form message server.")
        version, code, payload_size, msg = protocol.SendMsgServerResponse().unpack(response_data)
        print(f"[INFO] {msg.decode()}")

    def handle_register_response(self,response_data):
        print("[INFO] Handle client registration response form authenticator server.")
        response = protocol.ClientRegistrationResponse()
        unpacked_data = response.unpack(response_data)
        if not unpacked_data:
            return False
        self.id = unpacked_data[-1][0]
        if response.code != protocol.ServerResponseCode.RESPONSE_REGISTRATION_FAILED.value:
            if not self.update_me_info():
                print("[ERROR] There was an issue while trying to create the 'me.info' file.")
                return False
        return True
    """Update the me.info file"""
    def update_me_info(self):
        try:
            with open(ME_FILE, "a") as file:
                file.write(self.id.hex() + "\n")
            return True
        except:
            return False

    def check_password(self):
        while True:
            password = input("Please insert the password: ")
            if len(password) < protocol.PASSWORD_SIZE:
                break
            print("[ERROR] The password is too long, please try again.")
        return password



