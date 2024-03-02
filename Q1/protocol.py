from enum import Enum
import struct

SERVER_VERSION = 24
DEFAULT_VAL = 0
HEADER_RESPONSE_SIZE = 7
CLIENT_HEADER_SIZE = 23
ID_SIZE = 16
CLIENT_NAME_SIZE = 255
SERVER_NAME_SIZE = 255
PASSWORD_SIZE = 255
PUBLIC_KEY_SIZE = 160
AES_KEY_SIZE = 32
NONCE_SIZE = 8
ENCRYPTED_NONCE_SIZE = 16
IV_SIZE = 16
ENCRYPTED_AES_KEY_SIZE = 48
ENCRYPTED_KEY_SIZE = ENCRYPTED_AES_KEY_SIZE + ENCRYPTED_NONCE_SIZE + IV_SIZE
ENCRYPTED_EXPIRATION_TIME_SIZE = 16
TICKET_SIZE = 121
TIMESTAMP_SIZE = 8
ENCRYPTED_VERSION_SIZE = 16
ENCRYPTED_ID_SIZE = 32
ENCRYPTED_TIME_SIZE = 16
AUTH_SIZE = IV_SIZE + ENCRYPTED_VERSION_SIZE + ENCRYPTED_ID_SIZE + ENCRYPTED_ID_SIZE + ENCRYPTED_TIME_SIZE
MSG_SIZE = 4
IP_SIZE = 16
PORT_SIZE = 2

"""Authenticator server requests code and responses code"""
class ServerRequestsCode(Enum):
    REGISTRATION_CLIENT_REQUEST = 1024
    REGISTRATION_SERVER_REQUEST = 1025
    SERVERS_LIST_REQUEST = 1026
    SYMMETRY_KEY_REQUEST = 1027

class ServerResponseCode(Enum):
    RESPONSE_REGISTRATION_SUCCESSFUL = 1600
    RESPONSE_REGISTRATION_FAILED = 1601
    RESPONSE_SERVERS_LIST = 1602
    RESPONSE_SYMMETRY_KEY = 1603

class ServerRequestHeader:

    def __init__(self):
        self.id = b""
        self.version = DEFAULT_VAL      # 1 byte
        self.code = DEFAULT_VAL         # 2 bytes
        self.payload_size = DEFAULT_VAL  # 4 bytes

"""Packing and unpacking Client Registration Request data to authenticator server"""
class ClientRegistrationRequest(ServerRequestHeader):

    def __init__(self):
        super().__init__()
        self.name = b""
        self.password = b""

    def pack(self, code, name, password):
        try:
            payload = request_payload_size[code]
            self.version = SERVER_VERSION
            self.payload_size = struct.calcsize(payload)
            self.name = name
            self.password = password
            data = struct.pack(f"<{ID_SIZE}s BHL {CLIENT_NAME_SIZE}s {PASSWORD_SIZE}s", self.id, self.version, code, self.payload_size,
                               self.name.encode("utf-8"), self.password.encode("utf-8"))
            return data
        except:
            return b""

    def unpack(self, data):
        try:
            self.clientID, self.version, self.code, self.payload_size, self.name, self.password = struct.unpack(
                f"<{ID_SIZE}s BHL {CLIENT_NAME_SIZE}s"
                f"{PASSWORD_SIZE}s", data)
            self.clientID = self.clientID.decode().rstrip("\x00")

            self.name = self.name.decode().rstrip("\x00")
            self.password = self.password.decode().rstrip("\x00")
            return True
        except:
            return False

"""Packing and unpacking Server Registration Request data to authenticator server"""
class ServerRegistrationRequest(ServerRequestHeader):

    def __init__(self):
        super().__init__()
        self.server_name = ""
        self.AES_key = b""
        self.ip = b""
        self.port = DEFAULT_VAL

    def pack(self, code, name, key,ip,port):
        payload = request_payload_size[code]
        self.version = SERVER_VERSION
        self.payload_size = struct.calcsize(payload)
        self.server_name = name
        self.AES_key = key
        data = struct.pack(f"<{ID_SIZE}s BHL {SERVER_NAME_SIZE}s {AES_KEY_SIZE}s {IP_SIZE}s H", self.id, self.version, code, self.payload_size, self.server_name.encode("utf-8"), self.AES_key,ip,port)
        return data
    def unpack(self, data):
        try:
            self.id, self.version, self.code, self.payload_size, self.server_name, self.AES_key,self.ip,self.port = struct.unpack(f"<{ID_SIZE}s BHL {SERVER_NAME_SIZE}s {AES_KEY_SIZE}s {IP_SIZE}s H", data)

            self.id = self.id.decode().rstrip("\x00")
            self.server_name = self.server_name.decode().rstrip("\x00")
            self.ip = self.ip.decode().rstrip("\x00")
            return True

        except:
            return False

"""Packing and unpacking Servers List Request data to authenticator server"""
class ServersListRequest(ServerRequestHeader):
    def __init__(self):
        super().__init__()

    def pack(self, code):
        self.version = SERVER_VERSION
        data = struct.pack(f"<{ID_SIZE}s BHL", self.id, self.version, code, self.payload_size)
        return data

    def unpack(self, data):
        try:
            self.id, self.version, self.code, self.payload_size = struct.unpack( f"<{ID_SIZE}s BHL", data)
            self.id = self.id.decode().rstrip("\x00")

            return True

        except:
            return False
"""Packing and unpacking Symmetry Key Request data to authenticator server"""
class SymmetryKeyRequest(ServerRequestHeader):

    def __init__(self):
        super().__init__()
        self.server_id = b""
        self.nonce = b""

    def pack(self, client_id,code,server_id,nonce):
        self.version = SERVER_VERSION
        self.code = code
        self.payload_size = struct.calcsize(request_payload_size[self.code])
        data = struct.pack(f"<{ID_SIZE}s BHL  {ID_SIZE}s {NONCE_SIZE}s",client_id,self.version, self.code,self.payload_size,server_id,nonce)
        return data

    def unpack(self, data):
        try:
            self.id, self.version, self.code, self.payload_size, self.server_id,self.nonce = struct.unpack(
                f"<{ID_SIZE}s BHL  {ID_SIZE}s {NONCE_SIZE}s", data)
            return True
        except:
            return False

############## Handle responses frm authenticator server #################
class ResponseHeader:
    def __init__(self):
        self.version = SERVER_VERSION
        self.code = ServerResponseCode.RESPONSE_REGISTRATION_SUCCESSFUL.value

"""Packing and unpacking client registration response data to authenticator server"""
class ClientRegistrationResponse(ResponseHeader):
    def __init__(self,id=b""):
        super().__init__()
        self.payload_size = ID_SIZE
        self.client_id = id

    def pack(self):
        try:
            if self.code == ServerResponseCode.RESPONSE_REGISTRATION_SUCCESSFUL.value:
                data = struct.pack(f"<BHL {ID_SIZE}s", self.version, self.code, self.payload_size, self.client_id)
                return data
            else:
                data = struct.pack(f"<BHL", self.version, self.code, self.payload_size)
                return data
        except:
            return b""

    def unpack(self,response_data):
        try:
            version, code, payload = struct.unpack(f"<BHL", response_data[:HEADER_RESPONSE_SIZE])
            if code == ServerResponseCode.RESPONSE_REGISTRATION_SUCCESSFUL.value:
                id = struct.unpack(f"<{ID_SIZE}s", response_data[HEADER_RESPONSE_SIZE:CLIENT_HEADER_SIZE])
                return (version, code, payload, id)
            else:
                print("[ERROR] Server responded with an error.")
                return b""

        except:
            print("[ERROR] While trying to unpack the data.")
            return b""

    def registration_unsuccessful(self):
        self.code = ServerResponseCode.RESPONSE_REGISTRATION_FAILED.value

"""Packing and unpacking server registration response data to authenticator server"""
class ServerRegistrationResponse(ResponseHeader):

    def __init__(self,id=b""):
        super().__init__()
        self.payload_size = ID_SIZE
        self.server_id = id

    def pack(self):
        try:
            if self.code == ServerResponseCode.RESPONSE_REGISTRATION_SUCCESSFUL.value:
                data = struct.pack(f"<BHL {ID_SIZE}s", self.version, self.code, self.payload_size, self.server_id)
                return data
            else:
                data = struct.pack(f"<BHL", self.version, self.code, self.payload_size)
                return data
        except:
            return b""

    def unpack(self,response_data):
        try:
            self.version, self.code, self.payload = struct.unpack(f"<BHL", response_data[:HEADER_RESPONSE_SIZE])
            if self.code == ServerResponseCode.RESPONSE_REGISTRATION_SUCCESSFUL.value:
                self.id = struct.unpack(f"<{ID_SIZE}s", response_data[HEADER_RESPONSE_SIZE:CLIENT_HEADER_SIZE])[0]
                return True
            else:
                print("[ERROR] The server is already registered.")
                return False
        except:
            print("[ERROR] While trying to unpack the data.")
            return False

    def registration_unsuccessful(self):
        self.code = ServerResponseCode.RESPONSE_REGISTRATION_FAILED.value

"""Packing and unpacking serverss list response data to authenticator server"""
class ServersListResponse(ResponseHeader):

    def __init__(self):
        super().__init__()
        self.payload_size = DEFAULT_VAL

    def pack(self,code,servers_data):
        self.code = code
        self.calculate_payload_size(servers_data)
        servers = self.pack_servers_data(servers_data)
        data = struct.pack(f"<BHL", self.version, self.code, self.payload_size)
        data += servers
        return data

    def unpack(self, data):
        try:
            servers_list = list()
            self.version, self.code, self.payload_size = struct.unpack(f"<BHL", data[:HEADER_RESPONSE_SIZE])
            num_of_servers = self.payload_size / struct.calcsize(response_payload_size[self.code])
            start = HEADER_RESPONSE_SIZE
            end = HEADER_RESPONSE_SIZE + IP_SIZE
            # unpacking the data's servers and insert the name and the id per each server to list.
            for server in range(int(num_of_servers)):
                ip = struct.unpack(f"<{IP_SIZE}s", data[start:end])[0].decode().rstrip("\x00")
                start += IP_SIZE
                end += PORT_SIZE
                port = struct.unpack(f"<H", data[start:end])[0]
                start += PORT_SIZE
                end += ID_SIZE
                server_id = struct.unpack(f"<{ID_SIZE}s", data[start:end])[0]
                start += ID_SIZE
                end += SERVER_NAME_SIZE
                server_name = struct.unpack(f"<{SERVER_NAME_SIZE}s", data[start:end])[0]
                start += SERVER_NAME_SIZE
                end += ID_SIZE
                servers_list.append([ip, port, server_id, server_name.decode("utf-8").rstrip("\x00")])
            return servers_list
        except:
            return b""

    def calculate_payload_size(self,servers_data):
        payload_size_per_server = response_payload_size[self.code]
        num_of_servers = len(servers_data)
        self.payload_size = num_of_servers * struct.calcsize(payload_size_per_server)

    def pack_servers_data(self,servers_list):
        data = b""
        for server in servers_list:
            data += struct.pack(f"<{IP_SIZE}s", server[0].encode("utf-8"))
            data += struct.pack(f"<H ", int(server[1]))
            data += struct.pack(f"<{ID_SIZE}s", server[2])
            data += struct.pack(f"<{SERVER_NAME_SIZE}s", server[3].encode("utf-8"))
        return data
"""Packing and unpacking symmetry key response data to authenticator server"""
class SymmetryKeyResponse(ResponseHeader):
    def __init__(self):
        super().__init__()
        self.client_id = b""

    def encrypt_symmetry_key(self,nonce, key, iv):
        self.nonce , self.client_encrypted_aes_key, self.iv = nonce, key, iv

    def ticket(self,client_id, server_id, timestamp, iv, key, expiration_time):
        self.client_id = client_id
        self.server_id = server_id
        self.timestamp = timestamp
        self.ticket_iv = iv
        self.server_encrypted__aes_key = key
        self.expiration_time = expiration_time

    def pack(self, code):
        self.code = code
        self.payload_size = struct.calcsize(response_payload_size[self.code])
        data = struct.pack(f"<BHL", self.version, self.code, self.payload_size)
        data += struct.pack(f"<{ID_SIZE}s",self.client_id)
        data += struct.pack(f"<{IV_SIZE}s {ENCRYPTED_NONCE_SIZE}s {ENCRYPTED_AES_KEY_SIZE}s", self.nonce, self.iv, self.client_encrypted_aes_key)# packing the encrypted symmetry key
        # packing the ticket
        data += struct.pack(f"<B {ID_SIZE}s{ID_SIZE}s {TIMESTAMP_SIZE}s {IV_SIZE}s {ENCRYPTED_AES_KEY_SIZE}s {ENCRYPTED_EXPIRATION_TIME_SIZE}s",self.version, self.client_id, self.server_id,self.timestamp,self.ticket_iv, self.server_encrypted__aes_key,self.expiration_time)
        return data

    def unpack_encrypted_key(self, data):
        self.version, self.code, self.payload_size = struct.unpack(f"<BHL", data[:HEADER_RESPONSE_SIZE])
        data = data[HEADER_RESPONSE_SIZE:]
        self.client_id = struct.unpack(f"<{ID_SIZE}s", data[:ID_SIZE])
        data = data[ID_SIZE:]
        self.nonce, self.iv, self.client_encrypted_aes_key = struct.unpack(f"<{IV_SIZE}s {ENCRYPTED_NONCE_SIZE}s {ENCRYPTED_AES_KEY_SIZE}s", data[:ENCRYPTED_KEY_SIZE])
        data = data[ENCRYPTED_KEY_SIZE:]
        return True, data

"""Message server requests code and responses code"""
class EMessagesServerRequestCode(Enum):
    SYMMETRY_KEY_REQUEST = 1028
    MESSAGE_REQUEST = 1029

class EMessagesServerResponseCode(Enum):
    RESPONSE_SYMMETRY_KEY_APPROVE = 1604
    RESPONSE_APPROVAL_OF_MESSAGE_RECEIVED = 1605
    RESPONSE_GENERAL_ERROR = 1609

########### Message server requests ################
class MsgServerHeaderRequest():

    def __init__(self):
        self.client_id = b""
        self.version = DEFAULT_VAL  # 1 byte
        self.code = DEFAULT_VAL  # 2 bytes
        self.payload_size = DEFAULT_VAL  # 4 bytes

"""Packing and unpacking symmetry key request data to message server"""
class SendMsgServerSymmetryKeyRequest(MsgServerHeaderRequest):
    def __init__(self,iv=b"",version=DEFAULT_VAL,client_id=b"", server_id=b"", creation_time=""):
        super().__init__()
        self.version = SERVER_VERSION
        self.auth_iv = iv
        self.encrypted_version = version
        self.encrypted_client_id = client_id
        self.server_id = server_id
        self.creation_time = creation_time

    def pack(self,client_id,code,ticket):
        # Packing header request
        self.client_id = client_id
        self.code = code
        self.payload_size = struct.calcsize(request_payload_size[self.code])
        data = struct.pack(f"<{ID_SIZE}s BHL",self.client_id,self.version,self.code,self.payload_size)
        # packing auth
        data += struct.pack(f"<{IV_SIZE}s {ENCRYPTED_VERSION_SIZE}s {ENCRYPTED_ID_SIZE}s {ENCRYPTED_ID_SIZE}s {ENCRYPTED_TIME_SIZE}s",
                           self.auth_iv,self.encrypted_version,self.encrypted_client_id,self.server_id,self.creation_time)
        data += ticket
        return data

    def unpack_header(self, data):
        data = data[:CLIENT_HEADER_SIZE]
        client_id, version, code, payload_size = struct.unpack(f"<{ID_SIZE}s BHL",data)
        return client_id,version

    def unpack_auth(self, data):
        data = data[CLIENT_HEADER_SIZE:AUTH_SIZE+CLIENT_HEADER_SIZE]
        auth_iv, encrypted_version, encrypted_client_id, server_id, creation_time = struct.unpack(f"<{IV_SIZE}s {ENCRYPTED_VERSION_SIZE}s {ENCRYPTED_ID_SIZE}s {ENCRYPTED_ID_SIZE}s {ENCRYPTED_TIME_SIZE}s",data)
        return auth_iv, encrypted_version, encrypted_client_id, server_id, creation_time

    def unpack_ticket(self, data):
        data = data[CLIENT_HEADER_SIZE+AUTH_SIZE:]
        version,client_id,server_id,timestamp,ticket_iv, aes_key,expiration_time = struct.unpack(f"<B {ID_SIZE}s {ID_SIZE}s {TIMESTAMP_SIZE}s {IV_SIZE}s {ENCRYPTED_AES_KEY_SIZE}s {ENCRYPTED_EXPIRATION_TIME_SIZE}s",data)
        return version,client_id,server_id,timestamp,ticket_iv, aes_key,expiration_time

"""Packing and unpacking message request data"""
class SendMsgServerRequest(MsgServerHeaderRequest):

    def __init__(self):
        super().__init__()
        self.version = SERVER_VERSION
        self.message_size = DEFAULT_VAL
        self.msg_iv = b""
        self.message_content = b""

    def pack(self,id,code,iv,msg_content):
        self.client_id = id
        self.code = code
        self.msg_iv = iv
        self.message_size = len(msg_content)
        self.message_content = msg_content
        self.payload_size = MSG_SIZE + IV_SIZE + self.message_size
        data = struct.pack(f"<{ID_SIZE}s BHL L {IV_SIZE}s {self.message_size}s",self.client_id,self.version,self.code,self.payload_size,self.message_size,self.msg_iv,self.message_content)
        return data

    def unpack(self,data):
        msg_content_size = len(data) - (CLIENT_HEADER_SIZE + IV_SIZE + MSG_SIZE)
        self.client_id,self.version,self.code,self.payload_size,self.message_size,self.msg_iv,self.message_content = struct.unpack(f"<{ID_SIZE}s BHL L {IV_SIZE}s {msg_content_size}s", data)
        return self.client_id,self.version,self.code,self.payload_size,self.message_size,self.msg_iv,self.message_content

########### Message server response ################
class MsgServerHeaderResponse():
    def __init__(self):
        self.version = SERVER_VERSION
        self.code = DEFAULT_VAL
        self.payload_size = DEFAULT_VAL


"""Response to message server requests"""
class SendMsgServerResponse(MsgServerHeaderResponse):
    def __init__(self):
        super().__init__()
        self.msg = b""

    def pack(self,code,data):
        self.code = code
        self.payload_size = len(data)
        response = struct.pack(f"<BHL {self.payload_size}s",self.version,self.code, self.payload_size,data)
        return response

    def unpack(self,data):
        version, code, payload_size = struct.unpack(f"<BHL ",data[:HEADER_RESPONSE_SIZE])
        msg = struct.unpack(f"<{payload_size}s ",data[HEADER_RESPONSE_SIZE:])[0]
        return version, code, payload_size, msg

"""Two dictonaries that store the payload size for each request type and response type"""
request_payload_size = {
            ServerRequestsCode.REGISTRATION_CLIENT_REQUEST.value :  f"<{CLIENT_NAME_SIZE}s {PASSWORD_SIZE}s ",
            ServerRequestsCode.REGISTRATION_SERVER_REQUEST.value :  f"<{SERVER_NAME_SIZE}s {AES_KEY_SIZE}s",
            ServerRequestsCode.SYMMETRY_KEY_REQUEST.value :  f"<{ID_SIZE}s {ID_SIZE}s {NONCE_SIZE}s",
            EMessagesServerRequestCode.SYMMETRY_KEY_REQUEST.value : f"<{AUTH_SIZE}s {TICKET_SIZE}s"
        }
response_payload_size = {
            ServerResponseCode.RESPONSE_REGISTRATION_SUCCESSFUL.value :  f"<{ID_SIZE}s",
            ServerResponseCode.RESPONSE_SERVERS_LIST.value : f"<{ID_SIZE}s {SERVER_NAME_SIZE}s {IP_SIZE}s H",
            ServerResponseCode.RESPONSE_SYMMETRY_KEY.value: f"<{ID_SIZE}s {NONCE_SIZE}s {IV_SIZE}s {AES_KEY_SIZE}s B {ID_SIZE}s{ID_SIZE}s{TIMESTAMP_SIZE}s {IV_SIZE}s {AES_KEY_SIZE}s {TIMESTAMP_SIZE}s"
        }
