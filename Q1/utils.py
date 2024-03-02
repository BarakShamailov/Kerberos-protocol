from Crypto.Cipher import AES
import hashlib
from Crypto.Util.Padding import unpad, pad
CLIENTS_FILE = "clients"
SERVERS_FILE = "servers"
PASSWORD_POS = 2
KEY_POS = 2


# Hash the password using SHA-256
def hash_password(password):
    hashed_password = hashlib.sha256(password.encode('utf-8')).hexdigest()
    return hashed_password

# This function got data with the data variable and encrypting it.
def encrypt_data(key,data, iv):
    cipher = AES.new(key, AES.MODE_CBC, iv=iv)
    ciphered_data = cipher.encrypt(pad(data, AES.block_size))
    return ciphered_data

# This function got encrypted data and return the decrypted data.
def decrypt_data(key, encrypted_data,iv ):
    cipher = AES.new(key, AES.MODE_CBC, iv=iv)
    deciphered_data = unpad(cipher.decrypt(encrypted_data), AES.block_size)
    return deciphered_data


def find_password_by_uuid(uuid):
    with open(CLIENTS_FILE, "r") as file:
        lines = file.readlines()
        for line in lines:
            line = line.split(":")
            if uuid.hex() in line:
                return line[PASSWORD_POS]
    return b""

def find_server_key_by_uuid(uuid):
    with open(SERVERS_FILE, "r") as file:
        lines = file.readlines()
        for line in lines:
            line = line.split(":")
            for item in line:
                if uuid.hex() in item:
                    return bytes.fromhex(line[-1])
    return b""