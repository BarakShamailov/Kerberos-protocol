import hashlib
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad, pad

""""Function that use to decrypt data """
def decrypt_data(key, encrypted_data,iv ):
    cipher = AES.new(key, AES.MODE_CBC, iv=iv)
    deciphered_data = unpad(cipher.decrypt(encrypted_data), AES.block_size)
    return deciphered_data
""""Function that use to encrypt data """
def encrypt_data(key,data, iv):
    cipher = AES.new(key, AES.MODE_CBC, iv=iv)
    ciphered_data = cipher.encrypt(pad(data, AES.block_size))
    return ciphered_data

"""Hashing algorithm (sha256) commonly used for hashing passwords"""
def sha256_password(password):
    hashed_password = hashlib.sha256(password.encode('utf-8')).digest()
    return hashed_password

"""Combine two passwords from the dictionary."""
def combine_passwords(passwords):
    mix_passwords = list()
    for first_pass in passwords:
        for second_pass in passwords:
            mix_passwords.append(first_pass+second_pass)
            mix_passwords.append(second_pass+first_pass)
    return mix_passwords


"""Data from the symmetry key request and response between client to authenticator server """
CLIENT_NONCE = b'\x95\x98\xb4\xadu\x1f~\xcf' # Unencrypted nonce that the client create and send it to the authenticator client.
IV = b'j\xc8JiW\xd7\x19~\xf8\x0f\xef)\xa5\x1e\x9bq' # IV that use to encrypt the nonce
ENCRYPTED_NONCE = b's\x87\xfc\xff\r\xa8\xd9\xf2\xa6\xcd\xbf\x81\x0c9\xbc"' # The Encrypted nonce send from the aut server to client.
AES_KEY_SIZE = 32
# Dictionary of 42 common passwords
common_passwords = [
                       "admin","12345678","123456789","1234","12345","password","123","Aa123456","1234567890","UNKNOWN"
    ,"1234657","123123","111111","Password","12345678910","000000","admin123","user","123456","qwerty","dragon","abc123",
    "dragon","letmein","shadow","master","baseball","666666","696969","football","123321","qwertyuiop","1q2w3e","aa12345678",
    "welcome","888888","123qwe","princess","7777777","monkey","654321","iloveyou"
    ]




def find_user_password(passwords):
    # First round to find user password with the original common passwords
    for password in passwords:
        # Calculate hash password, the result will be the symmetry key's client.
        hash_sha256_password = sha256_password(password)

        # Encrypt nonce with key that created from sha256 hashing password
        encrypted_nonce_sha256key = encrypt_data(hash_sha256_password, CLIENT_NONCE, IV)
        # check weather the encrypted_nonce equal to the ENCRYPTED_NONCE sent from the aut server to client.
        if encrypted_nonce_sha256key == ENCRYPTED_NONCE:
            # If it is equal it is sign to we have the correct symmetry ket between client to auth server.
            decrypted_nonce = decrypt_data(hash_sha256_password, encrypted_nonce_sha256key, IV)
            # Another check to approve that when we will decrypt the nonce we will get the original nonce.
            if decrypted_nonce == CLIENT_NONCE:
                found_password = f"The user's password is {password}!"
                return found_password
    return ""

if __name__ == "__main__":
    # First round attempt to find the user's password by using original common passwords.
    result = find_user_password(common_passwords)
    if result:
        print(result)
    else:
        combined_passwords = combine_passwords(common_passwords)
        # Second round, attempt to find the user's password by using a combination of common passwords.
        result = find_user_password(combined_passwords)
        if result:
            print(result)
        else:
            print("The user's password not found...")


