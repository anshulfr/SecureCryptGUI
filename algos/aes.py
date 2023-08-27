import base64
from cryptography.fernet import Fernet
import os
from keygen import generate_key


def encrypt_path(password, path):
    password = password.encode()
    salt = os.urandom(16)
    fernet_key = generate_key(password, salt, 32)
    fernet = Fernet(base64.urlsafe_b64encode(fernet_key))

    directory, old_filename = os.path.split(path)
    filename, extension = os.path.splitext(old_filename)

    new_filename = f"{filename}_encrypted{extension}"
    enc_path = os.path.join(directory, new_filename).replace("\\", "/")

    with open(path, 'rb') as file:
        plaintext = file.read()

    ciphertext = fernet.encrypt(plaintext)

    with open(enc_path, 'wb') as file:
        file.write(base64.urlsafe_b64encode(fernet_key) + salt + ciphertext)

    os.remove(path)


def encrypt(password, path):
    if os.path.isfile(path):
        encrypt_path(password, path)
    else:
        for root, _, files in os.walk(path):
            for file_name in files:
                file_path = os.path.join(root, file_name)
                encrypt_path(password, file_path)


def decrypt_path(password, path):
    password = password.encode()
    with open(path, 'rb') as file:
        content = file.read()

    directory, old_filename = os.path.split(path)
    filename, extension = os.path.splitext(old_filename)

    if filename.endswith("_encrypted"):
        original_filename = filename.rsplit("_encrypted", 1)[0] + extension
        dec_path = os.path.join(directory, original_filename).replace("\\", "/")

        salt = content[44:60]
        fernet_key = generate_key(password, salt, 32)
        fernet = Fernet(base64.urlsafe_b64encode(fernet_key))

        with open(path, 'rb') as file:
            ciphertext = file.read()[60:]

        plaintext = fernet.decrypt(ciphertext)

        with open(dec_path, 'wb') as file:
            file.write(plaintext)

        os.remove(path)


def decrypt(password, path):
    if os.path.isfile(path):
        decrypt_path(password, path)
    else:
        for root, _, files in os.walk(path):
            for file_name in files:
                file_path = os.path.join(root, file_name)
                decrypt_path(password, file_path)
