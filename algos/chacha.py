from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms
import os
from keygen import generate_key


def encrypt_path(password, path):
    password = password.encode()
    salt = os.urandom(16)
    encryption_key = generate_key(password, salt, 32)

    cipher = Cipher(algorithms.ChaCha20(encryption_key, salt), mode=None, backend=default_backend())
    encryptor = cipher.encryptor()

    directory, old_filename = os.path.split(path)
    filename, extension = os.path.splitext(old_filename)

    new_filename = f"{filename}_encrypted{extension}"
    enc_path = os.path.join(directory, new_filename).replace("\\", "/")

    with open(path, 'rb') as file:
        plaintext = file.read()

    ciphertext = encryptor.update(plaintext) + encryptor.finalize()

    with open(enc_path, 'wb') as file:
        file.write(salt + ciphertext)

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

        salt = content[:16]
        decryption_key = generate_key(password, salt, 32)
        cipher = Cipher(algorithms.ChaCha20(decryption_key, salt), mode=None, backend=default_backend())
        decryptor = cipher.decryptor()
        ciphertext = content[16:]

        plaintext = decryptor.update(ciphertext) + decryptor.finalize()

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


