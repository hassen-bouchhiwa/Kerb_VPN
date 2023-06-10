from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
import os
import base64
import hashlib

def myhash(my_string):
    hash_object = hashlib.sha256()
    hash_object.update(my_string.encode())
    hashed_string = hash_object.hexdigest()
    return hashed_string

def encrypt_aes256(key_string, plaintext):
    # Generate a random initialization vector (IV)
    key = key_string.encode('utf-8')
    if len(key) != 32:
        key += b'\0' * (32 - len(key))

    iv = os.urandom(16)
    
    # Create a Cipher object with AES-256 in CBC mode
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    
    # Create a Padder object for padding the plaintext
    padder = padding.PKCS7(128).padder()
    padded_plaintext = padder.update(plaintext.encode('utf-8')) + padder.finalize()
    
    # Encrypt the padded plaintext with the Cipher object
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded_plaintext) + encryptor.finalize()
    
    # Return the IV and ciphertext as bytes
    return iv + ciphertext

def decrypt_aes256(key_string, ciphertext):
    # Split the ciphertext into the IV and encrypted data
    key = key_string.encode('utf-8')
    if len(key) != 32:
        key += b'\0' * (32 - len(key))

    iv, ciphertext = ciphertext[:16], ciphertext[16:]
    
    # Create a Cipher object with AES-256 in CBC mode
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    
    # Decrypt the ciphertext with the Cipher object
    decryptor = cipher.decryptor()
    padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    
    # Remove padding from the plaintext
    unpadder = padding.PKCS7(128).unpadder()
    plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()
    
    # Return the plaintext as a string
    return plaintext.decode('utf-8')
    













