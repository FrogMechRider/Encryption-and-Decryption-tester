import os
import hashlib
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa, padding as rsa_padding
from cryptography.hazmat.primitives import hashes, serialization

# Symmetric Encryption (AES)
def generate_key():
    return os.urandom(32) #256-bit key

def encrypt_aes(key, plaintext):
    iv = os.urandom(16)
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(plaintext.encode()) + padder.finalize()

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()
    return iv + ciphertext

def decrypt_aes(key, ciphertext):
    iv = ciphertext[:16]
    actual_ciphertext = ciphertext[16:]

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    padded_data = decryptor.update(actual_ciphertext) + decryptor.finalize()

    unpadder = padding.PKCS7(128).unpadder()
    plaintext = unpadder.update(padded_data) + unpadder.finalize()
    return plaintext.decode()

# Asymmetric Encryption (RSA)
def generate_rsa_keys():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    public_key = private_key.public_key()
    return private_key, public_key

def encrypt_rsa(public_key, plaintext):
    ciphertext = public_key.encrypt(
        plaintext.encode(),
        rsa_padding.OAEP(
            mgf=rsa_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return ciphertext

def decrypt_rsa(private_key, ciphertext):
    plaintext = private_key.decrypt(
        ciphertext,
        rsa_padding.OAEP(
            mgf=rsa_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return plaintext.decode()

# Hashing (SHA-256)
def hash_sha256(data):
    sha256 = hashlib.sha256()
    sha256.update(data.encode())
    return sha256.hexdigest()

# File Encryption and Decryption
def encrypt_file(file_path, key):
    with open(file_path, 'rb') as file:
        plaintext = file.read()
    ciphertext = encrypt_aes(key, plaintext.decode())
    with open(file_path + ".enc", 'wb') as file:
        file.write(ciphertext)

def decrypt_file(encrypted_file_path, key):
    with open(encrypted_file_path, 'rb') as file:
        ciphertext = file.read()
    plaintext = decrypt_aes(key, ciphertext)
    original_file_path = encrypted_file_path.replace(".enc","")
    with open(original_file_path, 'wb') as file:
        file.write(plaintext.encode())

#CLI for users
def main():
    while True:
        print("\nData Encryption and Decryption Tool")
        print("1. Symmetric Encryption (AES)")
        print("2. Asymmetric Encryption (RSA)")
        print("3. Hashing (SHA-256)")
        print("4. File Encryption")
        print("5. File Decryption")
        print("6. Exit")
        choice = input("Choose an option: ")

        if choice == '1':
            key = generate_key()
            plaintext = input("Enter plaintext: ")
            ciphertext = encrypt_aes(key, plaintext)
            print(f"Ciphertext: {ciphertext}")
            decrypted_text = decrypt_aes(key, ciphertext)
            print(f"Decrypted text: {decrypted_text}")

        elif choice == '2':
            private_key, public_key = generate_rsa_keys()
            plaintext = input("Enter the plaintext: ")
            ciphertext = encrypt_rsa(public_key, plaintext)
            print(f"Ciphertext: {ciphertext}")
            decrypted_text = decrypt_rsa(private_key, ciphertext)
            print(f"Decrypted text: {decrypted_text}")

        elif choice == '3':
            data = input("Enter data to hash: ")
            hashed_data = hash_sha256(data)
            print(f"Hashed data: {hashed_data}")

        elif choice == '4':
            file_path = input("Enter the file path to enccrypt: ")
            key = generate_key()
            encrypt_file(file_path, key)
            print(f"File encrypted successfully . Key: {key}")

        elif choice == '5':
            file_pth = input("Enter the encrypted file path: ")
            key = input("Enter the key: ")
            key = bytes(key, 'utf-8') # Convert string key to bytes
            decrypt_file(file_path, key)
            print("File decrypted successfully.")
        
        elif choice == '6':
            break

        else:
            print("Invalid choice. Please choose another number")

if __name__ == "__main__":
    main()


