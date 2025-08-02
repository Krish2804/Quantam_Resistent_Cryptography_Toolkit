# encrypt_file.py
import oqs
import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

def encrypt_file(input_file_path, output_file_path, public_key):
    with oqs.KeyEncapsulation("Kyber512") as kem:
        ciphertext, shared_secret = kem.encap_secret(public_key)  # ✅ Correct usage

    aes_key = shared_secret[:32]
    nonce = os.urandom(16)

    with open(input_file_path, 'rb') as f:
        data = f.read()

    cipher = Cipher(algorithms.AES(aes_key), modes.CTR(nonce), backend=default_backend())
    encryptor = cipher.encryptor()
    encrypted_data = encryptor.update(data) + encryptor.finalize()

    with open(output_file_path, 'wb') as f:
        f.write(ciphertext)
        f.write(nonce)
        f.write(encrypted_data)

    print("✅ File encrypted successfully.")
