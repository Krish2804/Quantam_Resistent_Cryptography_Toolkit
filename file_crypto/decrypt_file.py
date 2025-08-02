# decrypt_file.py
import oqs
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

def decrypt_file(input_file_path, output_file_path, secret_key):
    with oqs.KeyEncapsulation("Kyber512", secret_key=secret_key) as kem:
        kem_ciphertext_len = kem.details['length_ciphertext']
        nonce_len = 16  # AES-CTR nonce length

        with open(input_file_path, 'rb') as f:
            kem_ciphertext = f.read(kem_ciphertext_len)
            nonce = f.read(nonce_len)
            encrypted_data = f.read()

        shared_secret = kem.decap_secret(kem_ciphertext)
        aes_key = shared_secret[:32]

        cipher = Cipher(algorithms.AES(aes_key), modes.CTR(nonce), backend=default_backend())
        decryptor = cipher.decryptor()
        decrypted_data = decryptor.update(encrypted_data) + decryptor.finalize()

        with open(output_file_path, 'wb') as f:
            f.write(decrypted_data)

    print("✅ File decrypted successfully.")
