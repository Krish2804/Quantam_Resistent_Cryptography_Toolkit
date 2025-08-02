from utils.keygen import generate_all_keys
from utils.encrypt import encrypt_message
from utils.decrypt import decrypt_message
from utils.sign_verify import (
    sign_with_dilithium,
    verify_dilithium_signature,
    sign_with_sphincs,
    verify_sphincs_signature
)
from file_crypto.encrypt_file import encrypt_file
from file_crypto.decrypt_file import decrypt_file

def main():
    message = "Quantum-secure message"
    input_file = "input.txt"
    encrypted_file = "encrypted_file.bin"
    decrypted_file = "decrypted_output.txt"

    # Key Generation
    keys = generate_all_keys()
    print("🔑 Keys generated:", {
        algo: ("<public>", "<private>")
        for algo in keys
    })

    # Split keys
    public_key_kyber, private_key_kyber = keys["kyber"]
    public_key_frodo, private_key_frodo = keys["frodo"]
    public_key_dil, private_key_dil = keys["dilithium"]
    public_key_sph, private_key_sph = keys["sphincs"]

    # --- Message Encryption/Decryption ---

    print("\n--- Kyber Encryption ---")
    ciphertext_kyber = encrypt_message(message, public_key_kyber, algorithm="kyber")
    print("Encrypted (Kyber):", ciphertext_kyber)
    decrypted_kyber = decrypt_message(ciphertext_kyber, private_key_kyber, algorithm="kyber")
    print("Decrypted (Kyber):", decrypted_kyber.hex())

    print("\n--- FrodoKEM Encryption ---")
    ciphertext_frodo = encrypt_message(message, public_key_frodo, algorithm="frodo")
    print("Encrypted (Frodo):", ciphertext_frodo)
    decrypted_frodo = decrypt_message(ciphertext_frodo, private_key_frodo, algorithm="frodo")
    print("Decrypted (Frodo):", decrypted_frodo.hex())

    # --- Digital Signatures ---

    print("\n--- Dilithium Signing ---")
    signature_dil = sign_with_dilithium(message, private_key_dil)
    print("Signature (Dilithium):", signature_dil)
    verified_dil = verify_dilithium_signature(message, signature_dil, public_key_dil)
    print("✅ Signature Verified (Dilithium):", verified_dil)

    print("\n--- SPHINCS+ Signing ---")
    signature_sph = sign_with_sphincs(message, private_key_sph)
    print("Signature (SPHINCS+):", signature_sph)
    verified_sph = verify_sphincs_signature(message, signature_sph, public_key_sph)
    print("✅ Signature Verified (SPHINCS+):", verified_sph)

    # --- File Encryption/Decryption ---

    print("\n--- File Encryption ---")
    encrypt_file(input_file, encrypted_file, public_key_kyber)
    print("✅ File encrypted successfully.")

    decrypt_file(encrypted_file, decrypted_file, private_key_kyber)
    print("✅ File decrypted successfully.")
    print("✅ File encryption and decryption complete.")

    # --- Show File Contents ---

    try:
        with open(input_file, 'rb') as f:
            original_data = f.read()
        print("\n📄 Original file content:", original_data.decode(errors='replace'))

        with open(encrypted_file, 'rb') as f:
            encrypted_data = f.read()
        print("🔒 Encrypted file content (hex):", encrypted_data.hex()[:100], "...")

        with open(decrypted_file, 'rb') as f:
            decrypted_data = f.read()
        print("🔓 Decrypted file content:", decrypted_data.decode(errors='replace'))
    except Exception as e:
        print("⚠️ Error reading file content:", e)

if __name__ == "__main__":
    main()
