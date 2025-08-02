from algorithms.kyber import kyber_decrypt
from algorithms.frodo import frodo_decrypt

def decrypt_message(ciphertext, private_key, algorithm="kyber"):
    if algorithm == "kyber":
        return kyber_decrypt(private_key, ciphertext)
    elif algorithm == "frodo":
        return frodo_decrypt(private_key, ciphertext)
    else:
        raise ValueError(f"Unsupported decryption algorithm: {algorithm}")
