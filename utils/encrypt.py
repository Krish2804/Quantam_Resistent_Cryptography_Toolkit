from algorithms.kyber import kyber_encrypt
from algorithms.frodo import frodo_encrypt

def encrypt_message(message, public_key, algorithm="kyber"):
    if algorithm == "kyber":
        return kyber_encrypt(public_key, message)
    elif algorithm == "frodo":
        return frodo_encrypt(public_key, message)
    else:
        raise ValueError(f"Unsupported encryption algorithm: {algorithm}")
