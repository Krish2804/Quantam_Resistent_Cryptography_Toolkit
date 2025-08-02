from algorithms.dilithium import dilithium_sign, dilithium_verify
from algorithms.sphincs import sphincs_sign, sphincs_verify

def sign_with_dilithium(message, private_key):
    return dilithium_sign(private_key, message)

def verify_dilithium_signature(message, signature, public_key):
    return dilithium_verify(message, signature, public_key)

def sign_with_sphincs(message, private_key):
    return sphincs_sign(message, private_key)

def verify_sphincs_signature(message, signature, public_key):
    return sphincs_verify(message, signature, public_key)
