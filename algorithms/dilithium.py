import oqs

def dilithium_keygen():
    with oqs.Signature("Dilithium2") as sig:
        public_key = sig.generate_keypair()
        private_key = sig.export_secret_key()
    return public_key, private_key

def dilithium_sign(private_key, message):
    with oqs.Signature("Dilithium2", secret_key=private_key) as sig:
        return sig.sign(message.encode())

def dilithium_verify(message, signature, public_key):
    if isinstance(message, str):
        message = message.encode()
    return oqs.Signature("Dilithium2").verify(message, signature, public_key)
