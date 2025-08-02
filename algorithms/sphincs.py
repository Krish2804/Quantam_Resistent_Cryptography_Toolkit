import oqs

def sphincs_keygen():
    with oqs.Signature("SPHINCS+-SHA2-128f-simple") as sig:
        public_key = sig.generate_keypair()
        private_key = sig.export_secret_key()
    return public_key, private_key

def sphincs_sign(message, secret_key):
    # Initialize Signature object with secret_key at construction
    with oqs.Signature("SPHINCS+-SHA2-128f-simple", secret_key=secret_key) as sig:
        return sig.sign(message.encode())

def sphincs_verify(message, signature, public_key):
    if isinstance(message, str):
        message = message.encode()
    return oqs.Signature("SPHINCS+-SHA2-128f-simple").verify(message, signature, public_key)
