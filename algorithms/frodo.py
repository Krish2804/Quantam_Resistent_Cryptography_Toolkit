import oqs

def frodo_keygen():
    with oqs.KeyEncapsulation("FrodoKEM-640-AES") as kem:
        public_key = kem.generate_keypair()
        private_key = kem.export_secret_key()
    return public_key, private_key

def frodo_encrypt(public_key, message=None):
    with oqs.KeyEncapsulation("FrodoKEM-640-AES") as kem:
        ciphertext, shared_secret = kem.encap_secret(public_key)
    return ciphertext

def frodo_decrypt(private_key, ciphertext):
    with oqs.KeyEncapsulation("FrodoKEM-640-AES", secret_key=private_key) as kem:
        shared_secret = kem.decap_secret(ciphertext)
    return shared_secret
