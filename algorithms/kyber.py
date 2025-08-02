import oqs

def kyber_keygen():
    with oqs.KeyEncapsulation('Kyber512') as kem:
        public_key = kem.generate_keypair()
        private_key = kem.export_secret_key()
    return public_key, private_key

def kyber_encrypt(public_key, message=None):
    with oqs.KeyEncapsulation("Kyber512") as kem:
        ciphertext, shared_secret = kem.encap_secret(public_key)
    return ciphertext

def kyber_decrypt(private_key, ciphertext):
    with oqs.KeyEncapsulation("Kyber512", secret_key=private_key) as kem:
        shared_secret = kem.decap_secret(ciphertext)
    return shared_secret
