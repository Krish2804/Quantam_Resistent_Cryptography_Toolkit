from algorithms import kyber, dilithium, sphincs
from utils import keygen, encrypt, decrypt, sign_verify

def test_kyber():
    print("\nTesting Kyber...")
    pk, sk = kyber.generate_keypair()
    ct, ss_enc = kyber.encrypt(pk)
    ss_dec = kyber.decrypt(sk, ct)
    assert ss_enc == ss_dec, "Kyber shared secrets do not match"
    print("✔ Kyber passed.")

def test_dilithium():
    print("\nTesting Dilithium...")
    pk, sk = dilithium.generate_keypair()
    message = b"IM3 test message"
    signature = dilithium.sign(sk, message)
    valid = dilithium.verify(pk, message, signature)
    assert valid, "Dilithium signature invalid"
    print("✔ Dilithium passed.")

def test_sphincs():
    print("\nTesting SPHINCS+...")
    pk, sk = sphincs.generate_keypair()
    message = b"IM3 test message"
    signature = sphincs.sign(sk, message)
    valid = sphincs.verify(pk, message, signature)
    assert valid, "SPHINCS+ signature invalid"
    print("✔ SPHINCS+ passed.")

if __name__ == "__main__":
    test_kyber()
    test_dilithium()
    test_sphincs()
