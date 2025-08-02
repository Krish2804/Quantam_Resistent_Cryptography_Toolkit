from algorithms.kyber import kyber_keygen
from algorithms.dilithium import dilithium_keygen
from algorithms.sphincs import sphincs_keygen
from algorithms.frodo import frodo_keygen

def generate_all_keys():
    keys = {
        "kyber": kyber_keygen(),
        "dilithium": dilithium_keygen(),
        "sphincs": sphincs_keygen(),
        "frodo": frodo_keygen(),
    }
    return keys
