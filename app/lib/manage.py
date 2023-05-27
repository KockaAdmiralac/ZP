from Crypto.PublicKey import RSA, DSA
from Crypto.PublicKey.RSA import RsaKey
from Crypto.PublicKey.DSA import DsaKey
from lib.models import PrivateKeyRing
from lib import ElGamalKey, Key, KeyAlgorithms

RSA_HEADERS = (b"-----BEGIN RSA PRIVATE KEY-----", b"-----END RSA PRIVATE KEY-----")
DSA_ELGAMAL_HEADERS = (b"-----BEGIN PRIVATE KEY-----", b"-----END PRIVATE KEY-----", \
                       b"-----BEGIN PRIVATE KEY-----", b"-----END PRIVATE KEY-----")


def _new_key_pair_from_algorithm(algorithm: KeyAlgorithms, bits: int, password: str):
    if algorithm == KeyAlgorithms.RSA:
        rsa_key = RSA.generate(bits)
        pem_public_key = rsa_key.export_key()
        pem_private_key = rsa_key.export_key(passphrase=password)
        return rsa_key, pem_public_key, pem_private_key
    
    elif algorithm == KeyAlgorithms.DSAElGamal:
        key = DSA.generate(bits), ElGamalKey(bits)
        dsa_key, elgamal_key = key
        pem_public_key = dsa_key.export_key() + b'\n' + elgamal_key.export_key()

        password_bytes = password.encode('utf-8')
        pem_private_key = dsa_key.export_key(passphrase=password) + b'\n' + \
                          elgamal_key.export_key(passphrase=password_bytes)
        return key, pem_public_key, pem_private_key
    
    raise ValueError('Unsupported key algorithm')


def _extract_key_id(public_key, algorithm: KeyAlgorithms):
    headers = RSA_HEADERS if algorithm == KeyAlgorithms.RSA else DSA_ELGAMAL_HEADERS
    for header in headers:
        public_key = public_key.replace(header, b"")
    public_key = public_key.strip()

    public_key_hex = public_key.hex()
    key_id = public_key_hex[-16:]
    return key_id


def create_key_pair(name: str, email: str, algorithm: KeyAlgorithms, size: int, password: str):
    key, pem_public_key, pem_private_key = _new_key_pair_from_algorithm(algorithm=algorithm, bits=size, password=password)
    key_id = _extract_key_id(public_key=pem_public_key, algorithm=algorithm)

    private_key_ring = PrivateKeyRing(key_id=key_id, name=name, public_key=pem_public_key, \
                                        private_key=pem_private_key, user_id=email, key_obj=key)
    PrivateKeyRing.insert(private_key_ring)


def find_key_by_key_id(key_id: str) -> Key:
    private_key_ring = PrivateKeyRing.get_by_key_id(key_id)
    return private_key_ring.key_obj


def delete_key_pair(key_id):
    PrivateKeyRing.delete_by_key_id(key_id)

def get_all_keys():
    return PrivateKeyRing.get_all()
