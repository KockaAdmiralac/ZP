import logging
from Crypto.PublicKey import RSA, DSA
from Crypto.PublicKey.RSA import RsaKey
from Crypto.PublicKey.DSA import DsaKey
from lib.models import PrivateKeyRing
from lib import ElGamalKey, Key, KeyAlgorithms

log = logging.getLogger(__name__)

RSA_HEADERS = (b"-----BEGIN RSA PRIVATE KEY-----", b"-----END RSA PRIVATE KEY-----")
DSA_ELGAMAL_HEADERS = (b"-----BEGIN PRIVATE KEY-----", b"-----END PRIVATE KEY-----", \
                       b"-----BEGIN PRIVATE KEY-----", b"-----END PRIVATE KEY-----")


def _new_key_pair_from_algorithm(algorithm: KeyAlgorithms, bits: int, password: str) -> Key:
    if algorithm == KeyAlgorithms.RSA:
        rsa_key = RSA.generate(bits)
        pem_public_key = rsa_key.export_key()
        pem_private_key = rsa_key.export_key(passphrase=password)
        return pem_public_key, pem_private_key
    
    elif algorithm == KeyAlgorithms.DSAElGamal:
        dsa_key, elgamal_key = DSA.generate(bits), ElGamalKey(bits)
        pem_public_key = dsa_key.export_key() + b'\n' + elgamal_key.export_key()

        password_bytes = password.encode('utf-8')
        pem_private_key = dsa_key.export_key(passphrase=password) + b'\n' + \
                          elgamal_key.export_key(passphrase=password_bytes)
        return pem_public_key, pem_private_key
    
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
    pem_public_key, pem_private_key = _new_key_pair_from_algorithm(algorithm=algorithm, bits=size, password=password)
    key_id = _extract_key_id(public_key=pem_public_key, algorithm=algorithm)

    PrivateKeyRing.insert(keyID=key_id, name=name, publicKey=pem_public_key, enPrivateKey=pem_private_key, userID=email)


def delete_key_pair():
    pass