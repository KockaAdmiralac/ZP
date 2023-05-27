from typing import List
from Crypto.PublicKey import RSA, DSA
from lib.models import PrivateKeyRing
from lib.pem import export_key_to_bytes
from lib import ElGamalKey, Key, KeyAlgorithms

def _new_key_pair_from_algorithm(algorithm: KeyAlgorithms, bits: int, passphrase: str):
    if algorithm == KeyAlgorithms.RSA:
        private_key = RSA.generate(bits)
        public_key = private_key.public_key()
    elif algorithm == KeyAlgorithms.DSAElGamal:
        private_key = DSA.generate(bits), ElGamalKey(bits)
        dsa_key, elgamal_key = private_key
        public_key = dsa_key.public_key(), elgamal_key.public_key()

    pem_public_key = export_key_to_bytes(public_key).decode('utf-8')
    pem_private_key = export_key_to_bytes(private_key, passphrase).decode('utf-8')
    return private_key, pem_public_key, pem_private_key

# For a V3 key, the eight-octet Key ID consists of the low 64 bits of
# the public modulus of the RSA key.
# https://www.rfc-editor.org/rfc/rfc4880#section-12.2
# https://github.com/mitchellrj/python-pgp/blob/62a3da/pgp/transferrable_keys.py#L328-L338
def _extract_key_id(key: Key):
    if isinstance(key, RSA.RsaKey):
        return hex(key.n)[-16:]
    else:
        return hex(key[0].p)[-16:]


def create_key_pair(name: str, email: str, algorithm: KeyAlgorithms, bits: int, passphrase: str):
    key, pem_public_key, pem_private_key = _new_key_pair_from_algorithm(algorithm, bits, passphrase)
    key_id = _extract_key_id(key)

    private_key_ring = PrivateKeyRing(key_id=key_id, name=name, public_key=pem_public_key, \
                                        private_key=pem_private_key, user_id=email)
    PrivateKeyRing.insert(private_key_ring)


def find_key_by_key_id(key_id: str) -> PrivateKeyRing:
    return PrivateKeyRing.get_by_key_id(key_id)

def delete_key_pair(key_id):
    PrivateKeyRing.delete_by_key_id(key_id)

def get_all_keys() -> List[PrivateKeyRing]:
    return PrivateKeyRing.get_all()
