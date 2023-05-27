from typing import Optional
from Crypto.PublicKey import RSA, DSA
from . import Key
from .elgamal import ElGamalKey

def export_key_to_bytes(key: Key, passphrase: Optional[str] = None) -> bytes:
    if isinstance(key, RSA.RsaKey):
        return key.export_key(passphrase=passphrase)
    else:
        dsa_key, elgamal_key = key
        passphrase_bytes = None if passphrase is None else passphrase.encode('utf-8')
        return dsa_key.export_key(passphrase=passphrase) + b'\n' + elgamal_key.export_key(passphrase_bytes)

def export_key(filename: str, key: Key, passphrase: Optional[str] = None):
    with open(filename, 'wb') as pem_file:
        pem_file.write(export_key_to_bytes(key, passphrase))

def import_key_from_bytes(contents: bytes, passphrase: Optional[str] = None) -> Key:
    two_keys = contents.split(b'---\n---')
    if len(two_keys) == 1:
        return RSA.import_key(contents, passphrase)
    else:
        dsa_part, elgamal_part = two_keys
        dsa_contents = dsa_part + b'---'
        elgamal_contents = b'---' + elgamal_part
        passphrase_bytes = None if passphrase is None else passphrase.encode('utf-8')
        return (DSA.import_key(dsa_contents, passphrase), ElGamalKey.import_key(elgamal_contents, passphrase_bytes))

def import_key(filename: str, passphrase: Optional[str] = None) -> Key:
    with open(filename, 'rb') as pem_file:
        return import_key_from_bytes(pem_file.read(), passphrase)
