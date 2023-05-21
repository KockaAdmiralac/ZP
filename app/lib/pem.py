from Crypto.PublicKey import RSA, DSA
from . import Key
from .elgamal import ElGamalKey

def export_key(filename: str, key: Key):
    with open(filename, 'wb') as pem_file:
        if isinstance(key, RSA.RsaKey):
            pem_file.write(key.export_key())
        else:
            dsa_key, elgamal_key = key
            pem_file.write(dsa_key.export_key())
            pem_file.write(b'\n')
            pem_file.write(elgamal_key.export_key())

def import_key(filename: str) -> Key:
    with open(filename, 'rb') as pem_file:
        contents = pem_file.read()
        if contents.startswith(b'-----BEGIN RSA PRIVATE KEY'):
            return RSA.import_key(contents)
        else:
            dsa_part, elgamal_part = contents.split(b'---\n---')
            dsa_contents = dsa_part + b'---'
            elgamal_contents = b'---' + elgamal_part
            return (DSA.import_key(dsa_contents), ElGamalKey.import_key(elgamal_contents))
