from Crypto.PublicKey import RSA, DSA
from Crypto.PublicKey.RSA import RsaKey
from lib.models import PrivateKeyRing
from lib import ElGamalKey, Key, KeyAlgorithms


def new_key_from_algorithm(algorithm: KeyAlgorithms, bits: int) -> Key:
    if algorithm == KeyAlgorithms.RSA:
        return RSA.generate(bits)
    elif algorithm == KeyAlgorithms.DSAElGamal:
        return DSA.generate(bits), ElGamalKey(bits)

def createKeyPair(name: str, email: str, algorithm: KeyAlgorithms, size: int, password: str):

    newKeyPair : Key = new_key_from_algorithm(algorithm=algorithm, bits=size)
    # convert to pem
    pemPublicKey = newKeyPair.export_key()
    keyID = pemPublicKey[-8:]
    pemPrivateKey = newKeyPair.export_key(passphrase=password)
    
    PrivateKeyRing.insert(keyID=keyID, name=name, publicKey=pemPublicKey, enPrivateKey=pemPrivateKey, userID=email)


def deleteKeyPair():
    pass