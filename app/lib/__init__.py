from enum import Enum
from typing import Tuple, Union
from Crypto.PublicKey import DSA, RSA
from .elgamal import ElGamalKey

Key = Union[RSA.RsaKey, Tuple[DSA.DsaKey, ElGamalKey]]
SigningKey = Union[RSA.RsaKey, DSA.DsaKey]
EncryptionKey = Union[RSA.RsaKey, ElGamalKey]

class KeyAlgorithms(Enum):
    RSA = 1
    DSAElGamal = 2

class Cipher(Enum):
    AES128 = 1
    TripleDES = 2
