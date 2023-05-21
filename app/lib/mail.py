from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA
from lib import ElGamalKey, EncryptionKey
from typing import Union

def asymmetric_encrypt(key: EncryptionKey, plaintext: bytes) -> Union[bytes, tuple]:
    if isinstance(key, RSA.RsaKey):
        return PKCS1_OAEP.new(key).encrypt(plaintext)
    else:
        return key.encrypt(plaintext)

def asymmetric_decrypt(key: EncryptionKey, ciphertext: Union[bytes, tuple]) -> bytes:
    if isinstance(key, RSA.RsaKey) and isinstance(ciphertext, bytes):
        return PKCS1_OAEP.new(key).decrypt(ciphertext)
    elif isinstance(key, ElGamalKey) and isinstance(ciphertext, tuple):
        return key.decrypt(ciphertext)
    raise ValueError('Unsupported key/ciphertext combination')
