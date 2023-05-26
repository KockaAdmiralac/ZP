from __future__ import annotations
from os import urandom
from typing import Optional, Tuple
from Crypto.IO import PEM, PKCS8
from Crypto.Math.Numbers import Integer
from Crypto.Math.Primality import generate_probable_safe_prime, generate_probable_prime
from Crypto.Util.asn1 import DerInteger, DerSequence
from Crypto.Util.number import bytes_to_long, long_to_bytes
from Crypto.Util.py3compat import tobytes, tostr

# Adapted from pycryptodome's ElGamal key class, while re-adding support for
# ElGamal encryption from pycrypto and defining our own PEM export
# procedure (based on DSA export to PEM from pycryptodome).
class ElGamalKey(object):
    def __init__(self, bits=1024, fast=True, params: Optional[Tuple[int, int, int]]=None):
        if params is not None:
            p, g, x = params
            self.p = Integer(p)
            self.g = Integer(g)
            self.x = Integer(x)
            self.y = pow(self.g, self.x, self.p)
            return

        randfunc = generate_probable_prime if fast else generate_probable_safe_prime
        # Generate a safe prime p
        # See Algorithm 4.86 in Handbook of Applied Cryptography
        self.p: Integer = randfunc(exact_bits=bits)

        # Generate generator g
        while 1:
            self.g: Integer = pow(Integer.random_range(min_inclusive=2, max_exclusive=self.p), 2, self.p)
            # We must avoid g=2 because of Bleichenbacher's attack described
            # in "Generating ElGamal signatures without knowning the secret key",
            # 1996
            if self.g in (1, 2):
                continue

            # Discard g if it divides p-1 because of the attack described
            # in Note 11.67 (iii) in HAC
            if (self.p - 1) % self.g == 0:
                continue

            # g^{-1} must not divide p-1 because of Khadir's attack
            # described in "Conditions of the generator for forging ElGamal
            # signature", 2011
            ginv = self.g.inverse(self.p)
            if (self.p - 1) % ginv == 0:
                continue

            # Found
            break

        # Generate private key x
        self.x: Integer = Integer.random_range(min_inclusive=2, max_exclusive=self.p - 1)

        # Generate public key y
        self.y: Integer = pow(self.g, self.x, self.p)

    def encrypt(self, plaintext: bytes) -> tuple:
        M = bytes_to_long(plaintext)
        K = bytes_to_long(urandom(len(plaintext)))
        a = pow(self.g, K, self.p)
        b = (pow(self.y, K, self.p) * M) % self.p
        return (int(a), int(b))

    def decrypt(self, ciphertext: tuple) -> bytes:
        r = Integer.random_range(min_inclusive=2, max_exclusive=self.p-1)
        a_blind = (pow(self.g, r, self.p) * ciphertext[0]) % self.p
        ax = pow(a_blind, self.x, self.p)
        plaintext_blind = (ax.inverse(self.p) * ciphertext[1] ) % self.p
        plaintext = (plaintext_blind * pow(self.y, r, self.p)) % self.p
        return long_to_bytes(int(plaintext))

    def export_key(self, passphrase: Optional[bytes] = None) -> bytes:
        private_key = DerInteger(self.x).encode()
        params = DerSequence([self.p, self.g])
        binary_key = PKCS8.wrap(private_key, oid, passphrase, key_params=params)
        key_type = 'ENCRYPTED PRIVATE KEY' if passphrase else 'PRIVATE KEY'
        pem_str = PEM.encode(binary_key, key_type, passphrase)
        return tobytes(pem_str)

    @staticmethod
    def import_key(contents: bytes, passphrase: Optional[bytes] = None) -> ElGamalKey:
        (der, marker, enc_flag) = PEM.decode(tostr(contents), passphrase)
        if enc_flag:
            passphrase = None
        decoded_oid, private_key_bytes, params_bytes = PKCS8.unwrap(der, passphrase)
        if decoded_oid != oid:
            raise ValueError('No PKCS#8 encoded ElGamal key')
        if params_bytes is None:
            raise ValueError('Invalid ElGamal key encoding')
        x = DerInteger().decode(private_key_bytes).value
        p, g = list(DerSequence().decode(params_bytes))
        return ElGamalKey(params=(p, g, x))

# OID for an RSA key because there isn't one for ElGamal
oid = '1.2.840.113549.1.1.1'
