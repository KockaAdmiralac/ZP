from base64 import b64decode, b64encode
from datetime import datetime
from io import BufferedReader, BytesIO
from Crypto.Cipher import AES, DES3, PKCS1_OAEP
from Crypto.Cipher._mode_eax import EaxMode
from Crypto.Hash import SHA1
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Signature import DSS, pss
from lib import Cipher, ElGamalKey, EncryptionKey, Key, SigningKey
from lib.models import PrivateKeyRing, PublicKeyRing
from typing import Callable, Dict, Optional, Tuple, Union
from zlib import compress, decompress

MessageHeaders = Dict[str, Optional[str]]

class Message:
    def __init__(self, message: str, compress: bool, base64: bool, public_key: Optional[Key], public_key_id: Optional[str], cipher: Optional[Cipher], private_key: Optional[Key], private_key_id: Optional[str], verification: Optional[bool] = True):
        self.message: str = message
        self.compress: bool = compress
        self.base64: bool = base64
        self.encryption_key: Optional[EncryptionKey] = None
        self.cipher: Optional[Cipher] = cipher
        self.signing_key: Optional[SigningKey] = None
        self.encryption_key_id: Optional[str] = public_key_id
        self.signing_key_id: Optional[str] = private_key_id
        if public_key is not None:
            if isinstance(public_key, RSA.RsaKey):
                self.encryption_key = public_key
            else:
                self.encryption_key = public_key[1]
        if private_key is not None:
            if isinstance(private_key, RSA.RsaKey):
                self.signing_key = private_key
            else:
                self.signing_key = private_key[0]
        self.verification: Optional[bool] = verification

    @staticmethod
    def format_headers(headers: MessageHeaders) -> bytes:
        headers_bytes = b''
        for header_name, header_value in headers.items():
            if header_value is None:
                continue
            headers_bytes += header_name.encode('utf-8') + b': ' + header_value.encode('utf-8') + b'\n'
        headers_bytes += b'----\n'
        return headers_bytes

    @staticmethod
    def read_headers(file: Union[BufferedReader, BytesIO]) -> Dict[str, str]:
        headers = {}
        while True:
            line = file.readline().strip()
            if line == b'':
                raise ValueError('No header terminator found when reading message.')
            if line.startswith(b'----'):
                break
            header = line.split(b': ')
            if len(header) != 2:
                raise ValueError(f'Malformed message header: {header}')
            header_name, header_value = header
            headers[header_name.decode('utf-8')] = header_value.decode('utf-8')
        return headers

    def digest(self, message: bytes) -> str:
        if self.signing_key is None:
            raise ValueError('Signing not enabled for message.')
        message_hash = SHA1.new(message)
        if isinstance(self.signing_key, RSA.RsaKey):
            message_signer = pss.new(self.signing_key)
        else:
            message_signer = DSS.new(self.signing_key, 'fips-186-3')
        return message_signer.sign(message_hash).hex()

    @staticmethod
    def verify(key: SigningKey, message: bytes, digest: bytes) -> bool:
        message_hash = SHA1.new(message)
        try:
            if isinstance(key, RSA.RsaKey):
                pss.new(key).verify(message_hash, digest)
            else:
                DSS.new(key, 'fips-186-3').verify(message_hash, digest)
            return True
        except ValueError:
            return False

    def generate_session_key(self) -> bytes:
        if self.cipher is None:
            raise ValueError('Encryption not enabled for message.')
        elif self.cipher == Cipher.AES128:
            return get_random_bytes(16)
        else:
            while True:
                try:
                    return DES3.adjust_key_parity(get_random_bytes(24))
                except ValueError:
                    pass

    def symmetric_encrypt(self, key: bytes, message: bytes) -> Tuple[bytes, bytes]:
        if self.cipher is None:
            raise ValueError('Encryption not enabled for message.')
        elif self.cipher == Cipher.AES128:
            cipher = AES.new(key, AES.MODE_EAX)
        else:
            cipher = DES3.new(key, DES3.MODE_EAX)
            if not isinstance(cipher, EaxMode):
                raise ValueError('This should never happen.')
        return cipher.nonce, cipher.encrypt(message)

    @staticmethod
    def symmetric_decrypt(cipher: Cipher, key: bytes, nonce: bytes, ciphertext: bytes) -> bytes:
        if cipher == Cipher.AES128:
            decipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
        else:
            decipher = DES3.new(key, DES3.MODE_EAX, nonce=nonce)
        return decipher.decrypt(ciphertext)

    def asymmetric_encrypt(self, plaintext: bytes) -> bytes:
        if self.encryption_key is None:
            raise ValueError('Encryption not enabled for message.')
        elif isinstance(self.encryption_key, RSA.RsaKey):
            return PKCS1_OAEP.new(self.encryption_key).encrypt(plaintext)
        else:
            return self.encryption_key.encrypt(plaintext)

    @staticmethod
    def asymmetric_decrypt(key: EncryptionKey, ciphertext: bytes) -> bytes:
        if key is None:
            raise ValueError('Decryption not enabled for message.')
        elif isinstance(key, RSA.RsaKey):
            return PKCS1_OAEP.new(key).decrypt(ciphertext)
        elif isinstance(key, ElGamalKey):
            return key.decrypt(ciphertext)
        raise ValueError('Unsupported key/ciphertext combination')

    def write(self, filename: str):
        with open(filename, 'wb') as file:
            headers: MessageHeaders = {
                'Encryption-Key-Id': self.encryption_key_id,
                'Encryption-Algorithm': 'AES128' if self.cipher == Cipher.AES128 else '3DES',
                'Signed': str(self.signing_key is not None),
                'Compressed': str(self.compress),
                'Radix-64': str(self.base64)
            }
            file.write(self.format_headers(headers))
            raw_message = self.format_headers({
                'Timestamp': datetime.now().isoformat()
            }) + self.message.encode('utf-8')
            # Signing
            if self.signing_key_id is not None and self.signing_key is not None:
                signed_message = self.format_headers({
                    'Digest': self.digest(raw_message),
                    'Signing-Key-Id': self.signing_key_id
                }) + raw_message
            else:
                signed_message = raw_message
            # Compression
            if self.compress:
                compressed_message = compress(signed_message)
            else:
                compressed_message = signed_message
            # Encryption
            if self.encryption_key_id is not None and self.encryption_key is not None and self.cipher is not None:
                session_key = self.generate_session_key()
                encryption_param, encrypted_contents = self.symmetric_encrypt(session_key, compressed_message)
                encrypted_session_key = self.asymmetric_encrypt(session_key)
                encrypted_message = encrypted_session_key + encryption_param + encrypted_contents
            else:
                encrypted_message = compressed_message
            # Base64 encoding
            if self.base64:
                encoded_message = b64encode(encrypted_message)
            else:
                encoded_message = encrypted_message
            file.write(encoded_message)

    @staticmethod
    def read(filename: str, read_passphrase: Callable[[], str]) -> 'Message':
        with open(filename, 'rb') as file:
            headers = Message.read_headers(file)
            encryption_key_id = headers.get('Encryption-Key-Id')
            encryption_algorithm = headers.get('Encryption-Algorithm')
            cipher = Cipher.AES128 if encryption_algorithm == 'AES128' else (Cipher.TripleDES if encryption_algorithm == '3DES' else None)
            is_signed = headers.get('Signed') == 'True'
            is_compressed = headers.get('Compressed') == 'True'
            is_base64 = headers.get('Radix-64') == 'True'
            # default values for Message constructor
            verification = True
            signing_key = None
            signing_key_id = None
            encryption_key = None
            # Base64 decoding
            if is_base64:
                decoded_message = b64decode(file.read())
            else:
                decoded_message = file.read()
            if encryption_key_id is not None and encryption_algorithm is not None and cipher is not None:
                encryption_key_data = PrivateKeyRing.get_by_key_id(encryption_key_id)
                if encryption_key_data is None:
                    raise ValueError('No private key with given ID found.')
                # enter passphrase
                passphrase = read_passphrase()
                if passphrase is None:
                    raise ValueError('Decryption requested but no private key passphrase given.')
                encryption_key_pair = encryption_key_data.get_private_key_obj(passphrase)
                if isinstance(encryption_key_pair, RSA.RsaKey):
                    encryption_key = encryption_key_pair
                    session_key_size_bytes = encryption_key.size_in_bytes()
                else:
                    encryption_key = encryption_key_pair[1]
                    session_key_size_bytes = encryption_key.size_in_bits() // 4
                encrypted_session_key = decoded_message[:session_key_size_bytes]
                encryption_param = decoded_message[session_key_size_bytes:session_key_size_bytes + 16]
                encrypted_contents = decoded_message[session_key_size_bytes + 16:]
                session_key = Message.asymmetric_decrypt(encryption_key, encrypted_session_key)
                decrypted_message = Message.symmetric_decrypt(cipher, session_key, encryption_param, encrypted_contents)
            else:
                decrypted_message = decoded_message
            # Decompression
            if is_compressed:
                decompressed_message = decompress(decrypted_message)
            else:
                decompressed_message = decrypted_message
            # Signature verification
            if is_signed:
                message_with_signature_headers = BytesIO(decompressed_message)
                signature_headers = Message.read_headers(message_with_signature_headers)
                digest_hex = signature_headers['Digest']
                signing_key_id = signature_headers['Signing-Key-Id']
                signing_key_data = PublicKeyRing.get_by_key_id(signing_key_id)
                raw_message = message_with_signature_headers.read()
                if signing_key_data is not None:
                    signing_key_pair = signing_key_data.get_public_key_obj()
                    if isinstance(signing_key_pair, RSA.RsaKey):
                        signing_key = signing_key_pair
                    else:
                        signing_key = signing_key_pair[0]
                    verification = Message.verify(signing_key, raw_message, bytes.fromhex(digest_hex))
            else:
                raw_message = decompressed_message
            # Timestamp separation
            message_with_raw_headers = BytesIO(raw_message)
            raw_headers = Message.read_headers(message_with_raw_headers)
            timestamp = raw_headers['Timestamp']
            message = message_with_raw_headers.read().decode('utf-8')
            print(timestamp, message, verification)
            return_message = Message(message=message, compress=is_compressed, base64=is_base64, public_key=encryption_key, public_key_id=encryption_key_id, \
                                 cipher=cipher, private_key=signing_key, private_key_id=signing_key_id, verification=verification) 
            return return_message
