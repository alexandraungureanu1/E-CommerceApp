import base64
import hashlib
import json

from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Signature import PKCS1_v1_5
from Crypto.Hash import SHA256


def generate_keys(key_length):
    key_pair = RSA.generate(key_length)
    public_key = key_pair.publickey().exportKey().decode()
    private_key = key_pair.exportKey().decode()
    return public_key, private_key


def encrypt(message, key):
    encryptor = PKCS1_OAEP.new(RSA.importKey(key.encode()))
    encrypted = encryptor.encrypt(message.encode())
    return base64.b64encode(encrypted).decode()


def decrypt(message, key):
    decryptor = PKCS1_OAEP.new(RSA.importKey(key.encode()))
    decrypted = decryptor.decrypt(base64.b64decode(message.encode()))
    return decrypted.decode()


def sign(message, key):
    key = RSA.importKey(key.encode())
    hash_obj = SHA256.new(message.encode())
    signer = PKCS1_v1_5.new(key)
    signature = signer.sign(hash_obj)
    return base64.b64encode(signature).decode()


def verify_signature(message, signature, key):
    key = RSA.importKey(key.encode())
    hash_obj = SHA256.new(message.encode())
    verifier = PKCS1_v1_5.new(key)
    if verifier.verify(hash_obj, base64.b64decode(signature.encode())):
        return True
    else:
        return False


def trans_dict_to_hash(dictionary):
    dictionary = json.dumps(dictionary).encode()
    hash_obj = hashlib.sha256(dictionary)
    hash_value = hash_obj.hexdigest()
    return hash_value
