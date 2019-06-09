import pprint
import urllib.request
import json
import base64
import binascii
import nacl.secret
import nacl.encoding
import nacl.signing
import nacl.utils
import nacl.pwhash
import nacl.hash
import nacl.exceptions
import time


def sign_message(message_string, private_key):
    """Signs the input message with the provided private key. Returns the hex string signature"""
    signature_bytes = bytes(message_string, encoding='utf-8')
    signed = private_key.sign(signature_bytes, encoder=nacl.encoding.HexEncoder)
    signature_hex_str = signed.signature.decode('utf-8')
    return signature_hex_str


def get_keys(private_key_hex_string):
    """"Takes the private key hex string as input. Will try to recreate the private key and corresponding public key
    along with their hex string form. returns status of the recreation along with a dictionary with the keys.
    Failed key creation returns an empty dictionary."""
    try:
        private_key = nacl.signing.SigningKey(private_key_hex_string, encoder=nacl.encoding.HexEncoder)
        public_hex_bytes = private_key.verify_key.encode(encoder=nacl.encoding.HexEncoder)
        pubkey_hex_str = public_hex_bytes.decode('utf-8')
        keys = {
            "private_key": private_key,
            "public_hex_bytes": public_hex_bytes,
            "private_key_hex_string": private_key_hex_string,
            "public_key_hex_string": pubkey_hex_str,
        }
        return True, keys
    except (binascii.Error, nacl.exceptions.ValueError) as e:
        print(e)
        return False, {}


def create_secret_box(encryption_key):
    """Takes an encryption key that was used to encrypt a secretbox. Will attempt to recreate the same symmetric key,
    to then create the same  secret box."""
    try:
        kdf = nacl.pwhash.argon2i.kdf  # Key derivation function used to generate symmetric key.

        key_password = encryption_key.encode("utf-8")
        long_salt = nacl.pwhash.argon2i.SALTBYTES * key_password
        # Convert the second password to bytes and multiply by 16.
        # As the password is unknown length, repeating it 16 times will ensure it is at least 16 bytes.
        # As this is the required length of salt.

        salt = long_salt[0:nacl.pwhash.argon2i.SALTBYTES]  # Slice the first 16 bytes to get the required length.
        ops = nacl.pwhash.argon2i.OPSLIMIT_SENSITIVE  # Recommended value of 8, given in the docs.
        mem = nacl.pwhash.argon2i.MEMLIMIT_SENSITIVE  # Recommended value of 536870912, given in the docs.

        # Generate the symmetric key from the kdf.
        symmetric_key = kdf(nacl.secret.SecretBox.KEY_SIZE, key_password, salt=salt,
                            opslimit=ops, memlimit=mem, encoder=nacl.encoding.HexEncoder)

        # Create the secret box, from the symmetric key, to encrypt messages with.
        secret_box = nacl.secret.SecretBox(symmetric_key, encoder=nacl.encoding.HexEncoder)
        return True, secret_box
    except nacl.exceptions.ValueError:
        return False, None


def decrypt_private_data(private_data_base64_string, encryption_key):
    """Takes the base64 encoded private data string (private_data field from private_data_object).
     Will attempt to recreate the same secret box and decrypt using the provided encryption key."""
    try:
        status, secret_box = create_secret_box(encryption_key)
        if not status:
            return False, None
        # convert the string back to base64 bytes.
        private_data_base64_bytes = private_data_base64_string.encode('utf-8')
        # Decode the base64 bytes to get back the encrypted message object.
        received_encrypted_message_object = base64.b64decode(private_data_base64_bytes)

        # Decrypt the encrypted message object with the receiving secret box.
        unencrypted_bytes = secret_box.decrypt(received_encrypted_message_object)
        # Convert the bytes back to a string, then to a dictionary.
        unencrypted_string = unencrypted_bytes.decode('utf-8')
        private_data_dict = json.loads(unencrypted_string)
        print("This is the private data that was retrieved:")
        pprint.pprint(private_data_dict)
        return True, private_data_dict
    except nacl.exceptions.CryptoError:
        return False, None


def create_new_key_pair():
    try:
        private_key = nacl.signing.SigningKey.generate()
        private_key_hex_bytes = private_key.encode(encoder=nacl.encoding.HexEncoder)
        private_key_hex_string = private_key_hex_bytes.decode('utf-8')
        public_hex_bytes = private_key.verify_key.encode(encoder=nacl.encoding.HexEncoder)
        pubkey_hex_str = public_hex_bytes.decode('utf-8')
        keys = {
            "private_key": private_key,
            "public_hex_bytes": public_hex_bytes,
            "private_key_hex_string": private_key_hex_string,
            "public_key_hex_string": pubkey_hex_str,
        }
        print("New keys created")
        return True, keys
    except (binascii.Error, nacl.exceptions.ValueError) as e:
        print(e)
        return False, {}


def encrypt_private_data(private_data_plain_text_bytes, encryption_key):
    """Takes the private data to be encrypted, along with the encryption key to encrypt with. Will return the encrypted
    message object. (This contains both the cipher text and nonce."""
    status, secret_box = create_secret_box(encryption_key)
    if not status:
        return False, None
    nonce = nacl.utils.random(nacl.secret.SecretBox.NONCE_SIZE)
    encrypted_message = secret_box.encrypt(private_data_plain_text_bytes, nonce)
    return True, encrypted_message


def create_private_message(target_public_key_bytes, plain_text_message_string):
    """Take the target public key and encrypt a message against it."""
    import nacl.public
    try:
        verify_key = nacl.signing.VerifyKey(target_public_key_bytes, encoder=nacl.encoding.HexEncoder)
        target_public_key_curve = verify_key.to_curve25519_public_key()
        sealed_box = nacl.public.SealedBox(target_public_key_curve)
        encrypted_message = sealed_box.encrypt(str.encode(plain_text_message_string), encoder=nacl.encoding.HexEncoder)
        encrypted_message_string = encrypted_message.decode('utf-8')  # This is the message to send (string)
        return True, encrypted_message_string
    except Exception as e:
        print(e)
        return False, None








