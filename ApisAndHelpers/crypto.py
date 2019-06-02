import pprint
import urllib.request
import json
import base64

import nacl.encoding
import nacl.signing
import nacl.utils
import nacl.secret
import nacl.pwhash
import nacl.hash
import nacl.exceptions
import time
import logging


def sign_message(message_string, private_key):
    """Signs the input message with the provided private key. Returns the hex string signature"""
    signature_bytes = bytes(message_string, encoding='utf-8')
    signed = private_key.sign(signature_bytes, encoder=nacl.encoding.HexEncoder)
    signature_hex_str = signed.signature.decode('utf-8')
    return signature_hex_str


def get_keys(private_key_hex_string):
    """"Takes the private key hex string as input. Will recreate the private key and corresponding public key
    along with their hex string form"""
    private_key = nacl.signing.SigningKey(private_key_hex_string, encoder=nacl.encoding.HexEncoder)
    pubkey_hex = private_key.verify_key.encode(encoder=nacl.encoding.HexEncoder)
    pubkey_hex_str = pubkey_hex.decode('utf-8')
    keys = {
        "private_key": private_key,
        "public_key": pubkey_hex,
        "private_key_hex_string": private_key_hex_string,
        "public_key_hex_string": pubkey_hex_str,
    }
    return keys
