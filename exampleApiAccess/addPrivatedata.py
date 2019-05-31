import urllib.request
import json
import time
import pprint
import accountParameters as acc
from nacl.encoding import Base64Encoder
import nacl.secret
import nacl.utils
import nacl.pwhash
import nacl.hash
import base64

ping_url = "http://cs302.kiwi.land/api/add_privatedata"
header = acc.create_header()
keys = acc.get_keys()
#  This turns the key into hex then string. As it needs to be serializable to send.
hex_private_key = keys["signing_key"].encode(encoder=nacl.encoding.HexEncoder).decode()

# To convert this string back to key, use:
# signing_key = nacl.signing.SigningKey(str.encode(hex_private_key), encoder=nacl.encoding.HexEncoder)

private_data_plain_text = {
    'prikeys': hex_private_key,
    'blocked_pubkeys': "",
    'blocked_usernames': "",
    'blocked_message_signatures': "",
    'blocked_words': "",
    'favourite_message_signatures': "",
    'friends_usernames': ""
}

private_data_plain_text_string = json.dumps(private_data_plain_text)
private_data_plain_text_bytes = bytes(private_data_plain_text_string, "utf-8")
loginserver_record = acc.get_server_record()
current_time = str(time.time())



############################# Generate symetric key for private data ########################
second_password = "SecondSecretPassword"  # This is entered by the user at login time.
kdf = nacl.pwhash.argon2i.kdf  # Key derivation function used to generate symmetric key.

key_password = second_password.encode("utf-8")
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

# Create a random nonce as this is required.
nonce = nacl.utils.random(nacl.secret.SecretBox.NONCE_SIZE)

# Encrypt the private data (bytes) using the secret box and random nonce.
# This encrypted message holds both the cipher text and nonce.
encrypted_message = secret_box.encrypt(private_data_plain_text_bytes, nonce)

# Encode the encrypted message object into base64 bytes.
# This is to streamline the process of signing the message as it can now be easily converted to a string then to bytes.
base64_bytes = base64.b64encode(encrypted_message)
# Convert the base64 bytes to string to be added to the payload and added to the signature.
base64_string = base64_bytes.decode('utf-8')

signature_hex_str = acc.sign_message(base64_string + loginserver_record + current_time)

payload = {
    "privatedata": base64_string,
    "loginserver_record": loginserver_record,
    "client_saved_at": current_time,
    "signature": signature_hex_str
}
pprint.pprint(payload)
byte_payload = bytes(json.dumps(payload), "utf-8")
# box = nacl.secret.SecretBox(symmetric_key)
# encrypted_box = box.encrypt(byte_payload)
# print(encrypted_box)
req = urllib.request.Request(url=ping_url, data=byte_payload, headers=header)
try:
    JSON_object = acc.query_server(req)
    pprint.pprint(JSON_object)
except urllib.error.HTTPError as error:
    print(error.read())
