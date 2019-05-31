import urllib.request
import json
import base64
import pprint
import nacl.encoding
import nacl.signing
import nacl.utils
import accountParameters as acc
import nacl.secret
import nacl.pwhash
import nacl.hash

url = "http://cs302.kiwi.land/api/get_privatedata"

header = acc.create_header()
keys = acc.get_keys()

req = urllib.request.Request(url=url, headers=header)

private_data_object = acc.query_server(req)

if private_data_object['response'] == 'ok':
    print("This private data was retrieved:")
    pprint.pprint(private_data_object)

elif private_data_object['response'] == 'no privatedata available':
    print("There doesnt appear to be any private data on the server.")
    """Make new private key -> public key -> add via add_pupkey ->
     add private key to privatedata"""
    exit(0) # return

else:  # error
    print("There was an error")
    exit(1) # return

# Can only get to here if there is an object. Check private data now.
if 'privatedata' not in private_data_object:
    print("There is no private data")
    exit()

try:
    received_base64_string = private_data_object['privatedata']

    ############################# Generate symetric key for decrypting private data ########################
    # Follow the same steps for creating the salt, symmetric key and secret box as used when encrypting the private data
    second_password = "SecondSecretPassword"  # This is entered by the user at login time.
    kdf = nacl.pwhash.argon2i.kdf  # Key derivation function used to generate symmetric key.
    key_password = second_password.encode("utf-8")
    long_salt = nacl.pwhash.argon2i.SALTBYTES * key_password
    salt = long_salt[0:nacl.pwhash.argon2i.SALTBYTES]  # Slice the first 16 bytes to get the required length.
    ops = nacl.pwhash.argon2i.OPSLIMIT_SENSITIVE  # Recommended value of 8, given in the docs.
    mem = nacl.pwhash.argon2i.MEMLIMIT_SENSITIVE  # Recommended value of 536870912, given in the docs.

    receiving_symmetric_key = kdf(nacl.secret.SecretBox.KEY_SIZE, key_password, salt=salt,
                                  opslimit=ops, memlimit=mem, encoder=nacl.encoding.HexEncoder)

    # Create secret box to encrypt with.
    receiving_secret_box = nacl.secret.SecretBox(receiving_symmetric_key, encoder=nacl.encoding.HexEncoder)

    # Extract the encrypted private data from 'get_privatedata'.
    # convert the string back to base64 bytes.
    received_base64_bytes = received_base64_string.encode('utf-8')
    # Decode the base64 bytes to get back the encrypted message object.
    received_encrypted_message = base64.b64decode(received_base64_bytes)

    # Decrypt the encrypted message object with the receiving secret box.
    unencrypted_bytes = receiving_secret_box.decrypt(received_encrypted_message)
    # Convert the bytes back to a string, then to a dictionary.
    unencrypted_string = unencrypted_bytes.decode('utf-8')
    private_data_dict = json.loads(unencrypted_string)

    print("This is the private data that was retrieved:")
    pprint.pprint(private_data_dict)
except TypeError:
    print("Could not load private data dictonary")
    exit(1)

if 'prikeys' in private_data_dict:
    try:
        signing_key = nacl.signing.SigningKey(str.encode(private_data_dict['prikeys']), encoder=nacl.encoding.HexEncoder)
        print("successfully retrieved private key.")
    except KeyError as error:
        print(error)
        print("It doesnt look like the stored private key is valid. Consider making a new one.")
else:
    print("There is no private key stored. Consider adding one.")