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


# def get_keys(signing_key_hex_string):
#     signing_key = nacl.signing.SigningKey(signing_key_hex_string, encoder=nacl.encoding.HexEncoder)
#     pubkey_hex = signing_key.verify_key.encode(encoder=nacl.encoding.HexEncoder)
#     pubkey_hex_str = pubkey_hex.decode('utf-8')
#     keys = {"signing_key": signing_key, "pubkey_hex_str": pubkey_hex_str}
#     return keys


def create_new_key_pair():
    signing_key = nacl.signing.SigningKey.generate()
    pubkey_hex = signing_key.verify_key.encode(encoder=nacl.encoding.HexEncoder)
    pubkey_hex_str = pubkey_hex.decode('utf-8')
    keys = {"signing_key": signing_key, "pubkey_hex_str": pubkey_hex_str}
    print("New keys created")
    return keys


# def create_header(username, password):
#     credentials = ('%s:%s' % (username, password))
#     b64_credentials = base64.b64encode(credentials.encode('ascii'))
#     headers = {
#         'Authorization': 'Basic %s' % b64_credentials.decode('ascii'),
#         'Content-Type': 'application/json; charset=utf-8',
#     }
#     return headers


def get_server_record(username, password):
    server_record_url = "http://cs302.kiwi.land/api/get_loginserver_record"
    header = create_header(username, password)
    request = urllib.request.Request(url=server_record_url, headers=header)
    JSON_object = query_server(request)
    loginserver_record = JSON_object['loginserver_record']
    return loginserver_record


# def sign_message(message, private_key):
#     signature_bytes = bytes(message, encoding='utf-8')
#     signed = private_key.sign(signature_bytes, encoder=nacl.encoding.HexEncoder)
#     signature_hex_str = signed.signature.decode('utf-8')
#     return signature_hex_str


# def query_server(request):
#     response = urllib.request.urlopen(request)
#
#     data = response.read()  # read the received bytes
#     encoding1 = response.info().get_content_charset('utf-8')  # load encoding if possible (default to utf-8)
#     response.close()
#
#     JSON_object = json.loads(data.decode(encoding1))
#     return JSON_object


def report(username, password, keys):
    url = "http://cs302.kiwi.land/api/report"
    header = create_header(username=username, password=password)

    payload = {
        "connection_location": "2",
        "connection_address": "122.58.162.166:5000",
        "incoming_pubkey": keys["pubkey_hex_str"],
        "status": 'online',  # other options are ‘away’, ‘busy’ or ‘offline’
    }
    byte_payload = bytes(json.dumps(payload), "utf-8")

    req = urllib.request.Request(url=url, data=byte_payload, headers=header)
    JSON_object = query_server(req)
    if JSON_object['response'] == 'ok':
        return True
    else:
        return False


def create_secret_box(second_password):
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
    return secret_box


def encrypt_private_data(secret_box, private_data):
    # Private_data is plaintext bytes
    # Create a random nonce as this is required.
    nonce = nacl.utils.random(nacl.secret.SecretBox.NONCE_SIZE)
    encrypted_message = secret_box.encrypt(private_data, nonce)

    # Encode the encrypted message object into base64 bytes.
    # This streamlines the process of signing the message as it can now be easily converted to a string then to bytes.
    base64_bytes = base64.b64encode(encrypted_message)
    # Convert the base64 bytes to string to be added to the payload and added to the signature.
    base64_string = base64_bytes.decode('utf-8')
    return base64_string


def decrypt_private_data(private_data_base64_string, secret_box):
    """Takes the base64 encoded private data string (private_data field from private_data_object) and secret box."""
    # Extract the encrypted private data from 'get_privatedata'.
    # convert the string back to base64 bytes.
    received_base64_bytes = private_data_base64_string.encode('utf-8')
    # Decode the base64 bytes to get back the encrypted message object.
    received_encrypted_message = base64.b64decode(received_base64_bytes)

    # Decrypt the encrypted message object with the receiving secret box.
    unencrypted_bytes = secret_box.decrypt(received_encrypted_message)
    # Convert the bytes back to a string, then to a dictionary.
    unencrypted_string = unencrypted_bytes.decode('utf-8')
    private_data_dict = json.loads(unencrypted_string)
    print("This is the private data that was retrieved:")
    pprint.pprint(private_data_dict)
    return private_data_dict


def get_private_key_from_private_data(private_data_dict):
    if 'prikeys' in private_data_dict:
        try:
            signing_key = nacl.signing.SigningKey(str.encode(private_data_dict['prikeys']),
                                                  encoder=nacl.encoding.HexEncoder)
            print("successfully retrieved private key.")
            return signing_key
        except KeyError:
            print("It doesnt look like the stored private key is valid. Consider making a new one.")

    # If there was no prikeys or invalid prikey, raise error
    raise KeyError


def add_pub_key(keys, username, password):
    add_pup_key_url = "http://cs302.kiwi.land/api/add_pubkey"

    header = create_header(username, password)
    signature_hex_str = sign_message(keys["pubkey_hex_str"] + username, keys['signing_key'])

    payload = {
        "pubkey": keys["pubkey_hex_str"],
        "username": username,
        "signature": signature_hex_str
    }

    byte_payload = bytes(json.dumps(payload), "utf-8")

    req = urllib.request.Request(url=add_pup_key_url, data=byte_payload, headers=header)
    JSON_object = query_server(req)
    if JSON_object['response'] == 'ok':
        print("Added a new pubkey")
        pprint.pprint(JSON_object)
        return True
    else:
        return False


def add_private_data(keys, username, password, second_password):
    try:
        # ping_url = "http://cs302.kiwi.land/api/add_privatedata"
        # private_key_hex_string = keys["signing_key"].encode(encoder=nacl.encoding.HexEncoder).decode('utf-8')
        ping_url = "http://cs302.kiwi.land/api/add_privatedata"
        header = create_header(username, password)
        #  This turns the key into hex then string. As it needs to be serializable to send.
        hex_private_key = keys["signing_key"].encode(encoder=nacl.encoding.HexEncoder).decode()

        # To convert this string back to key, use:
        # signing_key = nacl.signing.SigningKey(str.encode(hex_private_key), encoder=nacl.encoding.HexEncoder)

        private_data_plain_text = {
            'prikeys': [hex_private_key, ""],
            'blocked_pubkeys': ["", ""],
            'blocked_usernames': ["", ""],
            'blocked_message_signatures': ["", ""],
            'blocked_words': ["", ""],
            'favourite_message_signatures': ["", ""],
            'friends_usernames': ["", ""]
        }

        private_data_plain_text_string = json.dumps(private_data_plain_text)
        private_data_plain_text_bytes = bytes(private_data_plain_text_string, "utf-8")
        loginserver_record = get_server_record(username, password)
        current_time = str(time.time())

        ############################# Generate symetric key for private data ########################
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
        symmetric_key = kdf(nacl.secret.SecretBox.KEY_SIZE, key_password, salt=salt, opslimit=ops, memlimit=mem,
                            encoder=nacl.encoding.HexEncoder)

        # Create the secret box, from the symmetric key, to encrypt messages with.
        secret_box = nacl.secret.SecretBox(symmetric_key, encoder=nacl.encoding.HexEncoder)

        # Create a random nonce as this is required.
        nonce = nacl.utils.random(nacl.secret.SecretBox.NONCE_SIZE)

        # Encrypt the private data (bytes) using the secret box and random nonce.
        # This encrypted message holds both the cipher text and nonce.
        encrypted_message = secret_box.encrypt(private_data_plain_text_bytes, nonce)

        # Encode the encrypted message object into base64 bytes.
        # This is to streamline the process of signing the message as it can now be easily converted to a string then to
        # bytes.
        base64_bytes = base64.b64encode(encrypted_message)
        # Convert the base64 bytes to string to be added to the payload and added to the signature.
        base64_string = base64_bytes.decode('utf-8')

        signature_hex_str = sign_message(base64_string + loginserver_record + current_time, keys['signing_key'])

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
            JSON_object = query_server(req)
            if JSON_object['response'] == 'ok':
                print("\n\nSecessfully added encrypted private data")
                pprint.pprint(JSON_object)
                return True
            else:
                return False
        except urllib.error.HTTPError as error:
            print(error.read())
    except (TypeError, nacl.exceptions.CryptoError):
        print("Could not load private data dictonary")
    return False

    # header = create_header(username, password)
    #
    # private_data_plain_text_string = json.dumps(private_data_dict)
    # private_data_plain_text_bytes = bytes(private_data_plain_text_string, "utf-8")
    # loginserver_record = get_server_record(username, password)
    # current_time = str(time.time())
    #
    # # Create the secret box to encrypt with
    # secret_box = create_secret_box(second_password)
    # encrypted_message_base64_string = encrypt_private_data(secret_box, private_data_plain_text_bytes)
    #
    # signature_hex_str = sign_message(encrypted_message_base64_string + loginserver_record + current_time,
    #                                  private_key=keys['signing_key'])
    #
    # # create signature and payload
    # payload = {
    #     "privatedata": encrypted_message_base64_string,
    #     "loginserver_record": loginserver_record,
    #     "client_saved_at": current_time,
    #     "signature": signature_hex_str
    # }
    # byte_payload = bytes(json.dumps(payload), "utf-8")
    #
    # req = urllib.request.Request(url=ping_url, data=byte_payload, headers=header)
    # try:
    #     JSON_object = query_server(req)
    #     pprint.pprint(JSON_object)
    #     return JSON_object
    # except urllib.error.HTTPError as error:
    #     print(error.read())
    #     return False


def ping_central_server(username=None, password=None, keys=None):
    ping_url = "http://cs302.kiwi.land/api/ping"
    if username is None or password is None:
        print("Checking if the server is online")
        try:
            check_online_req = urllib.request.Request(url=ping_url)
            json_object = query_server(check_online_req)
            if json_object['response'] == 'ok':
                print("Server is online and reachable.")
                return True
            else:
                print("Sorry, it appears the server is not reachable at this time")
                return False
        except urllib.error.HTTPError as error:
            print(error.read())
            return False
    elif username is not None and password is not None and keys is None:  # This means check httpbasic
        print("Checking if the provided username and password is valid")
        header = create_header(username, password)
        check_credentials_req = urllib.request.Request(url=ping_url, headers=header)
        json_object = query_server(check_credentials_req)
        if json_object['authentication'] == 'basic':
            print("These credentials are valid. Processing to get private data. (private key)")
            return True
        else:
            print("It doesnt look like those are valid credentials")
            print("Try again")
            return False
    elif username is not None and password is not None and keys is not None:
        print("Checking if the provided key is valid")
        header = create_header(username, password)
        signature_hex_str = sign_message(keys["pubkey_hex_str"], private_key=keys['signing_key'])
        payload = {
            "pubkey": keys["pubkey_hex_str"],
            "signature": signature_hex_str
        }
        byte_payload = bytes(json.dumps(payload), "utf-8")
        verify_signature_req = urllib.request.Request(url=ping_url, data=byte_payload, headers=header)
        verify_signature_object = query_server(verify_signature_req)
        if verify_signature_object['signature'] == 'ok':
            return True
        else:
            raise False


def get_private_data(username, password, second_password, allow_overwrite):
    if len(second_password) == 0:
        print("Please enter an Encryption Password")
        return False
    # get_private_data_url = "http://cs302.kiwi.land/api/get_privatedata"
    # header = create_header(username, password)
    #
    # try:
    #     get_private_data_req = urllib.request.Request(url=get_private_data_url, headers=header)
    #     private_data_object = query_server(get_private_data_req)
    #     received_base64_string = private_data_object['privatedata']
    #     secret_box = create_secret_box(second_password)
    #     private_data_dict = decrypt_private_data(received_base64_string, secret_box)
    #     keys = get_keys(private_data_dict['prikeys'])
    #     return ping_central_server(username, password, keys)
    #
    # except (KeyError, urllib.error.HTTPError, nacl.exceptions.CryptoError):
    #     return False

    url = "http://cs302.kiwi.land/api/get_privatedata"

    header = create_header(username, password)
    private_data_dict = None

    req = urllib.request.Request(url=url, headers=header)
    private_data_object = query_server(req)

    if private_data_object['response'] == 'ok':
        print("This private data was retrieved:")
        pprint.pprint(private_data_object)

    else:  # error
        print("There was an error retrieving private data")
        return False

    # Can only get to here if there is an object. Check private data now.
    if 'privatedata' not in private_data_object:
        print("There is no private data")
        return False

    try:
        received_base64_string = private_data_object['privatedata']

        ############################# Generate symetric key for decrypting private data ########################
        # Follow the same steps for creating the salt, symmetric key and secret box as used when encrypting the private data
        kdf = nacl.pwhash.argon2i.kdf  # Key derivation function used to generate symmetric key.
        key_password = second_password.encode("utf-8")
        long_salt = nacl.pwhash.argon2i.SALTBYTES * key_password
        salt = long_salt[0:nacl.pwhash.argon2i.SALTBYTES]  # Slice the first 16 bytes to get the required length.
        ops = nacl.pwhash.argon2i.OPSLIMIT_SENSITIVE  # Recommended value of 8, given in the docs.
        mem = nacl.pwhash.argon2i.MEMLIMIT_SENSITIVE  # Recommended value of 536870912, given in the docs.

        receiving_symmetric_key = kdf(nacl.secret.SecretBox.KEY_SIZE, key_password, salt=salt,
                                      opslimit=ops, memlimit=mem, encoder=nacl.encoding.HexEncoder)
        print("Reconstructed Symmetric key")
        # Create secret box to encrypt with.
        receiving_secret_box = nacl.secret.SecretBox(receiving_symmetric_key, encoder=nacl.encoding.HexEncoder)
        print("Reconstructed Secret Box")
        # Extract the encrypted private data from 'get_privatedata'.
        # convert the string back to base64 bytes.
        received_base64_bytes = received_base64_string.encode('utf-8')
        # Decode the base64 bytes to get back the encrypted message object.
        received_encrypted_message = base64.b64decode(received_base64_bytes)
        print("decoded encrypted message to: " + str(received_encrypted_message))
        # Decrypt the encrypted message object with the receiving secret box.
        unencrypted_bytes = receiving_secret_box.decrypt(received_encrypted_message)
        # Convert the bytes back to a string, then to a dictionary.
        unencrypted_string = unencrypted_bytes.decode('utf-8')
        private_data_dict = json.loads(unencrypted_string)

        print("This is the private data that was retrieved:")
        pprint.pprint(private_data_dict)
    except (TypeError, nacl.exceptions.CryptoError):
        print("Could not load private data dictonary")
        return False

    if private_data_dict is not None and'prikeys' in private_data_dict:
        try:
            signing_key = nacl.signing.SigningKey(str.encode(private_data_dict['prikeys'][0]), encoder=nacl.encoding.HexEncoder)
            print("successfully retrieved private key.")
            signing_key_hex_string = signing_key.encode(encoder=nacl.encoding.HexEncoder).decode('utf-8')

            keys = get_keys(signing_key_hex_string)
            if not report(username, password, keys):
                return False
            if ping_central_server(username, password, keys):
                return True
            else:
                return False
        except KeyError as error:
            print(error)
            print("It doesnt look like the stored private key is valid. Consider making a new one.")
    else:
        print("There is no private key stored. Consider adding one.")

    return False



def overwrite_private_data(username, password, second_password):
    print("\n\n\nAdding new key and overwriting private data.")
    print("Generating a new public private key pair and registering it with the server")
    """Make new private key -> public key -> add via add_pupkey -> add private key to privatedata"""
    keys = create_new_key_pair()
    if add_pub_key(keys, username, password):
        print("Successfully added public key to server")
    else:
        return False
    if not report(username, password, keys):
        return False
    add_private_data_result = add_private_data(keys, username, password, second_password)
    if add_private_data_result:
        print("Sucessfully added private data")
        return True
    else:
        print("An error occurred when adding your private data.")
        return False




















