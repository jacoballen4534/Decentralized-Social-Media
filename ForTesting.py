import ApisAndHelpers.crypto as crypto
import ApisAndHelpers.loginServerApis as loginServerApis
import ApisAndHelpers.requests as requests
import pprint


username = "jall229"
password = "jacoballen4534_205023320"
encryption_key = "Test"
private_key_hex_bytes = 'b19d2b5bedbef07365402439cb520797dc0690540973053d14b91c1fcba1835c'
status, keys = crypto.get_keys(private_key_hex_bytes)
api_key = loginServerApis.load_new_apikey(username, password)
x_signature = loginServerApis.ping(username="jall229", api_key=api_key)


def test_load_new_apikey():
    loginServerApis.load_new_apikey(username=username, api_key=new_api_key, password=password)


def test_report():
    loginServerApis.report(location="2", username=username, keys=keys, status="online", api_key=api_key, password=password)


def test_list_users():
    loginServerApis.list_users(username=username, api_key=api_key, password=password)


def test_add_pub_key():
    new_key_status, new_keys = crypto.create_new_key_pair()
    if new_key_status:
        print(loginServerApis.add_pub_key(new_keys, username, api_key=api_key, password=password))
    else:
        print("Failed to make key")


def test_get_private_data():
    data = loginServerApis.get_private_data(username, encryption_key, api_key=api_key, password=password)
    print("This is the data that was returned \n\n\n\n")
    pprint.pprint(data)


def test_list_apis():
    loginServerApis.list_apis()


def test_get_loginserver_record():
    loginServerApis.get_loginserver_record(username=username, password=password, api_key=api_key)


def test_check_pubkey():
    loginServerApis.check_pubkey(username=username,public_key_kex_string_to_check=
    "b9eba910b59549774d55d3ce49a7b4d46ab5e225cdcf2ac388cf356b5928b6bc", api_key=api_key, password=password)

test_get_private_data()