import pprint
import urllib.request
import accountParameters as acc


def login_server_pub_key():
    url = "http://cs302.kiwi.land/api/loginserver_pubkey"
    req = urllib.request.Request(url)
    JSON_object = acc.query_server(req)
    return JSON_object


pprint.pprint(login_server_pub_key())
