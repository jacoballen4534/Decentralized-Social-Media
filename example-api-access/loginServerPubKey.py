import pprint
import urllib.request
import apiHelpers as acc

url = "http://cs302.kiwi.land/api/loginserver_pubkey"

req = urllib.request.Request(url)
JSON_object = acc.query_server(req)


pprint.pprint(JSON_object)