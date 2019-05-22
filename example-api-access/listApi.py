import pprint
import urllib.request
import json
import apiHelpers as acc

url = "http://cs302.kiwi.land/api/list_apis"

#create request and open it into a response object
req = urllib.request.Request(url)
JSON_object = acc.query_server(req)


pprint.pprint(JSON_object)