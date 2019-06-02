import pprint
import urllib.request
import json
import ApisAndHelpers.requests as request_helpers

new_api_key_url = "http://cs302.kiwi.land/api/load_new_apikey"
header = request_helpers.create_header("jacob", "jall229_205023320")

api_key_object = request_helpers.query_server(url=new_api_key_url, header=header)

pprint.pprint(api_key_object)