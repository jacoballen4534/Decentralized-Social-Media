import pprint
import urllib.request
import urllib.error
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


def query_server(request):
    """Takes a url, optional header and data. Will make a url request to then process.
    If the query was sucessfull, it will convert the response to json format and return it."""
    try:
        response = urllib.request.urlopen(request, timeout=5)
        data = response.read()  # read the received bytes
        encoding = response.info().get_content_charset('utf-8')  # load encoding if possible (default to utf-8)
        response.close()

        json_object = json.loads(data.decode(encoding))
        return json_object
    except urllib.error.HTTPError as error:
        print(error.read())
        logging.debug("Url: " + str(request) + " gave error :" + error.reason)
        # raise  # Log the error then pass it up.
        return {'response': 'error'}


def create_header(username, password):
    credentials = ('%s:%s' % (username, password))
    b64_credentials = base64.b64encode(credentials.encode('ascii'))
    headers = {
        'Authorization': 'Basic %s' % b64_credentials.decode('ascii'),
        'Content-Type': 'application/json; charset=utf-8',
    }
    return headers
