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
import socket


def query_server(request, headers=False):
    """Takes a url, optional header and data. Will make a url request to then process.
    the headers argument specifies if the readers of the request should be returned.
    If the query was successful, it will convert the response to json format and return it."""
    try:
        response = urllib.request.urlopen(request, timeout=5)
        data = response.read()  # read the received bytes
        response_headers = dict(response.info())
        encoding = response.info().get_content_charset('utf-8')  # load encoding if possible (default to utf-8)
        response.close()

        json_object = json.loads(data.decode(encoding))
        json_object['response'] = 'ok'  # to ensure there is a response for all requests
        if headers:  # Only return the headers if they are asked for
            return json_object, response_headers
        return json_object
    except urllib.error.HTTPError as error:
        print(error.read())
        logging.debug("Url: " + str(request) + " gave error :" + error.reason)
        return {'response': 'error'}
    except urllib.error.URLError as e:
        print(e.reason)
        return {'response': 'error'}
    except TypeError:
        return {'response': 'error'}
    except socket.timeout:
        return {'response': 'error'}


def create_basic_header(username, password):
    credentials = ('%s:%s' % (username, password))
    b64_credentials = base64.b64encode(credentials.encode('ascii'))
    headers = {
        'Authorization': 'Basic %s' % b64_credentials.decode('ascii'),
        'Content-Type': 'application/json; charset=utf-8',
    }
    return headers


def create_api_header(x_username, api_key, x_signature=None):
    headers = {
        'X-username': x_username,
        'X-apikey': api_key,
        'Content-Type': 'application/json; charset=utf-8',
    }
    if x_signature is not None:
        headers['X-signature'] = x_signature
    return headers
