import pprint
import urllib.request
import cherrypy
import apiHelpers as acc
import json

startHTML = "<html><head><title>CS302 example</title><link rel='stylesheet' href='/static/example.css' /></head><body>"

class MainApp(object):
    # CherryPy Configuration
    _cp_config = {'tools.encode.on': True, 'tools.encode.encoding': 'utf-8', 'tools.sessions.on': 'True', }

    # If they try somewhere we don't know, catch it here and send them to the right place.
    @cherrypy.expose
    def default(self, *args, **kwargs):
        """The default page, given when we don't recognise where the request is for."""
        Page = startHTML + "I don't know where you're trying to go, so have a 404 Error."
        cherrypy.response.status = 404
        return Page

    # PAGES (which return HTML that can be viewed in browser)
    @cherrypy.expose
    def index(self):
        Page = startHTML + "Welcome! This is my login page!<br/>"

        try:
            Page += "Hello " + cherrypy.session['username'] + "!<br/>"
            Page += "Here is some bonus text because you've logged in! <br/>" \
                    "You are now<font color='green'> visible</font>  on the login server.<br/> " \
                    "<a href='/signout'>Sign out</a>"
        except KeyError:  # There is no username

            Page += "Click here to <a href='login'>login</a>."
        return Page

    @cherrypy.expose
    def login(self, bad_attempt=0):
        Page = startHTML
        if bad_attempt != 0:
            Page += "<font color='red'>Invalid username/password!</font>"

        Page += '<form action="/signin" method="post" enctype="multipart/form-data">'
        Page += 'Username: <input type="text" name="username"/><br/>'
        Page += 'Password: <input type="text" name="password"/>'
        Page += '<input type="submit" value="Login"/></form>'
        return Page

    @cherrypy.expose
    def sum(self, a=0, b=0):  # All inputs are strings by default
        output = int(a) + int(b)
        return str(output)

    # LOGGING IN AND OUT
    @cherrypy.expose
    def signin(self, username=None, password=None):
        """Check their name and password and send them either to the main page, or back to the main login screen."""
        success = authoriseUserLogin(username, password)
        if success:
            cherrypy.session['username'] = username
            raise cherrypy.HTTPRedirect('/')
        else:
            raise cherrypy.HTTPRedirect('/login?bad_attempt=1')

    @cherrypy.expose
    def signout(self):
        """Logs the current user out, expires their session"""
        username = cherrypy.session.get('username')
        if username is None:
            pass
        else:
            cherrypy.lib.sessions.expire()
        raise cherrypy.HTTPRedirect('/')


###
### Functions only after here
###

def authoriseUserLogin(username, password):
    # Deal with no values being passed in. (user manually calls "/"
    # if 'username' in cherrypy.session
    print("Checking if the server is online")
    ping_url = "http://cs302.kiwi.land/api/ping"
    try:
        check_online_req = urllib.request.Request(url=ping_url)
        json_object = acc.query_server(check_online_req)
        if json_object['response'] == 'ok':
            print("Server is online and reachable.")
        else:
            print("Sorry, it appears the server is not reachable at this time")
            exit()
    except urllib.error.HTTPError as error:
        print(error.read())
        exit()

    print("Checking if the provided username and password is valid")
    header = acc.create_header(username, password)
    check_credentials_req = urllib.request.Request(url=ping_url, headers=header)
    json_object = acc.query_server(check_credentials_req)
    if json_object['authentication'] == 'basic':
        print("These credentials are valid. Processing to get private data. (private key)")
    else:
        print("It doesnt look like those are valid credentials")
        print("Try again")
        return False

    get_private_data_url = "http://cs302.kiwi.land/api/get_privatedata"
    get_private_data_req = urllib.request.Request(url=get_private_data_url, headers=header)
    private_data_object = acc.query_server(get_private_data_req)
    if private_data_object['response'] == 'ok':
        """Precede to getting the key -> set hex key, or skip that step and set private key"""
        print("Your private data was retrieved, however, jall229 key will be used for now")
	# Check pubkey is valid with check_pubkey
        hex_key = b'bae8e8311801aabe5d4eb4c85f3ba53a54c7a2fffbc561e59a6ff53765dfe138'
    elif private_data_object['response'] == 'no privatedata available':
        print("There doesnt appear to be any private data on the server.")
        print("Generating a new private public key pair and registering it to the server")
        """Make new private key -> public key -> add via add_pupkey -> add private key to privatedata -> Can replace hex key step"""

        print("Until this is implemented, using jall229 pre saved key.")
        hex_key = b'bae8e8311801aabe5d4eb4c85f3ba53a54c7a2fffbc561e59a6ff53765dfe138'
    else:  # error
        print("There was an error")
        return False

    keys = acc.get_keys(hex_key)
    signature_hex_str = acc.sign_message(keys["pubkey_hex_str"], hex_key=hex_key)
    payload = {
        "pubkey": keys["pubkey_hex_str"],
        "signature": signature_hex_str
    }
    byte_payload = bytes(json.dumps(payload), "utf-8")
    verify_signature_req = urllib.request.Request(url=ping_url, data=byte_payload, headers=header)
    verify_signature_object = acc.query_server(verify_signature_req)

    if verify_signature_object['response'] == 'ok':
        print("This is a verified signature. Nice!")
    else:
        print("You do not have a valid signature, please try logging in again")  # may need to generate new key here
        return False

    print("Attempting to report to the server.")
    report_object = acc.report(username=username, password=password, hex_key=hex_key)
    if report_object['response'] == 'ok':
        print("Congratulations, you reported to the server.")
        print("You are now online")
        return True
    else:
        print("Could not report to the server, please try again later.")
        return False
