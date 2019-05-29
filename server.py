import pprint
import urllib.request
import cherrypy
import exampleApiAccess.apiHelpers as acc
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
        Page += 'Password: <input type="password" name="password"/><br/>'
        Page += 'Encryption Password: <input type="password" name="second_password"/><br/>'
        Page += 'Allow private data overwrite: <input type="checkbox" name="allow_overwrite"/><br/>'
        Page += '<input type="submit" value="Login"/></form>'
        Page += '<br/><p> Note. If you tick allow private data overwrite, this will overwride your current private' \
                'data, and create a new public private key pair for you. Your existing keys will still work.</br>' \
                'This will occur in any of the following circumstances:</br>' \
                '<ul>' \
                '<li>No private data at all.</li>' \
                '<li>Empty string private data.</li>' \
                '<li>Unable to decrypt existing private data.</li>' \
                '<li>No private key in private data.</li>' \
                '<li>Invalid private key</li>' \
                '<li>Invalid Encryption Password</li>' \
                '</ul></br>' \
                'This is designed to encrypt your private data so you can test your decryption implementation</p>'
        return Page

    @cherrypy.expose
    def sum(self, a=0, b=0):  # All inputs are strings by default
        output = int(a) + int(b)
        return str(output)

    # LOGGING IN AND OUT
    @cherrypy.expose
    def signin(self, username=None, password=None, second_password = None, allow_overwrite=None):
        """Check their name and password and send them either to the main page, or back to the main login screen."""
        success = authorise_user_login(username, password, second_password, allow_overwrite)
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

def authorise_user_login(username, password, second_password, allow_overwrite):
    # _______________________________Check server is online __________________________________
    if not acc.ping_central_server():
        return False  # Need to return message to display
    # ____________________Check username pass with http basic________________________________
    if not acc.ping_central_server(username, password):
        return False
    # _________________________ Retrieve private data _______________________________________






    else:  # error
        print("There was an error")
        return False

    if 'privatedata' not in private_data_object:
        print("There is no private data")
        return False

    received_base64_string = private_data_object['privatedata']
    secret_box = acc.create_secret_box(second_password)
    private_data_dict = acc.decrypt_private_data(received_base64_string, secret_box=secret_box)

    # TODO: If there is no private data. Or there is private data but cant decode, or there is no private key on the private data. Make a new private key.
    try:
        private_key = acc.get_private_key_from_private_data(private_data_dict)
    except KeyError:
        print("There was either no private key, or it was invalid")
        return False
    # TODO: Add different retern options. Maybe dont need.

    keys = acc.get_keys(private_key)
    signature_hex_str = acc.sign_message(keys["pubkey_hex_str"], hex_key=hex_key)
    payload = {"pubkey": keys["pubkey_hex_str"], "signature": signature_hex_str}
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
