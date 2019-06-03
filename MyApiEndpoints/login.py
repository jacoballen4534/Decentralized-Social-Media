import pprint
import urllib.request
import cherrypy
import exampleApiAccess.apiHelpers as acc
import json
from jinja2 import Environment, FileSystemLoader
env = Environment(loader=FileSystemLoader('static'), autoescape=True)


class Login:
    @cherrypy.expose
    def default(self, *args, **kwargs):
        """The default page, given when we don't recognise where the request is for."""
        error_template = env.get_template('/html/404Error.html')
        cherrypy.response.status = 404
        return error_template.render()

    @cherrypy.expose
    def index(self, status_code=0, *args, **kwargs):
        """This is the login page where the user will enter their details to be authenticated with the login server"""

        login_template = env.get_template('/html/login.html')
        return login_template.render(server_down=(status_code == '1'), invalid_cridentials=(status_code == '2'),
                                     something_went_wring=(status_code == '3'))

    @cherrypy.expose
    def signin(self, username=None, password=None, key_type=None, key_value=None):
        """Check their name and password and send them either to the main page, or back to the main login screen."""
        status_code, api_key, x_signature, private_key = authorise_user_login(username, password, key_type, key_value)
        # api_key = "2"
        # if True:
        if status_code == 0:  # Successfully logged in and generated api key
            print("\n\nSuccessful login:\n\t\t\t\tUsername: " + str(username) + "\n\t\t\t\tPassword: " + str(password) +
                  "\n\t\t\t\tprivate_key: " + str(private_key) + "\n\t\t\t\tapi_key: " + str(api_key) +
                  "\n\t\t\t\tx-signature: " + str(x_signature) + "\n\n")
            cherrypy.session['username'] = username
            cherrypy.session['x_signature'] = x_signature
            cherrypy.session['api_key'] = api_key
            cherrypy.session['private_key'] = private_key
            raise cherrypy.HTTPRedirect('/')
        else:
            raise cherrypy.HTTPRedirect('/login?status_code=' + str(status_code))

    @cherrypy.expose
    def signout(self):
        """Logs the current user out, expires their session"""
        username = cherrypy.session.get('username')
        second_password = cherrypy.session.get('second_password')
        if username is not None or password is not None or second_password is not None:
            cherrypy.lib.sessions.expire()

        raise cherrypy.HTTPRedirect('/')


def authorise_user_login(username, password, key_type, key_value):
    """Takes in a username, password, and either encryption key or private key. Will validate that the server is online
    and reachable, the username and password are valid, if an encryption key is used, will retrieve and decrypt the
    private data of the user. If the private key is entered, will recreate the users private key from that. Then verify
    the resulting private key is valid. Returns a status code, the users api_key, the associated x-signature and
    the users private_key. The status codes are as follows:
    0 = Valid credentials, valid key and api key retrieved.
    1 = Login server is unavailable
    2 = invalid username or password
    3 = problem retrieving api_key
    4 = Private key error
    5 = Error retrieving private data, or no private data available.
    6 = Private key does not associate with the public key registered on your account"""
    import ApisAndHelpers.loginServerApis as loginApi
    import ApisAndHelpers.crypto as crypto
    # _______________________________Check server is online __________________________________
    if not loginApi.ping():
        return 1, None, None, None  # Return status and new api key for the user. 1 indicates server is down
    # ____________________Check username pass with http basic________________________________
    if not loginApi.ping(username, password):
        return 2, None, None, None  # 2 indicates invalid credentials, therefore no api key
    # _________________________ Generate new api key _______________________________________
    api_key = loginApi.load_new_apikey(username, password)
    if api_key is None:
        return 3, None, None, None  # 3 = Something went wrong, Couldn't get an api_key
    # _______________________________ Check api key_______________________________________
    valid_api_key_status, x_signature = loginApi.ping(username, password, api_key=api_key)
    if not valid_api_key_status:
        return 3, None, None, None  # 3 = Something went wrong, Invalid api_key

    # _________________________ Check private key is a key_______________________________________
    if key_type == "Private Key":
        status, keys = crypto.get_keys(key_value)
        if not status:  # The provided key is malformed
            return 4, api_key, x_signature, None
    else:  # Decrypt private data with Encryption key
        status, private_data = loginApi.get_private_data(username=username, password=password, encryption_key=key_value)
        if not status:  # Error retrieving private data
            return 5, api_key, x_signature, None
        # This point means the private data has been retrieved and decrypted.
        status, keys = crypto.get_keys(private_data['prikeys'][0])
        if not status:  # The provided key is malformed
            return 4, api_key, x_signature, None
    # This point means we have a proper key, either entered directly, or from private data. Check if it is valid.
    # _________________________ Validate private key_______________________________________
    valid_key_status = loginApi.ping(username, password, keys)
    if not valid_key_status:
        return 6, api_key, x_signature, None

    # _________________________ Report the associated public key_______________________________________

    return 0, api_key, x_signature, keys['private_key']  # 0 = Success, return new key









