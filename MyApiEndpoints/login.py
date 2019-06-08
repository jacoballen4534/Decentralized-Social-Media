import pprint
import urllib.request
import cherrypy
import json
import pickle
from jinja2 import Environment, FileSystemLoader
import ApisAndHelpers.loginServerApis as loginApi
import main
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
                                     api_key_error=(status_code == '3'), private_key_error=(status_code == '4'),
                                     private_data_error=(status_code == '5'), key_missmathch=(status_code == '6'),
                                     api_key_expired=(status_code == '7'))

    @cherrypy.expose
    def signin(self, username=None, password=None, key_type=None, key_value=None):
        """Check their name and password and send them either to the main page, or back to the main login screen."""
        status_code, api_key, keys = authorise_user_login(username, password, key_type, key_value)
        # api_key = "2"
        # if True:
        if status_code == 0:  # Successfully logged in and generated api key
            print("\n\nSuccessful login:\n\t\t\t\tUsername: " + str(username) + "\n\t\t\t\tPassword: " + str(password) +
                  "\n\t\t\t\tprivate_key: " + str(keys['private_key_hex_string']) + "\n\t\t\t\tapi_key: " + str(api_key) + "\n\n")
            cherrypy.session['username'] = username
            cherrypy.session['api_key'] = api_key
            if keys is not None:
                pickled_keys = pickle.dumps(keys, protocol=4, fix_imports=False)
                cherrypy.session['pickled_keys'] = pickled_keys
            else:
                cherrypy.session['pickled_keys'] = None

            raise cherrypy.HTTPRedirect('/')
        else:
            raise cherrypy.HTTPRedirect('/login?status_code=' + str(status_code))

    @cherrypy.expose
    def signout(self):
        """Logs the current user out, expires their session"""
        username = cherrypy.session.get('username')
        api_key = cherrypy.session.get('api_key')
        pickled_keys = cherrypy.session.get("pickled_keys")
        keys = None
        try:
            # Set the user status to offline before signing out
            keys = pickle.loads(pickled_keys)
            loginApi.report(location=main.LOCATION, username=username, keys=keys, status="offline",
                            api_key=api_key)
        except Exception:
            pass

        if username is not None or api_key is not None or pickled_keys is not None:
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
    import ApisAndHelpers.crypto as crypto
    # Clear all credentials if the are already logged in, but try to log in again.
    cherrypy.session['username'] = None
    cherrypy.session['api_key'] = None
    cherrypy.session['pickled_keys'] = None
    # _______________________________Check server is online __________________________________
    if not loginApi.ping():
        return 1, None, None  # Return status and new api key for the user. 1 indicates server is down
    # ____________________Check username pass with http basic________________________________
    if not loginApi.ping(username, password):
        return 2, None, None  # 2 indicates invalid credentials, therefore no api key
    # _________________________ Generate new api key _______________________________________
    api_key = loginApi.load_new_apikey(username=username, password=password)  # The only use of password
    if api_key is None:
        return 3, None, None  # 3 = Something went wrong, Couldn't get an api_key
    # _______________________________ Check api key_______________________________________
    valid_api_key_status = loginApi.ping(username=username, password=password, api_key=api_key)
    if not valid_api_key_status:
        return 3, None, None  # 3 = Something went wrong, Invalid api_key

    # _________________________ Check private key is a key_______________________________________
    if key_type == "Private Key":
        status, keys = crypto.get_keys(private_key_hex_string=key_value)
        if not status:  # The provided key is malformed
            return 4, api_key, None
    else:  # Decrypt private data with Encryption key
        status, private_data = loginApi.get_private_data(username=username, encryption_key=key_value, api_key=api_key,
                                                         password=password)
        if not status:  # Error retrieving private data
            return 5, api_key, None
        # This point means the private data has been retrieved and decrypted.
        status, keys = crypto.get_keys(private_data['prikeys'][0])
        if not status:  # The provided key is malformed
            return 4, api_key, None
    # This point means we have a proper key, either entered directly, or from private data. Check if it is valid.
    # _________________________ Validate private key_______________________________________
    valid_key_status = loginApi.ping(username, password, keys)
    if not valid_key_status:
        return 6, api_key, None

    # _________________________ Report the associated public key_______________________________________
    report_status = loginApi.report(location=main.LOCATION, username=username, keys=keys, status="online",
                                    api_key=api_key, password=password)
    if not report_status:
        return 4, api_key, keys

    return 0, api_key, keys  # 0 = Success, return new keys









