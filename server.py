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
            Page += "You are now<font color='green'> visible</font>  on the login server.<br/> " \
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
        Page += 'Overwrite private data: <input type="checkbox" name="allow_overwrite"/><br/>'
        Page += '<input type="submit" value="Login"/></form>'

        Page += '<br/>' \
                'Assuming private key is stored on private data in the following form<br/>' \
                'private_data{<br/>' \
                '\t\t"prikeys": ["private_key_hex_string", " "],<br/>' \
                '\t\t"blockedpubkeys": ["...", "..."],<br/>' \
                '\t\t....<br/>' \
                '}<br/>' \
                'keys are in list.<br/>' \
                '<p> <h3> Test your Encryption </h3 >' \
                'Enter your username, password and encryption key. (Dont tick overwrite)<br/>' \
                'This will attempt to retrieve your encrypted private data and decrypt.<br/>' \
                'If you make it past the login page, that means your data was successfully decrypted.<br/>' \
                'If you receive invalid username or password, This could be invalid credentials<br/>' \
                'or something else went wrong. Either try again or contact me.<br/>' \
                'As an extra check, call the list users api. If you are on there, it was successful.<br/>'

        Page += '<h3> Test your Decryption </h3 >' \
                '<h4>Note: </h4>' \
                'Due to not having access to your existing private keys, this will:<br/>' \
                '<ul>' \
                '<li>Overwrite your existing private data.</li>' \
                '<li>Create a new public private key for you.(and add it to your account)</li>' \
                '<li>Set your "incoming key" to this new key</li>' \
                '</ul></br>' \
                'To use one of your old keys, you will need to call the report api with that key<br/>' \
                '(to reset it as your incoming key).<br/>' \
                'Use this to add new encrypted private data to your account to check your decryption against.' \
                'If you get past the login page, this means your new private data has been added.<br/>' \
                'If you receive invalid username or password, This could be invalid credentials<br/>' \
                'or something else went wrong. Either try again or contact me.<br/>' \
                'As an extra check, call the list users api. If you are on there, it was successful.<br/>'
        return Page

    @cherrypy.expose
    def sum(self, a=0, b=0):  # All inputs are strings by default
        output = int(a) + int(b)
        return str(output)

    # LOGGING IN AND OUT
    @cherrypy.expose
    def signin(self, username=None, password=None, second_password=None, allow_overwrite=None):
        """Check their name and password and send them either to the main page, or back to the main login screen."""
        print("\nLogin attempt:\n\t\t\t\tUsername: " + str(username) + "\n\t\t\t\tPassword: " + str(password) +
              "\n\t\t\t\tsecond_password: " + str(second_password) + "\n\t\t\t\tOverwrite: " + str(allow_overwrite) + "\n\n")
        success = authorise_user_login(username, password, second_password, allow_overwrite)
        if success:
            print("\n\nSucessfull login:\n\t\t\t\tUsername: " + str(username) + "\n\t\t\t\tPassword: " + str(password) +
                  "\n\t\t\t\tsecond_password: " + str(second_password) + "\n\t\t\t\tOverwrite: " + str(allow_overwrite) + "\n\n")
            cherrypy.session['username'] = username
            cherrypy.session['password'] = password
            cherrypy.session['second_password'] = second_password
            raise cherrypy.HTTPRedirect('/')
        else:
            raise cherrypy.HTTPRedirect('/login?bad_attempt=1')

    @cherrypy.expose
    def signout(self):
        """Logs the current user out, expires their session"""
        username = cherrypy.session.get('username')
        password = cherrypy.session.get('password')
        second_password = cherrypy.session.get('second_password')
        if username is not None or password is not None or second_password is not None:
            cherrypy.lib.sessions.expire()

        raise cherrypy.HTTPRedirect('/')


###
### Functions only after here
###

def authorise_user_login(username, password, second_password, overwrite):
    # _______________________________Check server is online __________________________________
    if not acc.ping_central_server():
        return False  # Need to return message to display
    # ____________________Check username pass with http basic________________________________
    if not acc.ping_central_server(username, password):
        return False
    # _________________________ Retrieve private data _______________________________________

    if overwrite != 'on':  # Just test decrypt
        return acc.get_private_data(username, password, second_password, overwrite)
    else:
        try:
            # Try to overwrite their private data.
            if not acc.overwrite_private_data(username, password, second_password):
                return False  # Something went wrong, Didnt work

            # Try to decrypt the new overwritten data.
            if acc.get_private_data(username, password, second_password, overwrite):
                return True

        except KeyError as e:
            print(e)
            return False
    return False
