import pprint
import urllib.request
import cherrypy
import exampleApiAccess.apiHelpers as acc
import json
from jinja2 import Environment, FileSystemLoader
env = Environment(loader=FileSystemLoader('static'), autoescape=True)

startHTML = "<html><head><title>CS302 example</title><link rel='stylesheet' href='/static/example.css' /></head><body>"


class Login(object):
    # If they try somewhere we don't know, catch it here and send them to the right place.
    @cherrypy.expose
    def default(self, *args, **kwargs):
        """The default page, given when we don't recognise where the request is for."""
        Page = startHTML + "I don't know where you're trying to go, so have a 404 Error."
        cherrypy.response.status = 404
        return Page

    # PAGES (which return HTML that can be viewed in browser)


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
