import cherrypy


startHTML = "<html><head><title>CS302 example</title><link rel='stylesheet' href='/static/example.css' /></head><body>"


class MainApp(object):
    logins = {"user": "password", "notuser": "anything"}
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
    def index(self, newUser="False"):
        Page = startHTML + "Welcome! This is a test website for COMPSYS302!<br/>"

        try:
            if newUser == "True":
                Page += "Welcome " + cherrypy.session['username'] + "! I hope you enjoy your new account.<br/>"
            else:
                Page += "Welcome back " + cherrypy.session['username'] + "!<br/>"
            Page += "Here is some bonus text.<br/>This is some different bonus text for task 9<br/> <a " \
                    "href='/signout'>Sign out</a> "
        except KeyError:  # There is no username

            Page += "Click here to <a href='login'>login</a>."
            Page += "<br/> Or consider <a href='signUp'>Signing Up</a>."
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
    def signUp(self):
        Page = startHTML

        Page += '<form action="/addNewUser" method="post" enctype="multipart/form-data">'
        Page += 'Username: <input type="text" name="username"/><br/>'
        Page += 'Password: <input type="text" name="password"/>'
        Page += '<input type="submit" value="Sign Up"/></form>'
        return Page

    @cherrypy.expose
    def sum(self, a=0, b=0):  # All inputs are strings by default
        output = int(a) + int(b)
        return str(output)

    # LOGGING IN AND OUT
    @cherrypy.expose
    def signin(self, username=None, password=None, newUser=False):
        """Check their name and password and send them either to the main page, or back to the main login screen."""
        error = authoriseUserLogin(username, password, self.logins)
        if error == 0:
            cherrypy.session['username'] = username
            raise cherrypy.HTTPRedirect('/?newUser=' + str(newUser))
        else:
            raise cherrypy.HTTPRedirect('/login?bad_attempt=1')

    @cherrypy.expose
    def addNewUser(self, username=None, password=None):
        addNewUser(username, password, self.logins)
        self.signin(username, password, True)

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

def authoriseUserLogin(username, password, logins):
    print("Log on attempt from {0}:{1}".format(username, password))
    if (username.lower() in logins) and (logins[username.lower()] == password.lower()):
        print("Success")
        return 0
    else:
        print("Failure")
        return 1


def addNewUser(username, password, logins):
    if username is None or username.lower() in logins or password is None:
        pass
    else:
        logins[username] = password
        cherrypy.session['username'] = username
