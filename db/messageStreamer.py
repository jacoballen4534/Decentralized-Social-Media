import threading
import cherrypy


class MessageStreamer(threading.Thread):
    # messages = ["message1", "message2", "message3", "message4", "message5"]
    # cherrypy.response.headers['Content-Type'] = 'text/event-stream;charset=utf-8'
    # @cherrypy.tools.allow(methods=["GET"])
    # @cherrypy.tools.json_out()
    def __init__(self, channel, args=(), kwargs=None, *, deamon=None):
        super().__init__()
        self.e = threading.Event()
        self.channel = channel
        print("NEW DOORMAN CREATED")
        cherrypy.engine.subscribe(channel, self._msgs)

    @property
    def message(self):
        return self._message

    @message.setter
    def message(self, msg):
        self.e.set()
        self._message = msg

    def messages(self):
        while True:
            self.e.wait()
            yield self._message
            self.e.clear()

    def _msgs(self, message):
        self.message = message

    def unsubscribe(self):
        print("DOORMAN UNSUBSCRIBING")
        cherrypy.engine.unsubscribe(self.channel, self._msgs)

