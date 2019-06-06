# import os
# import time
# import threading
# import cherrypy
#
# import db.messageStreamer
#
#
# class Root():
#
#     @cherrypy.expose
#     @cherrypy.tools.json_in()
#     def sensor(self, **kwargs):
#         """
#         receives POSTed data, converts to SSE ready message and
#         pushes it onto the cherrypy bus
#         """
#         input_json = cherrypy.request.json
#         msg = "event: time\ndata: {}\n\n".format(str(input_json['cpu']))
#         cherrypy.engine.publish("cpu", msg)
#
#     @cherrypy.expose
#     def pubcpu(self):
#         """
#         publishes data from the subscribed channel...
#         """
#         channel = 'broadcast'
#
#         doorman = db.messageStreamer.MessageStreamer(channel)
#         cherrypy.response.headers["Content-Type"] = "text/event-stream"
#
#         def pub():
#             for message in doorman.messages():
#                 try:
#                     yield message
#                 except GeneratorExit:
#                     # cherrypy shuts down the generator when the client
#                     # disconnects. Catch disconnect and unsubscribe to clean up
#                     doorman.unsubscribe()
#                     return
#         return pub()
#     pubcpu._cp_config = {'response.stream': True}
#
#
