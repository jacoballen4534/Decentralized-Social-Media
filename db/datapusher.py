# import cherrypy
# import time
# import random
# import requests
#
#
# def rndtobus(channel):
#     """
#     generate randomly intervalled <2s, random int 0-100,
#     push the messages directly onto the cherrypy bus.
#     Simulate for example the listen/notify from Postgresql putting
#     the latest transaction on the bus.
#     """
#     time.sleep(2)
#     while True:
#         time.sleep(random.random()*2)
#         msg = "event: time\ndata: {}\n\n".format(str(random.randint(0, 100)))
#         cherrypy.engine.publish(channel, msg)
#
#
# def rndtoport():
#     """
#     generate randomly intervalled <2s, random int 0-100,
#     post the data to the sensor method
#     Simulate for example an ESP8266 posting data to a IP over WiFi.
#     """
#     time.sleep(2)
#     headers = {"Content-Type": "application/json"}
#     url = 'http://10.0.0.4:8080/sensor/'
#     while True:
#         time.sleep(random.random()*2)
#         payload={'cpu': random.randint(0, 100)}
#         r = requests.post(url, headers=headers, json=payload)
#
