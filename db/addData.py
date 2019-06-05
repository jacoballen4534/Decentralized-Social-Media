import pprint
import urllib.request
import cherrypy
import json
import time
import ApisAndHelpers.requests as request_helper
import ApisAndHelpers.crypto as crypto
import sqlite3


def add_public_broadcast(loginserver_record, message, timestamp):

    status, sender, sender_pubkey, time_stamp, signature = pre_process_broadcast(loginserver_record, timestamp)
    if not status:
        return False

    conn = None
    try:
        conn = sqlite3.connect("./db/database.db")
        c = conn.cursor()
        c.execute("""INSERT INTO broadcasts
                    (message, sender, timestamp, sender_pubkey, signature)
                    VALUES
                    (?,?,?,?,?)""", (message, sender, time_stamp, sender_pubkey, signature,))
        conn.commit()
        print("Added message to db")
    except (sqlite3.OperationalError, sqlite3.IntegrityError) as e:
        print(e)
    finally:
        if conn is not None:
            conn.close()


def pre_process_broadcast(loginserver_record, time_stamp):
    try:
        tokens = loginserver_record.split(",")
        username = tokens[0]
        public_key = tokens[1]
        timestamp = float(time_stamp)
        signature = tokens[3]
        return True, username, public_key, timestamp, signature
    except Exception as e:
        print(e)
        return False, None, None, None, None
