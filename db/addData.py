import pprint
import urllib.request
import cherrypy
import json
import time
# import ApisAndHelpers.requests as request_helper
# import ApisAndHelpers.crypto as crypto
import sqlite3


def add_public_broadcast(loginserver_record, message, timestamp, broadcast_signature):
    """This will take all public broadcasts to be stored. The message will be inspected to see if it is a metamessage
    and stored in the appropriate database"""
    status, sender, sender_pubkey, time_stamp = pre_process_broadcast(loginserver_record, timestamp)
    if not status:
        return False

    try:
        if message[:5] == '!Meta':
            tokens = message.split(':')
            if len(tokens) < 3:
                return  # This means there was the meta tag, with nothing after it.
            # What is this meta message acting on. for favorite, this is the broadcast they are liking
            acting_on = tokens[2]
            acting_on = acting_on.replace("[", "").replace("]", "")
            message_type = tokens[1]
            if message_type == 'favourite_broadcast':
                add_favourite_broadcast(signature_of_message_to_favorite=acting_on, sender=sender,
                                        sender_pubkey=sender_pubkey, time_stamp=time_stamp)
            elif message_type == 'block_broadcast':
                return
            elif message_type == 'block_username':
                return
            elif message_type == 'block_pubkey':
                return
            else:
                return
        else:
            add_broadcast_message(message, sender, sender_pubkey, time_stamp, broadcast_signature)
    except Exception as e:
        print(e)


def add_broadcast_message(message, sender, sender_pubkey, time_stamp, signature):
    conn = None
    try:
        conn = sqlite3.connect("./db/database.db")
        c = conn.cursor()
        conn.execute("PRAGMA foreign_key = true")
        c.execute("""INSERT INTO broadcasts
                    (message, sender, timestamp, sender_pubkey, signature)
                    VALUES
                    (?,?,?,?,?)""", (message, sender, time_stamp, sender_pubkey, signature,))
        conn.commit()
        print("Added message to db")
    except (sqlite3.OperationalError, sqlite3.IntegrityError) as e:
        print(e)
    except Exception as e:
        print(e)
    finally:
        if conn is not None:
            conn.close()


def add_favourite_broadcast(signature_of_message_to_favorite, sender, sender_pubkey, time_stamp):
    conn = None
    try:
        conn = sqlite3.connect("./db/database.db")
        c = conn.cursor()
        conn.execute("PRAGMA foreign_key = true")
        c.execute("""INSERT INTO favourite_broadcast
                        (username, pubkey, timestamp, favourite_signature)
                        VALUES
                        (?,?,?,?)""", (sender, sender_pubkey, time_stamp, signature_of_message_to_favorite,))
        conn.commit()
        print("Added message to db")
    except (sqlite3.OperationalError, sqlite3.IntegrityError) as e:
        print(e)
    except Exception as e:
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
        sender_signature = tokens[3]  # un-unused at the moment
        return True, username, public_key, timestamp
    except Exception as e:
        print(e)
        return False, None, None, None, None


def update_user_list(user):
    username = user.get('username')
    incoming_pubkey = user.get('incoming_pubkey')
    connection_updated_at = float(user.get('connection_updated_at'))
    connection_address = user.get('connection_address')
    connection_location = int(user.get('connection_location'))
    if (username is not None and incoming_pubkey is not None and connection_updated_at is not None and
            connection_address is not None and connection_location is not None):
        conn = None
        try:
            conn = sqlite3.connect("./db/database.db")
            c = conn.cursor()
            c.execute("""REPLACE INTO all_seen_users
                        (username, incoming_pubkey, connection_updated_at, connection_address, connection_location)
                        VALUES
                        (?,?,?,?,?)""",
                      (username, incoming_pubkey, connection_updated_at, connection_address, connection_location,))
            conn.commit()
        except (sqlite3.OperationalError, sqlite3.IntegrityError) as e:
            print(e)
        finally:
            if conn is not None:
                conn.close()


def add_private_message(loginserver_record, target_pubkey_str, target_username, encrypted_message_string,
                        sender_created_at, message_signature):
    """Takes a private message and stores the reletive components for later distribution."""
    status, sender_username, sender_pubkey, time_stamp = pre_process_broadcast(loginserver_record, sender_created_at)
    if not status:
        return False

    conn = None
    try:
        conn = sqlite3.connect("./db/database.db")
        c = conn.cursor()
        conn.execute("PRAGMA foreign_key = true")
        c.execute("""INSERT INTO private_messages
                    (message, sender, receiver, timestamp, sender_pubkey, receiver_pubkey, signature)
                    VALUES
                    (?,?,?,?,?,?,?)""", (encrypted_message_string, sender_username, target_username, time_stamp,
                                         sender_pubkey, target_pubkey_str, message_signature,))
        conn.commit()
        print("Added message to db")
    except (sqlite3.OperationalError, sqlite3.IntegrityError) as e:
        print(e)
    except Exception as e:
        print(e)
    finally:
        if conn is not None:
            conn.close()
