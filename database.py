# TwoFingerPhishPunch - database.py

# Contains database functions to use the SQLite3 database

# Created by Leon Ware


import sqlite3
from os import path

sqlite3.enable_callback_tracebacks(True)


# Connects to the database. Will create a new database if it does not exist.
def initialise(database_name):

    if path.exists(database_name):  # Checks if there is already a database
        print("Found existing database")
        conn = sqlite3.connect(database_name)  # Connects to the database
        c = conn.cursor()

    else:
        print("Generating new database")
        conn = sqlite3.connect(database_name)  # Connects to the database
        c = conn.cursor()

        c.execute('''CREATE TABLE source_urls
        (URL_ID integer primary key autoincrement, URL text UNIQUE, Malicious boolean, Time_Added datetime)''')

        c.execute('''CREATE TABLE source_domains
                (Domain_ID integer primary key autoincrement, Domain text UNIQUE,\
                 Malicious boolean, Time_Added datetime)''')

        c.execute('''CREATE TABLE blacklist_urls (URL text UNIQUE)''')

        c.execute('''CREATE TABLE blacklist_domains (Domain text UNIQUE)''')

        print("Database created!")

    return [conn, c]


def save(db_conn):  # Saves the database
    db_conn[0].commit()
    print("Changes committed")


def close(db_conn):  # Close connection to the database
    db_conn[0].close()
    print("Database disconnected")


def add_url(db_conn, url_name, is_malicious):
    try:
        db_conn[1].execute('''INSERT INTO source_urls
        (URL, Malicious, Time_Added) VALUES (?, ?, CURRENT_TIMESTAMP)''',
                           (url_name, is_malicious))
        return True

    except sqlite3.IntegrityError:
        # print("URL aready exists")
        return False


def add_domain(db_conn, domain_name, is_malicious):
    try:
        db_conn[1].execute('''INSERT INTO source_domains
        (Domain, Malicious, Time_Added) VALUES (?, ?, CURRENT_TIMESTAMP)''',
                           (domain_name, is_malicious))
        return True

    except sqlite3.IntegrityError:
        # print("Domain already exists")
        return False


def malicious(db_conn, mode):  # Return all malicious things - for testing and optimising blacklist
    if mode == "url":
        db_conn[1].execute('''SELECT URL FROM source_urls WHERE Malicious = True''')
    elif mode == "domain":
        db_conn[1].execute('''SELECT Domain FROM source_domains WHERE Malicious = True''')
    else:
        raise Exception("Malicious mode must be 'url' or 'domain'.")
    return db_conn[1].fetchall()


def benign(db_conn, mode):  # Return all benign things - for testing
    if mode == "url":
        db_conn[1].execute('''SELECT URL FROM source_urls WHERE Malicious = False''')
    elif mode == "domain":
        db_conn[1].execute('''SELECT Domain FROM source_domains WHERE Malicious = False''')
    else:
        raise Exception("Malicious mode must be 'url' or 'domain'.")
    return db_conn[1].fetchall()


def clear_blacklists(db_conn):
    # This will remove all rows from the blacklist tables
    db_conn[1].execute('''DELETE FROM blacklist_domains''')
    db_conn[1].execute('''DELETE FROM blacklist_urls''')
    print("Blacklists cleared")


def blacklist_add(db_conn, data, mode):
    # Add items to the specified blacklist
    if mode == "domain":
        table, column = "blacklist_domains", "Domain"
    elif mode == "url":
        table, column = "blacklist_urls", "URL"
    else:
        raise Exception("Malicious mode must be 'url' or 'domain'.")

    db_conn[1].execute('''INSERT INTO {} ({}) VALUES (?)'''.format(table, column), (data,))


def get_max(db_conn, table):
    # Return the max ID from the chosen source table
    # Used as a quick way to determine how many URLs or domains are contained in the table
    if table == "url":
        db_conn[1].execute('''SELECT max(URL_ID) FROM source_urls''')
    elif table == "domain":
        db_conn[1].execute('''SELECT max(Domain_ID) FROM source_domains''')
    else:
        return -1

    return db_conn[1].fetchone()


# Fetches a number of random benign or malicious samples
def get_random(db_conn, number, table, is_malicious):
    """
    :param db_conn:
    :param number: integer
    :param table: string
    :param is_malicious: boolean
    :return: tuple
    """

    if table == "domain":
        table, column = "source_domains", "Domain"
    elif table == "url":
        table, column = "source_urls", "URL"
    else:
        raise Exception("Table name must be 'url' or 'domain'.")

    db_conn[1].execute('''SELECT {} FROM {} WHERE Malicious = {} \
                          ORDER BY RANDOM() LIMIT {}'''.format(column, table, is_malicious, number))

    return db_conn[1].fetchall()


# Checks if an item is contained in the blacklist
# Returns true if it is, and false if it is not
def in_blacklist(db_conn, data, mode):
    data = '"' + data + '"'  # Stupid workaround to ensure sqlite3 does not treat data as a column name
    # print(data)

    if mode == "domain":
        db_conn[1].execute('''SELECT Domain FROM blacklist_domains WHERE Domain = {}'''.format(data))
    elif mode == "url":
        db_conn[1].execute('''SELECT URL FROM blacklist_urls WHERE URL = {}'''.format(data))
    else:
        raise Exception("Mode must be 'url' or 'domain'.")

    result = db_conn[1].fetchone()

    if result:
        return True
    else:
        return False
