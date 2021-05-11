# TwoFingerPhishPunch - main.py

# Main control tying all the functionality together into something coherent

# Created by Leon Ware

from queue import Queue
from threading import Thread
from shutil import copy as shutil_copy

from tld.utils import update_tld_names  # Used for updating tld library definitions

# Import the other python scripts
import get_data
import database
import ai
import csv
import server

database_name = "database.sqlite3"


# ingest_data is used to ingest data into the database, and display the results of this process
# if enable_downloads is true, files will be downloaded
def ingest_data(enable_downloads):
    db_conn = database.initialise(database_name)  # Initialise SQLite and get connection

    # db_conn, enable_downloads(True/False)
    data_results = get_data.gather_data(db_conn, enable_downloads)  # Gather our source data

    print("Ingest data:")
    print("URLs added:", data_results[0])
    print("URLs existing:", data_results[1])
    print("Domains added:", data_results[2])
    print("Domains existing:", data_results[3])
    print("Invalid items:", data_results[4])

    database.save(db_conn)  # Save database so we can use new tables
    database.close(db_conn)


# This function was used to analyse the domain analysis data and insert them into a CSV file
# It has not been updated for URL analysis, and is no longer used
def write_to_csv(data):
    print("Creating: ai_test_data.csv")

    # Opens 'ai_test_data.csv' to insert data. Will overwrite existing file.
    try:
        with open("ai_test_data.csv", "w", newline="") as file:  # Extra newline param prevent space between rows
            csv_writer = csv.writer(file, delimiter=',', quotechar='"', quoting=csv.QUOTE_MINIMAL)

            csv_header = ["Domain", "Malicious", "Entropy", "SequentialConsonants", "SequentialVowels", "Length",
                          "Consonants", "Vowels", "Entropy/Length", "Consonants/Vowels", "Vowels/Length",
                          "SequentialVowels/Length", "SequentialConsonants/SequentialVowels", "RMA"]

            csv_writer.writerow(csv_header)

            for i in range(len(data)):
                csv_writer.writerow(data[i])
    except PermissionError:
        print("WARNING: Failed to write to CSV - File already open")


# create_network calls functions to create and test the neural networks.
def create_network(num_candidates, mode, samples, iterations):
    db_conn = database.initialise(database_name)  # Initialise SQLite and get our connection

    # Batch network creation
    network_names = []  # Keeps track of the models created
    network_models = []  # Provide access to all models for testing
    for i in range(num_candidates):
        print("\nPreparing training data for", mode, "network candidate", i)
        # Each network gets own randomised training data
        data_names, data_analysis, data_normalisers = ai.get_training_data(db_conn, samples, mode)

        print("Creating and training", mode, "network candidate", i)
        model_name = mode + "_candidate_" + str(i) + ".model"
        network_names.append(model_name)
        # Call the network creation function using given parameters, and hard-coded learning rate
        created_network = ai.create_network(data_names, data_analysis, data_normalisers, model_name, iterations, 1e-6)
        network_models.append(created_network)

    # Batch network testing, returns list of accuracy results
    network_results = ai.test_models(db_conn, network_models, mode)

    best_network = network_results.index(max(network_results))  # Find position of network with max score in list
    final_model = network_names[best_network]

    print("Best network:", best_network, "-", final_model)
    # Copy the network to the final name of domain_nn.model or url_nn.model
    # These names are hard-coded in several locations
    shutil_copy(ai.model_location + final_model, ai.model_location + mode + "_nn.model")

    database.close(db_conn)  # Close connection because it isn't needed anymore

    print("Done")


# create_blacklists generates optimised blacklists for domain and URL networks
# The blacklists are first cleared and then re-generated
# Also provides some useful statistics
def create_blacklists():
    print("Clearing existing blacklists")
    db_conn = database.initialise(database_name)
    database.clear_blacklists(db_conn)  # Clears the blacklist tables

    # Produces blacklists from false-negative predictions from ai models
    print("Optimising URL blacklist...")
    processed, added = ai.optimise_blacklists(db_conn, "url_nn.model", "url")
    print("Processed:", processed)
    print("Added:", added)

    print("Optimising Domain blacklist...")
    processed, added = ai.optimise_blacklists(db_conn, "domain_nn.model", "domain")
    print("Processed:", processed)
    print("Added:", added)

    database.save(db_conn)  # It is vital that the database is saved before we close it
    database.close(db_conn)

    print("Done")


# start_servers prepares thread queues and then calls functions to start the servers.
# Note that the proxy will call MITM Proxy, which uses the mitm_script.py file
def start_servers():
    # Several queues are created so that threads can communicate with each other.
    # Primarily to work around a limit of single SQLite connection per thread, and also
    # stop races between thread outputs jumbling output.

    # query_queue holds all blacklist searches we need to perform
    query_queue = Queue(maxsize=20)  # [type, domain/url, query info]
    domain_results = Queue(maxsize=10)  # [domain, result, query info]
    url_results = Queue(maxsize=10)  # [url, result, query info]
    message_queue = Queue(maxsize=20)  # A queue for receiving messages from threads

    # This thread connects to the database and receives requests from the query_queue
    # It then returns results on the respective queue for domain or URL queries
    print("Starting blacklist checker")  # NOTE - connects to database in thread
    blacklist_checker = Thread(target=server.check_blacklist,
                               args=(database_name, query_queue, domain_results, url_results))
    blacklist_checker.setDaemon(True)
    blacklist_checker.start()

    # This thread starts the DNS server using several hard-coded values.
    # No issues were observed connection to port 53, but this could change depending on OS used.
    print("Setting up DNS server")
    # Set port, neural network model, ignore localhost, queues
    dns_server = Thread(target=server.start_dns,
                        args=(53, "domain_nn.model", True, query_queue, domain_results, message_queue))
    dns_server.setDaemon(True)
    dns_server.start()

    # This starts the MITM proxy with the plugin script.
    # The plugin script will separately connect to the database
    print("Setting up Proxy server")
    server.mitm_proxy(message_queue, "mitm_script.py")

    # Enter an infinite loop to read output messages and display them coherently.
    while True:
        message = message_queue.get()  # By default, get() is blocking so it waits for a message
        print(message)
        message_queue.task_done()


# This code executes when the file is run.
# Comment out functions to stop them running, such as to restart the servers without re-creating neural networks.
if __name__ == "__main__":
    update_tld_names()  # Update the TLD names for the TLD library

    ingest_data(False)  # Read source files and populate database, with toggle for downloads

    # Collect data, generate neural networks, train, test and save
    create_network(5, "domain", 30000, 5000)  # Network candidates, mode, samples, iterations
    create_network(5, "url", 30000, 5000)

    create_blacklists()

    start_servers()

    print("FINISHED")
