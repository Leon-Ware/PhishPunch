# TwoFingerPhishPunch - mitm_script.py

# Provides plugin functionality for MITM Proxy

# Created by Leon Ware

# Adapted from https://docs.mitmproxy.org/stable/addons-scripting/
# Send a reply from the proxy without sending any data to the remote server

from mitmproxy import http

import ai
import analysis
from database import initialise
from database import in_blacklist

database_name = "database.sqlite3"


model = ai.load_network("url_nn.model")  # Load the neural network
normalisers = model.get_normalisers()  # Used for scaling analysis data

db_conn = initialise(database_name)


# The request function is an event handler for MITM proxy requests
def request(flow: http.HTTPFlow) -> None:
    # requested_url = flow.request.pretty_url
    requested_url = flow.request.url

    url_data = analysis.url(requested_url)  # Analyse the domain name and prepare for neural network
    url_data = analysis.normalise_data([url_data], normalisers)
    prediction = model.predict(url_data[0])  # Neural network determines maliciousness

    # prediction[0] = benign, prediction[1] = malicious
    if prediction[0] > prediction[1]:  # If benign > malicious score, we need to check the blacklist
        blacklist_check = in_blacklist(db_conn, requested_url, "url")
        print(requested_url, "CHECK:", blacklist_check)
        if blacklist_check:
            print("BLACKLISTED -", requested_url)
            flow.response = http.HTTPResponse.make(
                200,  # (optional) status code
                b"Blacklisted resource!",  # (optional) content
                {"Content-Type": "text/html"}  # (optional) headers
            )
        else:
            print("Resource OK -", requested_url)
    else:
        print("MALICIOUS -", requested_url)
        flow.response = http.HTTPResponse.make(
            200,  # (optional) status code
            b"Malicious resource!",  # (optional) content
            {"Content-Type": "text/html"}  # (optional) headers
        )
