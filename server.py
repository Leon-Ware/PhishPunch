# TwoFingerPhishPunch - server.py

# Contains server functions to create and run the DNS and proxy servers

# Created by Leon Ware

import ai
import analysis
from database import initialise
from database import in_blacklist

from os import system as os_system
from os import getcwd
from threading import Thread

import socket
import dnslib


# Future work:
# Check if DNS packets can have more than 1 query per packet


# Launches mitm_proxy using the system call, which opens it through the command line
def mitm_proxy(msg_q, script_file):
    current_dir = getcwd()
    script_file = current_dir + "\\" + script_file

    send_message(msg_q, "~~ MITM Proxy ~~",
                 "\nMITM Proxy documentation can be found at: https://mitmproxy.org/",
                 "\nWill start proxy using:", script_file,
                 "\nNote: Certificate errors can be fixed by visiting 'mitm.it' whilst the proxy is running",
                 "\nAttempting to start proxy through command line now...")

    # os_system("mitmdump.exe")
    os_system("mitmdump.exe -s " + script_file)  # Starts MITM with the specified plugin file

    send_message(msg_q, "Proxy terminated!")


# Listens for DNS requests on the specified port, and checks them against the neural network
# Anything that looks suspicious is put on the queue to be checked against the blacklist
def dns_listener(dns_socket, model_name, ignore_local, query_queue, msg_q):
    # This will be a thread created when called from another function

    model = ai.load_network(model_name)  # Load the neural network
    normalisers = model.get_normalisers()  # Used for scaling analysis data

    # Keep listening for packets
    while True:
        try:
            # 1024 bytes is a good maximum size for request packets. Normally they are much smaller.
            # https: // blog.cloudflare.com / a - deep - dive - into - dns - packet - sizes - why - smaller - packet - sizes - keep - the - internet - safe /
            # Article shows cloudflare works to keep DNS answers below 512 bytes.
            packet = dns_socket.recvfrom(1024)  # receive data from client (data, addr) - this function is OS safe

        # https://stackoverflow.com/questions/30749423/is-winsock-error-10054-wsaeconnreset-normal-with-udp-to-from-localhost
        # A weird issue with Windows, where a packet sent to a closed port causes Windows to send a 'port unreachable'
        # packet to the socket, and is interpreted as a connection failure
        # Ignoring the error allows everything to keep working
        except ConnectionResetError:
            continue

        data = packet[0]
        address = packet[1]

        if address[0] == '127.0.0.1' and ignore_local:  # Ignore requests from this device if we want to
            continue

        try:
            # send_message(msg_q, "\nPacket from", address)
            dns_data = dnslib.DNSRecord.parse(data)
        except dnslib.dns.DNSError:
            send_message(msg_q, "\nMalformed DNS packet")
            continue  # Break out of this loop, then loop back in

        domain_name = str(dns_data.get_q().qname)[:-1]  # Get the domain query name and strip trailing dot

        domain_data = analysis.domain(domain_name)  # Analyse the domain name and prepare for neural network
        domain_data = analysis.normalise_data([domain_data], normalisers)

        prediction = model.predict(domain_data[0])  # Neural network determines maliciousness

        if prediction[0] > prediction[1]:  # If benign > malicious score, we need to check the blacklist
            # send_message(msg_q, domain_name, "- appears safe")
            query_params = [dns_data.header.id, dns_data.get_q().qtype]
            query_queue.put(["domain", domain_name, address, query_params])  # Send in queue to be checked by blacklist
        else:
            send_message(msg_q, domain_name, "- BLOCKED request from", address)


# After blacklist check is complete, this function then performs a lookup for the domain and sends the response packet
def dns_resolver(dns_socket, result_queue, msg_q):
    while True:
        blacklist_result = result_queue.get()  # Fetch the result from the queue - [domain, in_blacklist]
        result_queue.task_done()  # Mark as done to remove from queue

        lookup_domain = blacklist_result[0]
        blacklisted = blacklist_result[1]
        # Address is taken from the queue to ensure we don't mismatch queries to clients
        query_address = blacklist_result[2]
        query_params = blacklist_result[3]

        if not blacklisted:
            try:
                if query_params[1] == 1:  # A record query (IPv4)
                    ip_address = socket.gethostbyname(lookup_domain)  # perform a DNS lookup
                elif query_params[1] == 28:  # AAAA record query (IPv6)
                    # https://stackoverflow.com/questions/15373288/python-resolve-a-host-name-with-ipv6-address
                    # This should fetch an IPv6 address, but this does not seem to work
                    try:
                        ip_address = socket.getaddrinfo(lookup_domain, 0, family=socket.AF_INET6)[0][4][0]
                    except socket.gaierror:
                        ip_address = socket.gethostbyname(lookup_domain)  # Fallback to IPv4
                        query_params[1] = 1  # Set our Qtype to IPv4 to match
                else:
                    send_message(msg_q, "UNSUPPORTED query type:", query_params[1])
                    continue

                # https://pythontic.com/modules/socket/getaddrinfo
                # ip_address = socket.getaddrinfo(lookup_domain, 0)  # 0 placeholder, all packet types?
                # send_message(msg_q, lookup_domain, ":", ip_address)
            except socket.gaierror:  # Might be an error caused by invalid domain names or lookup failure
                send_message(msg_q, "LOOKUP ERROR:", lookup_domain, "- QTYPE:", query_params[1])
                # send_message(msg_q, lookup_domain, query_params[1], "LOOKUP ERROR:", error)
                continue

            # Assemble response packets
            if query_params[1] == 28:  # AAAA record, IPv6
                response = dnslib.DNSRecord(
                    dnslib.DNSHeader(qr=1, aa=1, ra=1, id=query_params[0]),
                    q=dnslib.DNSQuestion(lookup_domain),
                    a=dnslib.RR(lookup_domain, rdata=dnslib.AAAA(ip_address))
                )
            else:  # Treat as normal A record answer
                response = dnslib.DNSRecord(
                    dnslib.DNSHeader(qr=1, aa=1, ra=1, id=query_params[0]),
                    q=dnslib.DNSQuestion(lookup_domain),
                    a=dnslib.RR(lookup_domain, rdata=dnslib.A(ip_address))
                )

            # https://pypi.org/project/dnslib/
            # Send DNS response packet
            dns_socket.sendto(response.pack(), query_address)
            send_message(msg_q, lookup_domain, ip_address, query_params[1], "resolved for", query_address)
        else:
            send_message(msg_q, lookup_domain, "- BLACKLISTED request from", query_address)


# Prepares the DNS server so it can be used.
# Includes creation of socket and starting both halves of the DNS server - listener and resolver
def start_dns(port, model_name, ignore_local, query_queue, result_queue, msg_q):
    # https://www.binarytides.com/programming-udp-sockets-in-python/
    # Start listening on port 53 UDP and TCP
    socket_host = ''  # Symbolic name meaning all available interfaces on host
    dns_listen_port = port  # DNS port

    # UPDATE PLAN:
    # Sending data from UDP socket is causing the connection to reset.
    # Instead, open a separate sending socket and send replies using that

    send_message(msg_q, "Attempting bind to UDP port ", dns_listen_port)
    try:
        dns_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)  # UDP query receive socket
        dns_socket.bind((socket_host, dns_listen_port))
        dns_socket.setblocking(True)  # Force blocking on, should be enabled by default
    except socket.error as error:
        send_message(msg_q, 'Failed to create sockets.\nError Code :', str(error[0]), '\nMessage :', error[1])
        return
    send_message(msg_q, "Port bind successful!")
    send_message(msg_q, "Ignoring local packets set to:", ignore_local)

    print("Starting DNS listener")
    listener = Thread(target=dns_listener,
                      args=(dns_socket, model_name, ignore_local, query_queue, msg_q))
    listener.setDaemon(True)
    listener.start()

    print("Starting DNS resolver")  # NOTE - connects to database in thread
    resolver = Thread(target=dns_resolver,
                      args=(dns_socket, result_queue, msg_q))
    resolver.setDaemon(True)
    resolver.start()


# Blacklist listener - receives queries, checks if they are in the blacklist, and then places answers in the queue
def check_blacklist(db_name, query_queue, domain_results, url_results):
    db_conn = initialise(db_name)  # Initialise in this thread

    while True:
        new_query = query_queue.get()  # Fetch a query from te queue
        mode = new_query[0]
        data = new_query[1]
        address = new_query[2]

        if new_query[0] == "domain":
            query_id = new_query[3]
            result = in_blacklist(db_conn, data, mode)  # Check blacklist
            domain_results.put([data, result, address, query_id])  # Places on queue for DNS resolver
        elif new_query[0] == "url":
            result = in_blacklist(db_conn, data, mode)
            url_results.put([data, result, address])
        query_queue.task_done()


def send_message(message_queue, *args):  # A handy function to send messages
    message = ""
    for part in args:
        message += str(part) + " "

    message_queue.put(message)
