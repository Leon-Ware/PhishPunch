# TwoFingerPhishPunch - analysis.py

# Contains analysis functions for URLs and domains

# Created by Leon Ware

from urllib.parse import urlparse
from urllib.parse import parse_qs
import ipaddress

import tld.exceptions
from tld import get_tld

from math import log as mathlog


# We need to read blacklist URLs at the start, so they can be accessed quickly
url_blacklist = []
with open("url_blacklist_words.txt", "r") as file:
    for line in file:
        url_blacklist.append(line.rstrip())


# normalise_data scales the analysis values to use with the neural network
# The normalisers are specific to each neural network
# Values of -1 are set to the maximum value
def normalise_data(data_array, normalisers):
    # print("Scaling values...")
    minimums = normalisers[0]
    maximums = normalisers[1]
    multipliers = normalisers[2]

    values = minimums  # Initialise the values array using an arbitrary normaliser array

    if len(data_array[0]) != len(normalisers[0]):
        raise ValueError("Array and normaliser lengths do not match.")

    out_of_bound_vals = 0

    # Iterate over everything and normalise
    for i in range(len(data_array)):
        for j in range(len(values)):
            if data_array[i][j] == -1:  # Replace -1 values with the maximums
                data_array[i][j] = maximums[j]

            # use minimums as an offset to subtract by, then scale with multipliers
            normalise_val = (float(data_array[i][j]) - float(minimums[j])) * multipliers[j]

            # Catch out of bound values.
            # Not an error. Results exceeding min/max of those used for testing will be out of bounds
            if normalise_val > 1 or normalise_val < 0:
                # print("Normalisation out of bounds! Got value:", normalise_val)
                out_of_bound_vals += 1
                if normalise_val > 1:
                    normalise_val = 1
                elif normalise_val < 0:
                    normalise_val = 0

            data_array[i][j] = normalise_val

    # return data_array, out_of_bound_vals
    return data_array


# Takes the analysis data array and determins minimum and maximum values
# Then works out scaling values to scale values between 0 and 1
def get_normalisers(data_array):
    """
    Calculate normalisation values when given a 2D array of numbers
    :param data_array: 2D array, int/float
    :return: array of normalisers
    """

    results_min = []  # A stupid workaround to get past an issue where Python makes these arrays the same
    results_max = []  # Duplicate using brute force to separate the arrays
    for i in range(len(data_array[0])):
        results_min.append(data_array[0][i])
        results_max.append(data_array[0][i])

    # Iterate over training data to find min and max. Negative results indicate value beyond min/max
    for i in range(len(data_array)):
        for j in range(len(results_min)):
            if data_array[i][j] > results_max[j]:  # j+2 because of domain name and malicious indicator
                results_max[j] = data_array[i][j]  # Set new maximum
            elif data_array[i][j] < results_min[j]:  # The minimum must not be -1. Reserved for zero division
                results_min[j] = data_array[i][j]  # Set new minimum

    # Determine scale factors using identified min and max values
    result_multipliers = []  # Find scale factor to get results between 0 and 1.
    for i in range(len(results_max)):
        try:
            result_multipliers.append(float(1 / (results_max[i] - results_min[i])))
        except ZeroDivisionError:
            # A zero division error means an infinite answer
            result_multipliers.append(0)  # Min and Max the same, so go with 0 so all results are 0

    return [results_min, results_max, result_multipliers]  # Normalisers - Offsets (min and max) and multipliers


# Analyse domain data and produce list of numerical values
def domain(data):
    # Remove suffix to get the useful part of domain name
    try:
        domain_tld = get_tld(data, fix_protocol=True)
    except tld.exceptions.TldDomainNotFound:
        domain_tld = False
    except Exception as e:
        print("ERROR:", e)
        print("data:", data)
        raise Exception("Yikes")

    if domain_tld:
        data = data.replace("." + domain_tld, '')  # Remove the TLD and trailing dot
    # print("Domain without TLD:", data)

    results = [0.0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]

    # SHANNON ENTROPY CALCULATION
    length = len(data)  # This has been adapted from an example from Splunk to be usable with Python 3
    occ = {}
    for c in data:
        if c not in occ:
            occ[c] = 0
        occ[c] += 1  # This might not be correct, but using occ[c] instead of occ is required
        # Final entropy values are slightly lower than expected but usable
    for (k, v) in occ.items():
        p = float(v) / float(length)
        results[0] -= p * mathlog(p, 2)  # Final calculation for entropy

    results[1] = consecutive_chars(data, False)  # consecutive consonants
    results[2] = consecutive_chars(data, True)  # consecutive vowels
    results[3] = len(data)  # domain length
    results[4] = total_chars(data, False)  # number consonants
    results[5] = total_chars(data, True)  # number vowels
    results[6] = results[0] / results[3]  # ratio entropy to domain length

    try:
        results[7] = results[4] / results[5]  # ratio consonants to vowels
    except ZeroDivisionError:
        results[7] = -1  # TEMPORARY VALUE, later set to maximum

    results[8] = results[5] / results[3]  # ratio vowels to domain length
    results[9] = results[2] / results[3]  # ratio sequential vowels to domain length

    try:
        results[10] = results[1] / results[2]  # ratio sequential consonants to sequential vowels
    except ZeroDivisionError:
        results[10] = 0

    # RMA algorithm
    if results[0] <= 2 and results[3] < 5:  # if entropy <= 2 and length < 5
        results[11] = 0  # Normal domain
    elif results[0] > 3.24:  # if entropy > 3.24
        results[11] = 1  # DGA domain
    elif results[1] >= 4 or results[2] >= 4:  # if sequential vowels or consonants >= 4
        results[11] = 1  # DGA domain
    else:
        results[11] = 0  # Normal domain

    return results


# Analyse URL data and return list of numerical values
def url(data):

    # FEATURES:

    # Full URL:
    # 0 - HTTP
    # 1 - Length
    # 2 - Number of dots
    # 3 - Blacklisted word appears(confirm, account, banking, secure,
    #         ebayisapi, webscr, login, signin, paypal, free, lucky, bonus)

    # Domain name:
    # 4 - Length
    # 5 - IP address
    # 6 - Port number
    # 7 - Tokens
    # 8 - Number of hyphens
    # 9 - Length of longest token

    # Directories:
    # 10 - Length
    # 11 - Number of sub-directory tokens
    # 12 - Length of longest sub-directory token
    # 13 - Maximum delimiters in a token

    # File name:
    # 14 - Length
    # 15 - Number of delimiters

    # Arguments:
    # 16 - Length
    # 17 - Number of variables
    # 18 - Length of longest variable value
    # 19 - Maximum delimiters

    results = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]

    url_data = urlparse(data)
    # print("Parsed data:", url_data)
    # print("Scheme:", url_data.scheme)
    # print("Hostname:", url_data.hostname)
    # print("Port:", url_data.port)

    if data.startswith("http://"):  # HTTP check
        results[0] = 1
    results[1] = len(data)  # URL total length
    results[2] = data.count(".")  # URL total dots
    results[3] = url_blacklist_words(url_data)  # Checks if a blacklisted word is contained in the URL path

    # https://stackoverflow.com/questions/21628852/changing-hostname-in-a-url
    # https://stackoverflow.com/questions/3462784/check-if-a-string-matches-an-ip-address-pattern-in-python
    host_name = url_data.hostname  # This only grabs host/domain, nothing else like port numbers
    try:
        results[4] = len(host_name)  # Domain name length

        try:
            ipaddress.ip_address(host_name)  # Checks if hostname is an IP address
            results[5] = 1  # Indicate hostname is an IP address
            # print("Has IP address")
        except ValueError:
            pass  # No valid IP address found
        if url_data.port is not None and url_data.port not in [80, 443]:  # Checks if using a custom port
            results[6] = 1  # Indicates custom port used
            # print("Not using standard port!")
        hostname_tokens = host_name.split(".")
        results[7] = len(hostname_tokens)  # Count tokens in hostname, assume this is '.'?
        results[8] = host_name.count("-")  # Count hyphens in hostname
        # https://www.geeksforgeeks.org/python-longest-string-in-list/
        results[9] = len(max(hostname_tokens, key=len))  # Max will return the longest element, so we do len on that
    except TypeError:
        pass  # The host name is missing

    results[10] = len(url_data.path)  # Directory length
    path_tokens = url_data.path.split("/")
    results[11] = len(path_tokens)  # Number of sub-directory tokens
    results[12] = len(max(path_tokens, key=len))  # Longest token in directory tokens
    results[13] = max_delimiters(path_tokens)  # Max delimiters in a sub-directory token

    url_file = url_data.path.split("/")[-1]  # Get last element of split directory
    # print("File:", url_file)
    results[14] = len(url_file)  # Length of file name
    results[15] = max_delimiters([url_file])  # Delimiters in the file name, list because only one token

    arguments = parse_qs(url_data.query)
    results[16] = len(url_data.query)  # Arguments length
    arg_val_list = []
    for key in arguments:
        arg_val_list.append(arguments[key][0])
    # print("Argument values:", arg_val_list)
    if arg_val_list:  # Check if we have arguments first
        results[17] = len(arg_val_list)  # Number of argument variables
        results[18] = len(max(arg_val_list, key=len))  # Get longest argument value
        results[19] = max_delimiters(arg_val_list)  # Maximum argument delimiters

    return results


# Part of analysis functions to count the number of consecutive vowels or consonants.
def consecutive_chars(data, vowels):
    data = data.lower()

    if vowels:  # If vowels = true, count consecutive vowels
        chars = "aeiou"
    else:
        chars = "bcdfghjklmnpqrstvwxyz"

    consecutive_count = 0
    max_count = 0

    for i in range(len(data)):
        if data[i] in chars:
            consecutive_count += 1  # If in the list, increase consecutive count
        else:
            consecutive_count = 0  # If not in the list, reset our current count

        if consecutive_count > max_count:  # If we reach a new max count, update
            max_count = consecutive_count

    return max_count


# Part of analysis functions, counts the number of vowels or consonants
def total_chars(data, vowels):
    data = data.lower()

    if vowels:  # If counting total vowels
        chars = "aeiou"
    else:
        chars = "bcdfghjklmnpqrstvwxyz"

    num_chars = 0

    for i in range(len(data)):  # Iterate over data string and count chars
        if data[i] in chars:
            num_chars += 1

    return num_chars


# Part of analysis functions to count the delimiters present in a domain or URL
def max_delimiters(data):
    """
    :param data: List of tokens
    :return: Integer max count
    """

    # Delimiters used in PhishDef paper
    delimiters = [".", "-", "_", "/", "?", "=", "&"]

    # Count the number of delimiters present
    max_count = 0
    for i in range(len(data)):
        cur_count = 0
        for j in range(len(delimiters)):
            cur_count += data[i].count(delimiters[j])
        if cur_count > max_count:
            max_count = cur_count

    return max_count


# Part of analysis functions, returns 1 if a blacklisted word is detected
# Note: blacklist is read at top of file
def url_blacklist_words(data):
    # Checks the blacklisted words exist in the URL path

    for i in range(len(url_blacklist)):
        if url_blacklist[i] in data.path:
            # print("Blacklisted word detected")
            return 1
    return 0
