# TwoFingerPhishPunch - perf_test.py

# This is a dedicated testing script used to evaluate the performance of the implemented system

# Created by Leon Ware

import datetime
from os import path, getcwd
import csv

import ai
import analysis
import database

database_name = "database.sqlite3"

# Hardcoded names of performance testing output files
# These can be safely changed
perf_test_path = getcwd() + "\\test_results\\"
performance_csv = perf_test_path + "performance_results.csv"
accuracy_csv = perf_test_path + "accuracy_results.csv"
creation_csv = perf_test_path + "nn_creation_time.csv"


# fetch_db_data selects the specified number of domain and URL samples from the database
# the number of items is total samples, not benign and malicious separately
def fetch_db_data(num_items, mode):
    db_conn = database.initialise(database_name)  # Initialise SQLite and get our connection
    num_items = int(round(num_items / 2, 0))

    # Gather these separately in case the database does not have enough samples
    domains_benign = database.get_random(db_conn, num_items, "domain", False)
    domains_malicious = database.get_random(db_conn, num_items, "domain", True)

    urls_benign = database.get_random(db_conn, num_items, "url", False)
    urls_malicious = database.get_random(db_conn, num_items, "url", True)

    database.close(db_conn)  # Close connection because it isn't needed anymore

    # Performance testing just requires a list of domains and urls to test
    if mode == "performance":
        domains = domains_benign + domains_malicious
        urls = urls_benign + urls_malicious
        return domains, urls

    # Accuracy testing requires lists to remain split to identify which category samples are from
    elif mode == "accuracy":
        # Keep lists separate so we know which ones are malicious and benign
        return domains_benign, domains_malicious, urls_benign, urls_malicious

    else:
        raise ValueError("Mode must be 'performance' or 'accuracy'.")


# A neural network prediction function that returns predictions for the entire list of samples provided
def network_predict(mode, model, normalisers, test_data):
    predictions = []
    if mode == "domain":
        for i in range(len(test_data)):
            data = analysis.domain(test_data[i][0])  # Analyse the domain name and prepare for neural network
            data = analysis.normalise_data([data], normalisers)
            predictions.append(model.predict(data[0]))  # Neural network determines maliciousness
    elif mode == "url":
        for i in range(len(test_data)):
            data = analysis.url(test_data[i][0])  # Analyse the domain name and prepare for neural network
            data = analysis.normalise_data([data], normalisers)
            predictions.append(model.predict(data[0]))  # Neural network determines maliciousness
    else:
        raise ValueError("Mode must be 'domain' or 'url'!")

    return predictions


# This function times how long it takes for a neural network to predict the data samples
# Returns an array of test timing results
def network_perf_timer(mode, model, test_data, runs):
    normalisers = model.get_normalisers()
    time_list = []  # Stores results from each test run
    for test in range(runs):
        start_time = datetime.datetime.now().timestamp()  # Timestamp for test start
        network_predict(mode, model, normalisers, test_data)
        end_time = datetime.datetime.now().timestamp()  # Timestamp for test finished
        time_list.append(end_time - start_time)  # Record the time taken

    return time_list


# This function records how long the blacklist takes to check a number of samples
def blacklist_perf_timer(mode, test_data, runs):
    time_list = []
    db_conn = database.initialise(database_name)

    for test in range(runs):
        start_time = datetime.datetime.now().timestamp()  # Timestamp for test start

        # Perform the blacklist check for each test sample
        for i in range(len(test_data)):
            # Data items are in tuples, so [i][0] to get the actual value
            database.in_blacklist(db_conn, test_data[i][0], mode)

        end_time = datetime.datetime.now().timestamp()  # Timestamp for test finished
        time_list.append(end_time - start_time)  # Record the time taken

    database.close(db_conn)
    return time_list


# Function to time both the neural network and blacklist to get a combined time result
def combined_perf_timer(mode, model, test_data, runs):
    normalisers = model.get_normalisers()
    time_list = []
    db_conn = database.initialise(database_name)

    # This represents performance in a 50% malicious dataset
    # with normal behaviour of checking the blacklist for anything that looks benign

    for test in range(runs):
        start_time = datetime.datetime.now().timestamp()  # Timestamp for test start

        # First get predictions for all the test samples
        predictions = network_predict(mode, model, normalisers, test_data)
        # For each benign prediction, check the blacklist, to represent normal behaviour
        for i in range(len(test_data)):
            if predictions[i][0] > predictions[i][1]:  # Benign > Malicious, need to check blacklist
                database.in_blacklist(db_conn, test_data[i][0], mode)

        end_time = datetime.datetime.now().timestamp()  # Timestamp for test finished
        time_list.append(end_time - start_time)  # Record the time taken

    database.close(db_conn)
    return time_list


# A function to display performance results in a readable way
def print_results(time_list, test_name, runs_made, num_items):
    # Simple way to determine average times, without importing libraries
    average_time = sum(time_list) / len(time_list)

    print("~~ Results for", test_name, "(" + str(runs_made) + " runs) ~~")
    print(num_items, "items processed in:", average_time, "seconds")
    processed_per_second = num_items / average_time
    time_per_process = average_time / num_items
    print("Processed per second:", round(processed_per_second, 2))
    print("Average process time:", '{0:.10f}'.format(time_per_process), "seconds")


# save_perf_results saves the performance results to a CSV
def save_perf_results(time_list, test_name, runs_made, num_items, filename):
    # Check if the file exists. If it doesn't, write the header
    if not path.exists(filename):
        print("File", filename, "was not found. Making new file.")
        with open(filename, "w", newline="") as file:  # Extra newline param prevent space between rows
            csv_writer = csv.writer(file, delimiter=',', quotechar='"', quoting=csv.QUOTE_MINIMAL)
            csv_header = ["Time performed", "Test type", "Samples", "Repeats", "Time - Average", "Time - Min",
                          "Time - Max", "Variance %", "Samples per second", "Seconds per sample"]
            csv_writer.writerow(csv_header)

    # Open CSV in 'append' mode, so it adds to the file and doesn't overwrite
    with open(filename, "a", newline="") as file:
        print("Saving results to", filename)
        csv_writer = csv.writer(file, delimiter=',', quotechar='"', quoting=csv.QUOTE_MINIMAL)

        date_performed = datetime.datetime.now()
        time_average = round(sum(time_list) / len(time_list), 5)
        time_min = round(min(time_list), 5)
        time_max = round(max(time_list), 5)
        variance = round(((time_max - time_min) / time_average) * 100, 5)
        samples_per = round((num_items / time_average), 5)
        seconds_per = '{0:.8f}'.format(time_average / num_items)

        csv_writer.writerow([date_performed, test_name, num_items, runs_made, time_average, time_min, time_max,
                             variance, samples_per, seconds_per])


# save_accu_results saves accuracy results to a CSV
def save_accu_results(results, test_name, num_items, filename, mode):
    # Check if the file exists. If it doesn't, write the header
    if not path.exists(filename):
        print("File", filename, "was not found. Making new file.")
        with open(filename, "w", newline="") as file:  # Extra newline param prevent space between rows
            csv_writer = csv.writer(file, delimiter=',', quotechar='"', quoting=csv.QUOTE_MINIMAL)
            csv_header = ["Time performed", "Test type", "Samples", "Total accuracy", "Benign accuracy",
                          "Malicious accuracy", "True positives", "True negatives", "False positives",
                          "False negatives"]
            csv_writer.writerow(csv_header)

    # Open CSV in 'append' mode, so it adds to the file and doesn't overwrite
    with open(filename, "a", newline="") as file:
        print("Saving results to", filename)
        csv_writer = csv.writer(file, delimiter=',', quotechar='"', quoting=csv.QUOTE_MINIMAL)

        date_performed = datetime.datetime.now()

        #           0               1               2                3                4             5       6
        # results - true_positives, true_negatives, false_positives, false_negatives, in_blacklist, missed, wrong
        # friendly - malicious,     benign,         incorrect mal,   incorrect benign...

        # in_blacklist = 0  # False negatives caught with blacklist
        # missed_blacklist = 0  # False negatives not caught by blacklist, should stay 0
        # wrong_blacklist = 0  # A benign sample that is somehow in the blacklist, should stay 0

        # Note - Calculate total samples from first 3 values only
        total_samples = sum(results[0:4])

        if mode == "network":
            # Total acc = true positives + true negatives / total samples
            total_acc = (results[0] + results[1]) / total_samples
            # Benign acc = true negatives / true negatives + false positives (Calculated for benign samples)
            benign_acc = results[1] / (results[1] + results[2])
            # Malicious acc = true positives / true positives + false negatives (Calculated for malicious samples)
            malicious_acc = results[0] / (results[0] + results[3])

        elif mode == "combined":
            # Additionally count samples caught with blacklist correctly
            total_acc = (results[0] + results[1] + results[4]) / total_samples
            # Subtract samples incorrectly caught with blacklist
            benign_acc = (results[1] - results[6]) / (results[1] + results[2])
            # Add samples caught with blacklist
            malicious_acc = (results[0] + results[4]) / (results[0] + results[3])

        else:
            raise ValueError("Accuracy save mode must be 'network' or 'combined'.")

        # Round to 5 decimal places and convert to percentages
        total_acc = round(total_acc * 100, 5)
        benign_acc = round(benign_acc * 100, 5)
        malicious_acc = round(malicious_acc * 100, 5)

        csv_writer.writerow([date_performed, test_name, num_items, total_acc, benign_acc, malicious_acc, results[0],
                             results[1], results[2], results[3]])


# This function performs all of the performance tests and saves them using save_perf_results
def full_performance_test(num_runs, num_samples):
    print("Preparing performance test")
    domain_model = ai.load_network("domain_nn.model")  # Load the neural network
    url_model = ai.load_network("url_nn.model")

    print("Fetching", num_samples, "mixed samples for each network")
    test_domains, test_urls = fetch_db_data(num_samples, "performance")
    num_domains = len(test_domains)
    num_urls = len(test_urls)

    print("\nTesting Domain neural network performance...")
    test_times = network_perf_timer("domain", domain_model, test_domains, num_runs)
    # print_results(test_times, "domain network", num_runs, num_domains)
    save_perf_results(test_times, "domain network", num_runs, num_domains, performance_csv)

    print("\nTesting URL neural network performance...")
    test_times = network_perf_timer("url", url_model, test_urls, num_runs)
    save_perf_results(test_times, "url network", num_runs, num_urls, performance_csv)

    print("\nTesting Domain blacklist performance...")
    test_times = blacklist_perf_timer("domain", test_domains, num_runs)
    save_perf_results(test_times, "domain blacklist", num_runs, num_domains, performance_csv)

    print("\nTesting URL blacklist performance...")
    test_times = blacklist_perf_timer("url", test_urls, num_runs)
    save_perf_results(test_times, "URL blacklist", num_runs, num_urls, performance_csv)

    print("\nTesting combined Domain performance...")
    test_times = combined_perf_timer("domain", domain_model, test_domains, num_runs)
    save_perf_results(test_times, "combined domain", num_runs, num_domains, performance_csv)

    print("\nTesting combined URL performance...")
    test_times = combined_perf_timer("url", url_model, test_urls, num_runs)
    save_perf_results(test_times, "combined URL", num_runs, num_urls, performance_csv)


# This function tests the accuracy of a neural network against benign and malicious samples
# It returns the numerical results, and does not count accuracy percentage
def prediction_accuracy_counter(mode, benign_samples, malicious_samples, model):
    true_positives = 0  # Correctly predicted malicious
    true_negatives = 0  # Correctly predicted benign
    false_positives = 0  # Wrongly predicted malicious
    false_negatives = 0  # Wrongly predicted benign
    in_blacklist = 0  # False negatives caught with blacklist
    missed_blacklist = 0  # False negatives not caught by blacklist, should stay 0
    wrong_blacklist = 0  # A benign sample that is somehow in the blacklist, should stay 0

    db_conn = database.initialise(database_name)

    # Perform predictions on benign samples
    predictions = network_predict(mode, model, model.get_normalisers(), benign_samples)
    for k in range(len(predictions)):
        if predictions[k][0] > predictions[k][1]:  # If predicted benign, we got it right
            true_negatives += 1

            # This is a sanity check to make sure samples are in the correct groups
            if database.in_blacklist(db_conn, benign_samples[k][0], mode):
                wrong_blacklist += 1
        else:
            false_positives += 1

    # Perform predictions on malicious samples
    predictions = network_predict(mode, model, model.get_normalisers(), malicious_samples)
    for k in range(len(predictions)):
        if predictions[k][0] > predictions[k][1]:  # If predicted benign, we got it wrong
            false_negatives += 1
            # Now check the blacklist
            if database.in_blacklist(db_conn, malicious_samples[k][0], mode):
                in_blacklist += 1
            else:
                missed_blacklist += 1
        else:
            true_positives += 1

    database.close(db_conn)

    return [true_positives, true_negatives, false_positives, false_negatives, in_blacklist, missed_blacklist,
            wrong_blacklist]


def accuracy_test(num_runs, num_samples, mode):
    print("Preparing accuracy test")
    domain_model = ai.load_network("domain_nn.model")  # Load the neural networks
    url_model = ai.load_network("url_nn.model")

    for i in range(num_runs):
        print("Fetching", num_samples, "mixed samples for each network")
        ben_domains, mal_domains, ben_urls, mal_urls = fetch_db_data(num_samples, "accuracy")

        print("\nTesting Domain network accuracy...")
        prediction_results = prediction_accuracy_counter("domain", ben_domains, mal_domains, domain_model)
        save_accu_results(prediction_results, "domain_" + mode, num_samples, accuracy_csv, mode)

        print("\nTesting URL network accuracy...")
        prediction_results = prediction_accuracy_counter("url", ben_urls, mal_urls, url_model)
        save_accu_results(prediction_results, "url_" + mode, num_samples, accuracy_csv, mode)


# Save the results of the neural network creation time to a CSV
def save_nn_creation_time(name, candidates, train_samples, iterations, test_samples, train_time, test_time):
    # Check if the file exists. If it doesn't, write the header
    if not path.exists(creation_csv):
        print("File", creation_csv, "was not found. Making new file.")
        with open(creation_csv, "w", newline="") as file:  # Extra newline param prevent space between rows
            csv_writer = csv.writer(file, delimiter=',', quotechar='"', quoting=csv.QUOTE_MINIMAL)
            csv_header = ["Time performed", "Test type", "Candidates", "Train samples", "Iterations", "Test samples",
                          "Train time", "Test time", "Total time"]
            csv_writer.writerow(csv_header)

    # Open CSV in 'append' mode, so it adds to the file and doesn't overwrite
    with open(creation_csv, "a", newline="") as file:
        print("Saving results to", creation_csv)
        csv_writer = csv.writer(file, delimiter=',', quotechar='"', quoting=csv.QUOTE_MINIMAL)

        date_performed = datetime.datetime.now()
        total_time = train_time + test_time

        csv_writer.writerow([date_performed, name, candidates, train_samples, iterations, test_samples, train_time,
                             test_time, total_time])


# Performs the full network creation and training process and times the training and testing processes
def nn_creation_time(mode, num_candidates, samples, iterations):
    db_conn = database.initialise(database_name)  # Initialise SQLite and get our connection

    start_time = datetime.datetime.now().timestamp()

    # Batch network creation
    network_names = []  # Keeps track of the models created
    network_models = []  # Provide access to all models for testing
    for i in range(num_candidates):
        print("\nPreparing training data for", mode, "network candidate", i)
        # Each network gets own randomised training data
        data_names, data_analysis, data_normalisers = ai.get_training_data(db_conn, samples, mode)

        print("Creating", mode, "network candidate", i)
        model_name = mode + "_candidate_" + str(i) + ".model"
        network_names.append(model_name)
        network_models.append(ai.create_network(data_names, data_analysis, data_normalisers, model_name, iterations,
                                                1e-6))

    mid_time = datetime.datetime.now().timestamp()

    # Batch network testing
    network_results = ai.test_models(db_conn, network_models, mode)

    best_network = network_results.index(max(network_results))  # Find position of network with max score in list
    final_model = network_names[best_network]

    print("Best network:", best_network, "-", final_model)

    end_time = datetime.datetime.now().timestamp()

    train_time = mid_time - start_time
    test_time = end_time - mid_time

    # Returns max ID of the samples used, to find how many were tested (returns tuple so [0] to get value)
    test_samples = database.get_max(db_conn, mode)[0]

    database.close(db_conn)  # Close connection because it isn't needed anymore

    save_nn_creation_time(mode, num_candidates, samples, iterations, test_samples, train_time, test_time)


# When perf_test.py is run directly, this code calls every test.
# Tests can be commented out if they are not required.
if __name__ == "__main__":
    print("Beginning Testing!")

    for loop in range(1):
        print("\n~~ Test iteration:", loop, "~~\n")

        # PERFORMANCE AND ACCURACY TESTING
        number_runs = 5  # How many times to perform the test
        number_samples = 10000  # Target number of records for testing, half benign and half malicious

        for run in range(3):
            full_performance_test(number_runs, number_samples)

            accuracy_test(number_runs, number_samples, "network")
            accuracy_test(number_runs, number_samples, "combined")

        # # NETWORK CREATING TIME TEST
        network_candidates = 5
        network_domains = 30000
        network_urls = 30000
        network_iterations = 5000
        nn_creation_time("domain", network_candidates, network_domains, network_iterations)
        nn_creation_time("url", network_candidates, network_urls, network_iterations)

    print("\nTesting Completed!")
