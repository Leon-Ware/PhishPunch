# TwoFingerPhishPunch - get_data.py

# Handles collection of URL and Domain information and inserts into database

# Created by Leon Ware

# INSTALLED WITH PIP
import requests  # Requests.get() is used to download files
from validators import url as valid_url
from validators import domain as valid_domain

# Regular libraries
import os
from shutil import unpack_archive
import csv  # Used to read CSV files
import database  # Used to store extracted URLs and domains


data_dir = os.getcwd() + "\\data"
unzip_dir = data_dir + "\\unzip"


# Calls functions to perform the data ingest
# read_sources, download_sources, unzip_sources and ingest_sources
def gather_data(db_conn, enable_download):
    d_urls, d_files, d_types, d_columns = read_sources()  # Read sources file for information

    download_sources(d_urls, d_files, enable_download)  # Download files
    d_files = unzip_sources(d_files)  # This assumes all zipped files have the .zip extension
    results = ingest_sources(db_conn, d_files, d_types, d_columns)  # Read into database

    return results


# Reads the sources.txt file and creates several lists of source information
def read_sources():
    download_urls = []
    download_filenames = []
    download_type = []
    download_columns = []

    print("Reading sources.txt")
    with open("sources.txt", "r") as file:  # Reads sources to get things to download
        while True:
            line = file.readline()

            if line == "":  # Blank line is end of file, all other lines have '\n'
                break

            if not line.startswith("#") and line != "\n":  # If line is not a comment or empty
                # print("Splitting line")
                line = line.rstrip().split(" ")  # Lines should be separated with - NO SPACES IN FILE NAMES!
                print(line)

                try:
                    # print(line[0])
                    download_urls.append(line[0])
                    download_filenames.append(line[1])  # Second part is the filename, in data folder

                    if line[2] == "malicious":
                        download_type.append(True)  # Malicious bool set to true - is malicious
                    elif line[2] == "benign":
                        download_type.append(False)  # Malicious bool set to false - is NOT malicious
                    else:
                        raise Exception("Invalid type")  # Let's raise an error

                    download_columns.append(int(line[3]))  # Column number containing URL data

                except Exception as e:
                    print("Error in sources file:", e)
                    print("Occurred at:", line)

    return download_urls, download_filenames, download_type, download_columns


# Downloads files from the specified URLs and saves them with the specified names
# Will only download new files if enable_download is true
def download_sources(download_urls, download_filenames, enable_download):
    if not os.path.exists("data"):  # Make a data folder if it doesn't exist
        print("Creating data directory")
        os.mkdir("data")

    if enable_download:
        print("Downloading sources")
        for i in range(len(download_urls)):  # For each URL, download to file and add prefix
            print("Downloading:", download_urls[i])

            try:
                print("Saving as:", download_filenames[i])
                r = requests.get(download_urls[i])  # This downloads the file from the specified URL

                with open(data_dir + "\\" + download_filenames[i], "wb") as download_file:
                    download_file.write(r.content)  # Saves the downloaded file

            except Exception as e:
                print("Download failed:", e)

    return download_filenames


# Looks for downloaded zip files (ending with .zip) and extracts them
# Throws an exception if the zip file contains multiple files
def unzip_sources(filenames):
    """
    Will extract .zip files passed in the filenames array
    :param filenames:
    :return:
    """

    previous_files = os.listdir(unzip_dir)  # Find unexpected files leftover in data/unzip

    for i in range(len(previous_files)):
        print("Removing unexpected file:", previous_files[i])
        os.remove(unzip_dir + "\\" + previous_files[i])  # Remove the file

    print("Unzipping zipped sources")

    for i in range(len(filenames)):
        if filenames[i].endswith(".zip"):  # Look for files ending in .zip
            try:
                print("Extracting", filenames[i])
                zip_file_path = data_dir + "\\" + filenames[i]

                unpack_archive(zip_file_path, unzip_dir)  # Unzip file - source, output dir

                filenames[i] = filenames[i][:-4]  # Update file name to unzipped version

                # This section copies out and renames the unzipped files from the extraction directory
                try:
                    extracted_contents = os.listdir(unzip_dir)

                    if len(extracted_contents) > 1:
                        raise Exception("Expected only one file to be extracted!")

                    extracted_file = unzip_dir + "\\" + extracted_contents[0]
                    new_file = data_dir + "\\" + filenames[i]

                    # Remove the existing file so it can be updated
                    if os.path.exists(new_file):
                        print("Removing existing file:", new_file)
                        os.remove(new_file)

                    os.rename(extracted_file, new_file)

                except Exception as e:
                    print("Failed to extract:", e)

            except FileNotFoundError:
                print("The target file was not found!")

    return filenames


# Adds the data in the list to the database and counts how many items have been added
def ingest_data(db_conn, data, classification, counts):
    if valid_url(data):  # Check if the data is a URL
        if database.add_url(db_conn, data, classification):
            counts[0] += 1  # URLs added
        else:
            counts[1] += 1  # URLs existing

    elif valid_domain(data):  # Check if the data is a domain name
        if database.add_domain(db_conn, data, classification):
            counts[2] += 1  # Domains added
        else:
            counts[3] += 1  # Domains existing

    # If not a domain or URL, discard and count
    else:
        counts[4] += 1  # Invalid data

    return counts


# Read the downloaded files and extract data from them
# Able to read data from CSV and TXT files
def ingest_sources(db_conn, files, types, column):
    # Here are some useful counters to check information is going in correctly
    # urls_added = 0
    # urls_existing = 0
    # domains_added = 0
    # domains_existing = 0
    # invalid_data = 0

    # The counters are now implemented in this list
    ingest_count = [0, 0, 0, 0, 0]

    print("Reading sources into database")

    for i in range(len(files)):
        print("Reading:", files[i])
        source_file = data_dir + "\\" + files[i]

        try:
            if files[i].endswith(".csv"):  # If file is CSV, open it using the csv library
                with open(source_file) as csvfile:
                    csv_data = csv.reader(csvfile)  # Read data from the file

                    for row in csv_data:
                        try:
                            # Reach each row and ingest data from the specified column
                            ingest_count = ingest_data(db_conn, row[column[i]], types[i], ingest_count)
                        except IndexError:
                            print("Failed to read a line")

            elif files[i].endswith(".txt"):  # If file is TXT, manually read it
                with open(source_file) as file:
                    for row in file:  # Read each row in the file
                        try:
                            row_data = row.split()  # Split by whitespace and then ingest
                            ingest_count = ingest_data(db_conn, row_data[column[i]], types[i], ingest_count)
                        except IndexError:
                            print("Failed to read a line")

        except FileNotFoundError:
            print("File not found! Skipping...")

    print("Done.")

    return ingest_count
