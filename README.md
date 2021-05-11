# PhishPunch
Real-time application of machine learning and blacklists to improve internet safety, written in Python 3.8


This repository contains the source code used in the PhishPunch dissertation.


## Requirements
- PyTorch (PyTorch 1.7.1)
- dnslib (Dnslib 0.9.14)
- requests (Requests 2.25.1)
- validators(Validators0.11.2)
- ipaddress (IPAddress)
- mitmproxy(MITMProxy6.0.2) - Note: install MITM Proxy application
- TLD (TLD 0.12.5)

## Setup
Create following directories:
- data\unzip
- models
- test_results (if testing performance)

## Usage:
Run main.py in console.
Adjust script and comment out function calls at the bottom of the file to change behaviour.

Run perf_test.py in console to test performance.
Adjust script and comment out function calls at the bottom of the file to change behaviour.
