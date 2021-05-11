# TwoFingerPhishPunch - ai.py

# Contains ai functions including training and predictions

# Created by Leon Ware

import torch
from torch.autograd import Variable
import numpy as np
import database
import analysis
from os import getcwd
from os import path
from os import mkdir


model_location = getcwd() + "\\models\\"


# This is the neural network class that stores the neural network and provides some key functions
class NeuralNet:
    def __init__(self, input_size, hidden_size, output_size, learning_rate):
        self.dtype = torch.FloatTensor
        # dtype = torch.cuda.FloatTensor # Uncomment this to run on GPU
        self.learn_rate = learning_rate

        self.x = Variable  # initialisation values for training data
        self.y = Variable

        self.normalisers = []  # Normaliser values for analysis functions

        # Create random Tensors for weights, and wrap them in Variables.
        # Setting requires_grad=True indicates that we want to compute gradients with
        # respect to these Variables during the backward pass.
        self.w1 = Variable(torch.randn(input_size, hidden_size).type(self.dtype), requires_grad=True)
        self.w2 = Variable(torch.randn(hidden_size, output_size).type(self.dtype), requires_grad=True)

    def set_training_data(self, x_array, y_array):
        # Training data must be set before training.

        # Create random Tensors to hold input and outputs, and wrap them in Variables.
        # Setting requires_grad=False indicates that we do not need to compute gradients
        # with respect to these Variables during the backward pass.
        self.x = Variable(torch.from_numpy(x_array).type(self.dtype), requires_grad=False)
        self.y = Variable(torch.from_numpy(y_array).type(self.dtype), requires_grad=False)

    def train(self):
        # https://stackoverflow.com/questions/4601373/better-way-to-shuffle-two-numpy-arrays-in-unison
        # Shuffle our arrays together using the same random number permutation
        # Shuffled each time training is performed
        random_sequence = np.arange(len(self.x))
        np.random.shuffle(random_sequence)
        self.x = self.x[random_sequence]
        self.y = self.y[random_sequence]

        # Forward pass: compute predicted y using operations on Variables
        y_pred = self.x.mm(self.w1).clamp(min=0).mm(self.w2)

        # Compute and print loss using operations on Variables.
        loss = (y_pred - self.y).pow(2).sum()
        loss.backward()

        # Update weights using gradient descent
        self.w1.data -= self.learn_rate * self.w1.grad.data
        self.w2.data -= self.learn_rate * self.w2.grad.data
        self.w1.grad.data.zero_()  # Manually zero the gradients
        self.w2.grad.data.zero_()

        return loss

    def predict(self, input_data):
        # print("Predict in:", input_data)
        # np.array input data to make it a 2D array of one entry to get individual predictions
        data = Variable(torch.from_numpy(np.array([input_data])).type(self.dtype), requires_grad=False)
        prediction = data.mm(self.w1).clamp(min=0).mm(self.w2)

        return prediction[0]

    def batch_predict(self, input_data):
        data = Variable(torch.from_numpy(np.array(input_data)).type(self.dtype), requires_grad=False)
        predictions = data.mm(self.w1).clamp(min=0).mm(self.w2)

        return predictions

    def set_normalisers(self, normaliser_array):
        self.normalisers = normaliser_array

    def get_normalisers(self):
        return self.normalisers


# Function to save the network. Clears training data then save to the specified file
def save_network(model, name):
    file_name = model_location + name

    model.set_training_data(np.array([]), np.array([]))  # This erases the stored x and y arrays to reduce file size

    if not path.exists(model_location):
        print("Creating models directory")
        mkdir(model_location)

    print("Saving model to:", file_name)
    torch.save(model, file_name)


def load_network(name):
    file_name = model_location + name

    model = torch.load(file_name)
    print("Loaded model at:", file_name)

    return model


# Test neural network models against the entire dataset of benign and malicious samples
def test_models(db_conn, models, mode):
    print("\nPreparing test data")

    benign_set = database.benign(db_conn, mode)
    malicious_set = database.malicious(db_conn, mode)

    # analyse the benign dataset
    benign_data = []
    for i in range(len(benign_set)):
        if mode == "domain":
            benign_data.append(analysis.domain(benign_set[i][0]))
        elif mode == "url":
            benign_data.append(analysis.url(benign_set[i][0]))
        else:
            raise ValueError("Mode must be 'domain' or 'url'.")

    # analyse the malicious dataset
    malicious_data = []
    for i in range(len(malicious_set)):
        if mode == "domain":
            malicious_data.append(analysis.domain(malicious_set[i][0]))
        elif mode == "url":
            malicious_data.append(analysis.url(malicious_set[i][0]))
        else:
            raise ValueError("Mode must be 'domain' or 'url'.")

    # This section tests each model by first normalising data with each neural network's normaliser settings,
    # and then counting the number of correct and incorrect predictions made
    accuracy_results = []
    for i in range(len(models)):
        # Ensure counters are reset before testing each model. Important.
        true_positives = 0
        true_negatives = 0
        false_positives = 0
        false_negatives = 0

        print("Testing", mode, "model", i, " benign accuracy")
        test_data = analysis.normalise_data(benign_data, models[i].get_normalisers())
        predictions = models[i].batch_predict(test_data)
        for j in range(len(predictions)):
            # prediction[0] = benign, prediction[1] = malicious
            if predictions[j][0] > predictions[j][1]:  # Check for benign prediction
                true_negatives += 1
            else:
                false_positives += 1

        print("Testing", mode, "model", i, " malicious accuracy")
        test_data = analysis.normalise_data(malicious_data, models[i].get_normalisers())
        predictions = models[i].batch_predict(test_data)
        for j in range(len(predictions)):
            # prediction[0] = benign, prediction[1] = malicious
            if predictions[j][1] > predictions[j][0]:  # Check for malicious prediction
                true_positives += 1
            else:
                false_negatives += 1

        accuracy = (true_positives + true_negatives) / \
                   (true_positives + true_negatives + false_positives + false_negatives)

        # Print the statistics
        print("Correct:", true_positives + true_negatives)
        print("Wrong:", false_positives + false_negatives)
        print("False negatives:", false_negatives)
        print("False positives:", false_positives)
        print("Accuracy:", accuracy * 100, "%")

        # Add these results to the list
        accuracy_results.append(accuracy)

    return accuracy_results


# Creates and trains the network, before saving
def create_network(training_names, training_values, normalisers, network_name, iterations, learn_rate):
    # https://www.datacamp.com/community/tutorials/tensorflow-tutorial#model
    # https://rubikscode.net/2018/02/05/introduction-to-tensorflow-with-python-example/

    # Prepare the dataset - input and answer arrays
    print("Preparing dataset")

    x_array, y_array = prep_data(training_names, training_values)

    batches = len(x_array)  # N - batch size
    input_size = len(x_array[0])  # D_in - input size
    hidden_size = input_size  # H - hidden laye, recommended that this is between input and output size
    output_size = len(y_array[0])  # D_out - output size

    print("Creating model")
    print("Batches:", batches)
    print("Input size:", input_size)
    print("Hidden:", hidden_size)
    print("Output size:", output_size)

    # This creates an instance of the neural net class and initialises it
    neural_net = NeuralNet(input_size, hidden_size, output_size, learn_rate)
    neural_net.set_normalisers(normalisers)  # Save normalisers to neural network model
    neural_net.set_training_data(x_array, y_array)  # Set the training data for the neural network to use

    print("Training model...")
    for i in range(iterations):  # Learn from the training data x times
        loss = neural_net.train()
        if (i + 1) % 200 == 0:
            print(i + 1, "Loss:", loss.data.item())  # Loss is a total from every training result

    save_network(neural_net, network_name)  # Save our neural network model, also clears training data

    return neural_net


# Fetches training data to be used for training the neural networks
def get_training_data(db_conn, rows, mode):
    print("Fetching", mode, "training data")

    malicious = database.get_random(db_conn, rows, mode, True)  # These return an array of tuples
    benign = database.get_random(db_conn, rows, mode, False)

    print("Malicious:", len(malicious))
    print("Benign:", len(benign))

    print("Preparing", mode, "data...")

    # https://adventuresinmachinelearning.com/python-tensorflow-tutorial/

    # Put all our selected domains and analysis data into one giant array
    input_array = []  # Domain/URL, and malicious indicator
    analysis_array = []  # Analysis array for the domain/url

    # Assemble training data with the domain/URL, and the maliciousness indicator - 0=benign, 1=malicious
    if mode == "url":
        for i in range(len(malicious)):
            # data.append([malicious[i][0], 1] + analysis.url(malicious[i][0]))
            input_array.append([malicious[i][0], 1])
            analysis_array.append(analysis.url(malicious[i][0]))
        for i in range(len(benign)):
            # data.append([benign[i][0], 0] + analysis.url(benign[i][0]))
            input_array.append([benign[i][0], 0])
            analysis_array.append(analysis.url(benign[i][0]))
    elif mode == "domain":
        for i in range(len(malicious)):
            # data.append([malicious[i][0], 1] + analysis.domain(malicious[i][0]))
            input_array.append([malicious[i][0], 1])
            analysis_array.append(analysis.domain(malicious[i][0]))
        for i in range(len(benign)):
            # data.append([benign[i][0], 0] + analysis.domain(benign[i][0]))
            input_array.append([benign[i][0], 0])
            analysis_array.append(analysis.domain(benign[i][0]))
    else:
        raise Exception("Mode must be 'url' or 'domain'.")

    # Determine the normalisers for this set of prepared training data
    print("Getting", mode, "normalisation values")
    normalisers = analysis.get_normalisers(analysis_array)

    # Then normalise the data with the normalisers
    print("Normalising", mode, "analysis values")
    analysis_array = analysis.normalise_data(analysis_array, normalisers)

    return input_array, analysis_array, normalisers


# Take the training data, produce an array of neural network answers, then turn into Numpy arrays
def prep_data(data_names, data_values):
    training_answers = []

    for i in range(len(data_names)):
        if data_names[i][1] == 0:  # Benign
            training_answers.append([1, 0])  # We need separate neurons for each output we want
        elif data_names[i][1] == 1:  # Malicious
            training_answers.append([0, 1])
        else:
            raise ValueError("Invalid maliciousness indicator.")

    x_array = np.array(data_values)  # Convert lists into Numpy arrays
    y_array = np.array(training_answers)

    return x_array, y_array


# Uses the neural networks to check their prediction results against all known malicious samples
# Stuff not correctly identified as malicious is added to the database blacklist
def optimise_blacklists(db_conn, model_name, mode):
    model = load_network(model_name)

    malicious_things = database.malicious(db_conn, mode)

    items_processed = 0  # Tracks total items used
    items_added = 0  # Tracks how many things were added to the blacklist

    for i in range(len(malicious_things)):
        item = malicious_things[i][0]
        # For each item, analyse it
        if mode == "url":
            item_data = analysis.url(item)
        elif mode == "domain":
            item_data = analysis.domain(item)
        else:
            raise Exception("Mode must be 'url' or 'domain'.")

        # Then normalise it
        item_data = analysis.normalise_data([item_data], model.get_normalisers())

        # Then make a prediction
        prediction = model.predict(item_data[0])
        items_processed += 1

        # If benign > malicious score, we predicted wrong so add to database
        if prediction[0] > prediction[1]:
            # print("Blacklist:", item)
            database.blacklist_add(db_conn, item, mode)  # Add item to blacklist
            items_added += 1

    return items_processed, items_added
