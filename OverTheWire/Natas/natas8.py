import requests

username = "natas8"
password = "DBfUBfqQG69KvJvJ1iAbMoIpwSNQ9bWe"

session = requests.Session()

url = "http://{}.natas.labs.overthewire.org/".format(username)
response = session.post(
    url, data={"secret": 'oubWYf2kBq', "submit": "submit"}, auth=(username, password))
content = response.text

print(content)
