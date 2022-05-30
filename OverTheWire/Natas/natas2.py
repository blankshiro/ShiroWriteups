import requests

username = "natas2"
password = "ZluruAthQk7Q2MqmDeTiUij2ZvWy2mBi"

url = "http://{}.natas.labs.overthewire.org/files/users.txt".format(username)
response = requests.get(url, auth=(username, password))
content = response.text

print(content)
