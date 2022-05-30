import requests

username = "natas1"
password = "gtVrDuiDfck831PqWsLEZy5gyDz1clto"

url = "http://{}.natas.labs.overthewire.org".format(username)
response = requests.get(url, auth=(username, password))
content = response.text

print(content)
