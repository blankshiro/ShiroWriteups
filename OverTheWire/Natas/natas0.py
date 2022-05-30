import requests

username = "natas0"
password = username

url = "http://{}.natas.labs.overthewire.org".format(username)
response = requests.get(url, auth=(username, password))
content = response.text

print(content)
