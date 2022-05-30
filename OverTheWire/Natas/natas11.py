import requests

username = "natas11"
password = "U82q5TCMMQ9xuFoI3dYX61s7OZD9JKoK"

session = requests.Session()

url = "http://{}.natas.labs.overthewire.org/".format(username)
response = session.post(url, auth=(username, password),
                        cookies={"data": "ClVLIh4ASCsCBE8lAxMacFMOXTlTWxooFhRXJh4FGnBTVF4sFxFeLFMK"})
content = response.text

print(content)
