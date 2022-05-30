import requests

username = "natas3"
password = "sJIJNW6ucpu6HPZ1ZAchaDtwd7oGrD14"

url = "http://{}.natas.labs.overthewire.org/s3cr3t/users.txt".format(username)
response = requests.get(url, auth=(username, password))
content = response.text

print(content)
